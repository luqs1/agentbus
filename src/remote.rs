//! Remote tools: another person's agent calls tools on this machine directly (read, grep, glob, ls, copy, write)
//! instead of asking an agent here to answer for it. It opens a *session* with an intent, and every call carries its
//! own `why`. Each call goes through the trust engine:
//!
//! 1. **Hard nevers** (code): credentials, other people's messages, agentbus data, outside home, the owner's path nevers.
//! 2. **Before** (pre-check): a trusted contact or an "always allowed" folder passes; otherwise Jev judges the call from
//!    who's asking, their groups, the owner's statements, the intent and similar past decisions.
//! 3. **Run**: tools that only reveal information run now, so the owner (if asked) decides on what would really be sent.
//! 4. **After** (post-check): the credential scanner, then cached decisions, then Jev on each piece of actual output.
//!    Pieces under a never are withheld; pieces nobody is sure about go to the owner.
//! 5. **The owner**, when needed: a dialog showing who, why and what would be sent, with an optional reason that
//!    becomes precedent. The asker gets `pending` and the result arrives in its inbox later.
//!
//! Tools that change things (`write`) can be refused by Jev before they run but always need the owner.

use crate::daemon::Agent;
use crate::h2h::{human, notify_banner, owner_name, resolve, Choice, Contact, H2h, MANUAL_BUTTONS};
use crate::trust::{self, home_dir};
use crate::util::*;
use anyhow::{anyhow, Result};
use regex::{Regex, RegexBuilder};
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// (name, effect, description). "reveal" tools are judged on their output; "change" tools always need the owner.
pub const TOOLS: [(&str, &str, &str); 6] = [
    ("read", "reveal", "Read a text file. args: {path, offset? (first line, 1-based), limit? (lines, default 400)}. Lines come numbered."),
    ("grep", "reveal", "Search file contents with a regular expression. args: {pattern, path? (default ~), glob? (file names, e.g. \"*.md\"), ignore_case?}."),
    ("glob", "reveal", "Find files by name. args: {pattern (e.g. \"*.md\", \"notes/**/*.txt\"; without a / it matches names at any depth), path? (default ~)}."),
    ("ls", "reveal", "List a folder. args: {path}."),
    ("copy", "reveal", "Get a copy of a file of any type (up to 2 GiB), downloaded to your machine. args: {path}."),
    ("write", "change", "Create or overwrite a text file. args: {path, content}. Always waits for the owner's approval."),
];

const OPENS_PER_HOUR: i64 = 30;
const CALLS_PER_HOUR: i64 = 600;
const SESSION_IDLE_MS: i64 = 2 * 3_600_000;
const READ_MAX_CHARS: usize = 20_000;
const OUTPUT_MAX_CHARS: usize = 60_000;
const WRITE_MAX_BYTES: usize = 1 << 20;
const SKIP_DIRS: [&str; 8] = ["node_modules", "target", "__pycache__", "venv", "dist", "build", "Pods", "DerivedData"];

pub fn catalog() -> Vec<Value> {
    TOOLS.iter().map(|(n, e, d)| json!({ "name": n, "effect": e, "description": d })).collect()
}

/// One piece of output, judged on its own: a file's lines, one file's matches, a listing.
#[derive(Clone)]
pub(crate) struct Item {
    pub path: String,
    pub text: String,
}

pub(crate) struct Ran {
    pub items: Vec<Item>,
    /// Shown after the items: "(lines 1-400 of 2000; …)", "(stopped at 200 matches)".
    pub note: String,
}

/// What the asking agent sees: the items (grep's under their file name), how many were held back, then the note.
pub(crate) fn render(tool: &str, items: &[&Item], held: usize, note: &str) -> String {
    let out: Vec<String> = items.iter().map(|it| if tool == "grep" { format!("{}\n{}", it.path, it.text) } else { it.text.clone() }).collect();
    let mut out = if matches!(tool, "glob" | "ls") { vec![out.join("\n")] } else { out };
    if held > 0 {
        out.push(format!("({held} result(s) not shared)"));
    }
    if !note.is_empty() {
        out.push(note.to_string());
    }
    out.join("\n\n")
}

#[derive(Clone, Debug)]
enum Verdict {
    Send,
    Withhold(&'static str),
    Unsure(String),
}

/// A call as the owner's side sees it.
#[derive(Clone)]
struct Ctx {
    c: Contact,
    person: i64,
    sid: String,
    mid: String,
    tool: String,
    why: String,
    intent: String,
    path: PathBuf,
    args: Value,
}

impl Ctx {
    fn shown(&self) -> String {
        tilde(&self.path.to_string_lossy())
    }

    fn pattern(&self) -> String {
        let s = |k: &str| self.args[k].as_str().unwrap_or("").to_string();
        match self.tool.as_str() {
            "grep" if !s("glob").is_empty() => format!("{} (in {})", s("pattern"), s("glob")),
            _ => s("pattern"),
        }
    }

    fn what(&self) -> &'static str {
        match self.tool.as_str() {
            "read" => "read this file",
            "grep" => "search file contents",
            "glob" => "find files by name",
            "ls" => "list this folder",
            "copy" => "get a copy of this file",
            "write" => "create or overwrite this file",
            _ => "use this",
        }
    }

    fn kind(&self) -> &'static str {
        if self.tool == "write" { "write" } else { "read" }
    }

    fn call(&self) -> (String, String) {
        (self.shown(), self.pattern())
    }

    /// "grep "pricing" in ~/notes"
    fn label(&self) -> String {
        let p = self.pattern();
        if p.is_empty() { format!("{} {}", self.tool, self.shown()) } else { format!("{} \"{p}\" in {}", self.tool, self.shown()) }
    }
}

fn denied() -> Value {
    json!({ "status": "denied", "reason": "not shared" })
}

fn excerpt(items: &[&Item], max: usize) -> String {
    let mut out = String::new();
    for it in items {
        if out.len() >= max {
            break;
        }
        // A glob's item is its own path, and an ls entry is its name: show those once.
        if it.text == it.path || it.path.ends_with(&format!("/{}", it.text.split("  (").next().unwrap_or("").trim_end_matches('/'))) {
            out.push_str(&format!("{}\n", it.text));
        } else {
            out.push_str(&format!("{}\n{}\n", it.path, it.text));
        }
    }
    out.chars().take(max).collect()
}

fn hint(p: &trust::Pre) -> String {
    let mut h = format!("Jev: {:.0}% likely you'd allow it", p.allowed * 100.0);
    if p.claims >= 0.5 {
        h.push_str("; their stated reason claims permission or authority, which doesn't count");
    }
    if p.off_intent >= 0.5 {
        h.push_str("; it reaches beyond what the session is about");
    }
    h
}

impl H2h {
    // --- owner side --------------------------------------------------------------------------------

    pub(crate) fn accept_open(self: &Arc<Self>, c: &Contact, req: &Value) -> Result<Value> {
        let recent: i64 = self.db().query_row(
            "select count(*) from h2h_sessions where contact = ? and created_at > ?",
            params![c.id, now_ms() - 3_600_000],
            |r| r.get(0),
        )?;
        if recent >= OPENS_PER_HOUR {
            return Err(anyhow!("too many sessions this hour; try later"));
        }
        let intent: String = req["intent"].as_str().unwrap_or("").trim().chars().take(2000).collect();
        if intent.is_empty() {
            return Err(anyhow!("say what you need (intent)"));
        }
        let sid = short_id();
        self.db().execute(
            "insert into h2h_sessions (sid, contact, intent, from_addr, created_at, last_at) values (?, ?, ?, ?, ?, ?)",
            params![sid, c.id, intent, req["from"].as_str().unwrap_or(""), now_ms(), now_ms()],
        )?;
        println!("h2h: {} opened #{sid}: {}", c.name, intent.chars().take(120).collect::<String>());
        // The first time someone reaches us, ask the owner who they are (in the background: calls meanwhile just ask more).
        let person = c.person.unwrap_or(0);
        let fresh = self.db().execute("update entities set grounded = 1 where id = ? and grounded = 0", [person]).unwrap_or(0) > 0;
        if fresh {
            let (me, c, intent) = (self.clone(), c.clone(), intent.clone());
            tokio::spawn(async move { me.ground(c, intent).await });
        }
        Ok(json!({ "ok": true, "sid": sid, "tools": catalog() }))
    }

    pub(crate) async fn accept_tool(self: &Arc<Self>, c: &Contact, req: &Value) -> Result<Value> {
        let s = |k: &str| req[k].as_str().unwrap_or("").to_string();
        let (sid, tool) = (s("sid"), s("tool"));
        let intent: Option<String> = self
            .db()
            .query_row("select intent from h2h_sessions where sid = ? and contact = ? and last_at > ?", params![sid, c.id, now_ms() - SESSION_IDLE_MS], |r| r.get(0))
            .optional()?;
        let intent = intent.ok_or_else(|| anyhow!("no such session (it may have expired); open a new one"))?;
        let calls: i64 = self.db().query_row(
            "select coalesce(sum(calls), 0) from h2h_sessions where contact = ? and last_at > ?",
            params![c.id, now_ms() - 3_600_000],
            |r| r.get(0),
        )?;
        if calls >= CALLS_PER_HOUR {
            return Err(anyhow!("too many calls this hour; try later"));
        }
        self.db().execute("update h2h_sessions set last_at = ?, calls = calls + 1 where sid = ?", params![now_ms(), sid])?;
        let effect = TOOLS.iter().find(|t| t.0 == tool).map(|t| t.1).ok_or_else(|| {
            anyhow!("no tool \"{tool}\"; tools: {}", TOOLS.iter().map(|t| t.0).collect::<Vec<_>>().join(", "))
        })?;
        let args = if req["args"].is_object() { req["args"].clone() } else { json!({}) };
        let path_arg = args["path"].as_str().unwrap_or("").trim().to_string();
        if path_arg.is_empty() && !matches!(tool.as_str(), "grep" | "glob") {
            return Err(anyhow!("args.path is required for {tool}"));
        }
        if matches!(tool.as_str(), "grep" | "glob") && args["pattern"].as_str().unwrap_or("").is_empty() {
            return Err(anyhow!("args.pattern is required for {tool}"));
        }
        let x = Ctx {
            c: c.clone(),
            person: c.person.unwrap_or(0),
            mid: s("mid"),
            why: s("why").chars().take(1000).collect(),
            intent,
            path: resolve(&home_dir(), if path_arg.is_empty() { "~" } else { &path_arg }),
            args,
            sid,
            tool,
        };
        println!("h2h: {} #{}: {} (why: {})", c.name, x.sid, x.label(), x.why.chars().take(100).collect::<String>());
        if effect == "reveal" { self.reveal(x).await } else { self.change(x).await }
    }

    fn rec(&self, x: &Ctx, resource: &str, decision: &str, by: &str, score: Option<f64>, phase: &str, reason: &str, excerpt: &str) {
        trust::record(
            &self.db(),
            &trust::Rec {
                rid: &x.sid, contact: &x.c.id, person: x.person, kind: x.kind(), tool: &x.tool, resource, decision, by, score, phase,
                why: &x.why, intent: &x.intent, reason, excerpt,
            },
        );
    }

    /// Jev decided something on its own: tell the owner, at most once a minute per session.
    fn jev_banner(&self, x: &Ctx, what: &str) {
        let mut b = self.banners.lock().unwrap();
        let last = b.get(&x.sid).copied().unwrap_or(0);
        if now_ms() - last > 60_000 {
            b.insert(x.sid.clone(), now_ms());
            notify_banner(&format!("agentbus: Jev decided for {}", x.c.name), &format!("{what}. Everything is in agentbus h2h log."));
        }
    }

    fn state(&self, x: &Ctx) -> Value {
        let (path, pattern) = x.call();
        let call = trust::Call { sid: &x.sid, tool: &x.tool, what: x.what(), path: &path, pattern: &pattern, why: &x.why, intent: &x.intent };
        trust::state(&self.db(), &owner_name(), x.person, x.c.level == "trusted", &call, None)
    }

    async fn reveal(self: &Arc<Self>, x: Ctx) -> Result<Value> {
        let t = trust::threshold();
        let path_str = x.path.to_string_lossy().into_owned();
        let (never, granted, repeat, never_paths) = {
            let db = self.db();
            let chain = trust::chain(&db, x.person);
            // The same path-only call refused earlier in this session (a search with another pattern is another question).
            let repeat: i64 = if matches!(x.tool.as_str(), "read" | "ls" | "copy") {
                db.query_row(
                    "select count(*) from h2h_log where rid = ? and tool = ? and resource = ? and decision = 'deny'",
                    params![x.sid, x.tool, path_str],
                    |r| r.get(0),
                )
                .unwrap_or(0)
            } else {
                0
            };
            let never_paths: Vec<String> = trust::statements_for(&db, &chain).into_iter().filter_map(|(s, _)| s.path.filter(|_| s.kind == "never")).collect();
            (trust::hard_never(&db, &chain, &x.path), trust::granted(&db, &chain, &x.path), repeat > 0, never_paths)
        };
        if let Some(why) = never {
            self.rec(&x, &path_str, "deny", "never", None, "pre", &why, "");
            return Ok(denied());
        }
        if repeat {
            self.rec(&x, &path_str, "deny", "repeat", None, "pre", "", "");
            return Ok(denied());
        }

        // Before it runs. For a read, this check can refuse or flag the call, not allow it: from a path and a purpose
        // alone Jev is rarely sure, and what may leave is decided on the actual output below. A flagged call (it claims
        // authority, or drifts from the session's intent) always goes to the owner.
        let base = self.state(&x);
        let (gate, ask_hint): (Option<&'static str>, String) = if x.c.level == "trusted" {
            (Some("trusted"), String::new())
        } else if granted.is_some() {
            (Some("grant"), String::new())
        } else {
            match trust::pre_check(base.clone()).await {
                Some(p) if p.forbidden >= t => {
                    self.rec(&x, &path_str, "deny", "jev", Some(p.forbidden), "pre", "", "");
                    self.jev_banner(&x, &format!("refused {}", x.label()));
                    return Ok(denied());
                }
                Some(p) if p.claims < 0.5 && p.off_intent < 0.5 => (Some("clear"), hint(&p)),
                Some(p) => (None, hint(&p)),
                None => (None, "Jev couldn't judge this (no TypeSafe key, or the call failed)".into()),
            }
        };

        // Read-only, so it runs now: if the owner is asked, they decide on what would really be sent.
        let (tool, path, args) = (x.tool.clone(), x.path.clone(), x.args.clone());
        let ran = tokio::task::spawn_blocking(move || run(&tool, &path, &args, &never_paths)).await.map_err(|e| anyhow!("{e}"))??;
        if ran.items.is_empty() {
            return Ok(json!({ "status": "ok", "output": format!("Nothing found. {}", ran.note).trim().to_string() }));
        }

        // After: the scanner, decisions already made about this exact content, then Jev on the rest.
        let keys: Vec<String> = {
            let db = self.db();
            ran.items.iter().map(|it| trust::item_key(&db, x.person, &it.path, &it.text)).collect()
        };
        let mut verdicts: Vec<Verdict> = Vec::new();
        for (it, key) in ran.items.iter().zip(&keys) {
            let cached = trust::cache_get(&self.db(), key);
            verdicts.push(if let Some(what) = secret_scan(&it.text) {
                self.rec(&x, &it.path, "deny", "scan", None, "post", &format!("contains {what}"), "");
                Verdict::Withhold("scan")
            } else {
                match cached.as_ref().map(|(d, _)| d.as_str()) {
                    Some("allow") => Verdict::Send,
                    Some(_) => Verdict::Withhold("cache"),
                    None => Verdict::Unsure(ask_hint.clone()),
                }
            });
        }
        let todo: Vec<usize> = (0..verdicts.len()).filter(|i| matches!(verdicts[*i], Verdict::Unsure(_))).collect();
        if !todo.is_empty() {
            let items: Vec<(String, String)> = todo.iter().map(|i| (ran.items[*i].path.clone(), ran.items[*i].text.clone())).collect();
            if let Some(scores) = trust::post_check(base, &items).await {
                for (i, (ok, never)) in todo.iter().zip(scores) {
                    let it = &ran.items[*i];
                    if never >= t {
                        self.rec(&x, &it.path, "deny", "jev", Some(never), "post", "", &it.text);
                        trust::cache_put(&self.db(), &keys[*i], "deny", "jev");
                        verdicts[*i] = Verdict::Withhold("jev");
                    } else if ok >= t && gate.is_some() {
                        self.rec(&x, &it.path, "allow", "jev", Some(ok), "post", "", &it.text);
                        trust::cache_put(&self.db(), &keys[*i], "allow", "jev");
                        verdicts[*i] = Verdict::Send;
                    } else if ok >= t {
                        verdicts[*i] = Verdict::Unsure(format!("{ask_hint}; on the content itself, Jev thinks it's fine ({:.0}%) but the call was flagged", ok * 100.0));
                    } else {
                        let h = format!("Jev: {:.0}% likely fine to send", ok * 100.0);
                        verdicts[*i] = Verdict::Unsure(if ask_hint.is_empty() { h } else { format!("{ask_hint}; {h}") });
                    }
                }
            }
        }
        // Allowed by the owner's standing choices (trusted, or an always-allowed folder): only a confident never holds back.
        if matches!(gate, Some("trusted" | "grant")) {
            for (i, v) in verdicts.iter_mut().enumerate() {
                if matches!(v, Verdict::Unsure(_)) {
                    self.rec(&x, &ran.items[i].path, "allow", gate.unwrap_or(""), None, "post", "", "");
                    *v = Verdict::Send;
                }
            }
        }
        if verdicts.iter().any(|v| matches!(v, Verdict::Withhold("jev"))) {
            self.jev_banner(&x, &format!("withheld part of {}", x.label()));
        }

        let unsure: Vec<usize> = (0..verdicts.len()).filter(|i| matches!(verdicts[*i], Verdict::Unsure(_))).collect();
        if unsure.is_empty() {
            let sent: Vec<bool> = verdicts.iter().map(|v| matches!(v, Verdict::Send)).collect();
            return self.finish(&x, &ran, &sent);
        }
        // The owner decides on the pieces nobody is sure about; the asker gets the whole result later.
        let (me, x2, ran2) = (self.clone(), x.clone(), ran);
        tokio::spawn(async move { me.owner_decides(x2, ran2, verdicts, unsure).await });
        Ok(json!({ "status": "pending", "note": format!("{} is being asked about this", owner_name()) }))
    }

    /// The output for the asker, and any file offer: only the items marked to send.
    fn finish(&self, x: &Ctx, ran: &Ran, sent: &[bool]) -> Result<Value> {
        let held = sent.iter().filter(|s| !**s).count();
        if held == ran.items.len() {
            return Ok(denied());
        }
        let shown: Vec<&Item> = ran.items.iter().zip(sent).filter(|(_, s)| **s).map(|(it, _)| it).collect();
        let files = if x.tool == "copy" { vec![self.offer(&x.c, &x.path)?] } else { vec![] };
        Ok(json!({ "status": "ok", "output": render(&x.tool, &shown, held, &ran.note), "files": files }))
    }

    async fn owner_decides(self: Arc<Self>, x: Ctx, ran: Ran, mut verdicts: Vec<Verdict>, unsure: Vec<usize>) {
        let chain = trust::chain_label(&trust::chain(&self.db(), x.person));
        let hints: Vec<String> = unsure.iter().filter_map(|i| if let Verdict::Unsure(h) = &verdicts[*i] { Some(h.clone()) } else { None }).collect();
        let hint = hints.into_iter().find(|h| !h.is_empty()).unwrap_or_default();
        let pieces: Vec<&Item> = unsure.iter().map(|i| &ran.items[*i]).collect();
        let of = if ran.items.len() > 1 { format!(" ({} of {} results)", unsure.len(), ran.items.len()) } else { String::new() };
        let body = format!(
            "{chain} wants to {}:\n{}\n\nWhy: {}\nSession: {}\n{hint}\n\nWould send{of}:\n{}\n\nYour reason (optional; Jev learns from it):",
            x.what(),
            x.label(),
            if x.why.is_empty() { "(none given)" } else { &x.why },
            x.intent.chars().take(200).collect::<String>(),
            excerpt(&pieces, 700),
        );
        let reply = self.manual(&x.c, &x.sid, "read", &x.tool, &x.label(), &body, &MANUAL_BUTTONS).await;
        let allow = reply.choice != Choice::Deny;
        let decision = if allow { "allow" } else { "deny" };
        // One answer covers every piece shown, but the reason may only be about some of them: only those become precedent.
        let covered: Vec<bool> = if unsure.len() > 1 && !reply.text.trim().is_empty() {
            let items: Vec<(String, String)> = unsure.iter().map(|i| (ran.items[*i].path.clone(), ran.items[*i].text.clone())).collect();
            match trust::reason_covers(decision, &reply.text, &items).await {
                Some(c) => c.into_iter().map(|p| p >= 0.5).collect(),
                None => vec![true; unsure.len()],
            }
        } else {
            vec![true; unsure.len()]
        };
        for (i, covered) in unsure.iter().zip(covered) {
            let it = &ran.items[*i];
            verdicts[*i] = if allow { Verdict::Send } else { Verdict::Withhold("manual") };
            if !covered {
                continue;
            }
            self.rec(&x, &it.path, decision, "manual", None, "post", &reply.text, &it.text);
            let key = trust::item_key(&self.db(), x.person, &it.path, &it.text);
            trust::cache_put(&self.db(), &key, decision, "manual");
        }
        if reply.choice == Choice::Always {
            let folder = if x.path.is_dir() { x.path.clone() } else { x.path.parent().map(Path::to_path_buf).unwrap_or(x.path.clone()) };
            let db = self.db();
            if let Some(e) = trust::entity(&db, x.person) {
                let _ = trust::grant(&db, Some(&e), &folder);
            }
        }
        let sent: Vec<bool> = verdicts.iter().map(|v| matches!(v, Verdict::Send)).collect();
        let (body, files) = match self.finish(&x, &ran, &sent) {
            Ok(v) if v["status"] == "ok" => (v["output"].as_str().unwrap_or("").to_string(), v["files"].clone()),
            Ok(_) => ("Not shared.".to_string(), json!([])),
            Err(e) => (format!("Couldn't finish: {e}"), json!([])),
        };
        self.send_answer(&x.c, &x.mid, &format!("Result of {}:\n\n{body}", x.label()), files).await;
    }

    async fn change(self: &Arc<Self>, x: Ctx) -> Result<Value> {
        let path_str = x.path.to_string_lossy().into_owned();
        let never = {
            let db = self.db();
            trust::hard_never(&db, &trust::chain(&db, x.person), &x.path)
        };
        if let Some(why) = never {
            self.rec(&x, &path_str, "deny", "never", None, "pre", &why, "");
            return Ok(denied());
        }
        let content = x.args["content"].as_str().unwrap_or("").to_string();
        if content.len() > WRITE_MAX_BYTES {
            return Err(anyhow!("content is over 1 MiB"));
        }
        if x.path.is_dir() {
            return Err(anyhow!("{} is a folder", x.shown()));
        }
        let hint = match trust::pre_check(self.state(&x)).await {
            Some(p) if p.forbidden >= trust::threshold() => {
                self.rec(&x, &path_str, "deny", "jev", Some(p.forbidden), "pre", "", &content);
                self.jev_banner(&x, &format!("refused {}", x.label()));
                return Ok(denied());
            }
            Some(p) => hint(&p),
            None => String::new(),
        };
        let (me, x) = (self.clone(), x.clone());
        tokio::spawn(async move {
            let chain = trust::chain_label(&trust::chain(&me.db(), x.person));
            let exists = if x.path.exists() { "overwrite" } else { "create" };
            let body = format!(
                "{chain} wants to {exists} a file:\n{} ({})\n\nWhy: {}\nSession: {}\n{hint}\n\nContent:\n{}\n\nYour reason (optional):",
                x.shown(),
                human(content.len() as u64),
                if x.why.is_empty() { "(none given)" } else { &x.why },
                x.intent.chars().take(200).collect::<String>(),
                content.chars().take(600).collect::<String>()
            );
            let reply = me.manual(&x.c, &x.sid, "write", &x.tool, &x.shown(), &body, &["Deny", "Allow once"]).await;
            let allow = reply.choice != Choice::Deny;
            me.rec(&x, &path_str, if allow { "allow" } else { "deny" }, "manual", None, "pre", &reply.text, &content);
            let result = if !allow {
                "Not allowed.".to_string()
            } else {
                let write = || -> Result<()> {
                    if let Some(dir) = x.path.parent() {
                        std::fs::create_dir_all(dir)?;
                    }
                    std::fs::write(&x.path, &content)?;
                    Ok(())
                };
                match write() {
                    Ok(()) => format!("Wrote {} ({}).", x.shown(), human(content.len() as u64)),
                    Err(e) => format!("Allowed, but writing failed: {e}"),
                }
            };
            me.send_answer(&x.c, &x.mid, &format!("Result of write {}: {result}", x.shown()), json!([])).await;
        });
        Ok(json!({ "status": "pending", "note": format!("{} decides on every change", owner_name()) }))
    }

    /// The grounding questions, asked once per person the first time they reach us. Each answer is optional.
    async fn ground(self: Arc<Self>, c: Contact, intent: String) {
        let n = c.name.clone();
        let ask = |q: String| {
            let me = self.clone();
            let c = c.clone();
            async move {
                let r = me.manual(&c, "ground", "ground", "ground", &q, &q, &["Skip", "Save"]).await;
                Some(r.text.trim().to_string()).filter(|t| r.choice != Choice::Deny && !t.is_empty())
            }
        };
        let relation = ask(format!(
            "{n}'s agent is reaching you for the first time:\n\"{}\"\n\nWho is {n} to you? (e.g. co-founder at Acme, a friend from uni, a client at Barbican)",
            intent.chars().take(200).collect::<String>()
        ))
        .await;
        let note = ask(format!("What do you and {n} work on together, or what might they ask about?")).await;
        let never = ask(format!("Anything {n} should never see? (leave empty if nothing)")).await;
        let person = c.person.unwrap_or(0);
        let (e, candidates) = {
            let db = self.db();
            let e = trust::entity(&db, person);
            if let Some(e) = &e {
                let _ = trust::upsert(&db, &e.name, None, relation.as_deref(), note.as_deref());
                if let Some(t) = &never {
                    let _ = trust::add_statement(&db, Some(e), "never", t, "grounding");
                }
            }
            let candidates: Vec<trust::Entity> = trust::entities(&db).into_iter().filter(|x| x.kind != "person").take(40).collect();
            (e, candidates)
        };
        let Some(e) = e else { return };
        let description = [relation.clone(), note.clone()].into_iter().flatten().collect::<Vec<_>>().join(". ");
        let mut linked = Vec::new();
        if let Some(scores) = trust::suggest_links(&e.name, &description, &candidates).await {
            let db = self.db();
            for (g, s) in candidates.iter().zip(scores) {
                if s >= trust::threshold() && trust::link(&db, &e, g, "member_of").is_ok() {
                    linked.push(g.name.clone());
                }
            }
        }
        let mut summary = format!("Saved what you said about {n}.");
        if !linked.is_empty() {
            summary.push_str(&format!(" Added them to {} (undo: agentbus h2h unlink {n} GROUP).", linked.join(", ")));
        }
        if relation.is_some() || note.is_some() || never.is_some() {
            notify_banner("agentbus", &summary);
        }
    }

    /// Replays your recent manual read decisions through Jev's post-check (each without itself as precedent) and
    /// reports how often it agrees with you. False allows are the number that matters.
    pub(crate) async fn eval(&self, limit: i64) -> Result<String> {
        let rows: Vec<(i64, i64, String, String, String, String, Option<String>, Option<String>, String)> = {
            let db = self.db();
            let mut st = db.prepare(
                "select l.id, l.person, coalesce(c.level, 'normal'), l.tool, l.resource, l.decision, l.intent, l.why, l.excerpt
                 from h2h_log l left join h2h_contacts c on c.id = l.contact
                 where l.by = 'manual' and l.kind = 'read' and l.excerpt is not null and l.person is not null order by l.id desc limit ?",
            )?;
            let rows = st
                .query_map([limit], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?)))?
                .filter_map(|r| r.ok())
                .collect();
            rows
        };
        if rows.is_empty() {
            return Ok("Nothing to replay yet: eval uses reads you decided yourself (they keep a local excerpt of what would have been sent).".into());
        }
        if typesafe_key_missing() {
            return Err(anyhow!("no TypeSafe key (agentbus h2h config typesafe-key …)"));
        }
        let t = trust::threshold();
        let (mut agree, mut unsure, mut false_allow, mut false_deny) = (0, 0, 0, 0);
        let mut lines = Vec::new();
        for (id, person, level, tool, resource, decision, intent, why, text) in &rows {
            let shown = tilde(resource);
            let (intent, why) = (intent.clone().unwrap_or_default(), why.clone().unwrap_or_default());
            let state = {
                let call = trust::Call { sid: "", tool, what: "", path: &shown, pattern: "", why: &why, intent: &intent };
                trust::state(&self.db(), &owner_name(), *person, level == "trusted", &call, Some(*id))
            };
            let Some(scores) = trust::post_check(state, &[(shown.clone(), text.clone())]).await else {
                lines.push(format!("  #{id} Jev call failed"));
                continue;
            };
            let (ok, never) = scores[0];
            let jev = if never >= t { "deny" } else if ok >= t { "allow" } else { "unsure" };
            match (jev, decision.as_str()) {
                ("unsure", _) => unsure += 1,
                (j, d) if j == d => agree += 1,
                ("allow", _) => false_allow += 1,
                _ => false_deny += 1,
            }
            if jev != decision {
                lines.push(format!("  #{id} you: {decision:<5} jev: {jev:<6} (ok {ok:.2}, never {never:.2})  {}", shown.chars().take(70).collect::<String>()));
            }
        }
        let n = rows.len();
        Ok(format!(
            "Replayed {n} of your decisions through Jev (threshold {t}):\n  agreed {agree}, unsure (would ask you) {unsure}, \
             false allows {false_allow}, false denies {false_deny}\n{}",
            if lines.is_empty() { "  no disagreements".into() } else { format!("Disagreements:\n{}", lines.join("\n")) }
        ))
    }

    // --- asker side ------------------------------------------------------------------------------

    pub async fn open_session(&self, a: &Agent, to: &str, intent: &str) -> Result<String> {
        let c = self.contact_by_name(to)?;
        if c.state == "waiting" && self.hello(&c).await.is_err() {
            return Err(anyhow!("{} hasn't added you yet, so nothing can reach them. Ask them to run: agentbus h2h add {}", c.name, self.code()));
        }
        if intent.trim().is_empty() {
            return Err(anyhow!("say what you need from {} (intent); it's shown to them and their permissions judge every call against it", c.name));
        }
        if let Some(what) = secret_scan(intent) {
            return Err(anyhow!("not sent: the intent seems to contain {what}"));
        }
        let sid = self.open_with(a, &c, intent).await?;
        let tools: Vec<String> = TOOLS.iter().map(|(n, _, d)| format!("  {n}: {d}")).collect();
        Ok(format!(
            "Session #{sid} open with {n}. Call their tools with remote_call(to=\"{n}\", tool, args, why). Paths are relative to their home \
             folder. Every call is checked against {n}'s permissions: many answer right away, some wait for {n} to decide (those results \
             arrive in your inbox), and anything private is refused.\n\nTools:\n{}",
            tools.join("\n"),
            n = c.name
        ))
    }

    async fn open_with(&self, a: &Agent, c: &Contact, intent: &str) -> Result<String> {
        let r = self
            .call_t(&c.id, &json!({ "t": "open", "from": self.d.addr(a), "intent": intent }), Duration::from_secs(30))
            .await
            .map_err(|e| older(c, e))?;
        let sid = r["sid"].as_str().ok_or_else(|| anyhow!("no session id in the reply"))?.to_string();
        self.db().execute(
            "insert into h2h_out_sessions (agent_key, contact, sid, intent, at) values (?, ?, ?, ?, ?)
             on conflict(agent_key, contact) do update set sid = excluded.sid, intent = excluded.intent, at = excluded.at",
            params![a.key, c.id, sid, intent, now_ms()],
        )?;
        Ok(sid)
    }

    pub async fn remote_call(&self, a: &Agent, to: &str, tool: &str, args: &Value, why: &str) -> Result<String> {
        let c = self.contact_by_name(to)?;
        let open: Option<(String, String)> = self
            .db()
            .query_row("select sid, intent from h2h_out_sessions where agent_key = ? and contact = ?", params![a.key, c.id], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        let (mut sid, intent) = open.ok_or_else(|| anyhow!("open a session with {} first: open_session(to=\"{}\", intent=\"what you need and why\")", c.name, c.name))?;
        if why.trim().is_empty() {
            return Err(anyhow!("say why you need this (why); {} sees it, and their permissions judge the call against it", c.name));
        }
        if let Some(what) = secret_scan(&format!("{args} {why}")) {
            return Err(anyhow!("not sent: the call seems to contain {what}"));
        }
        let mid = short_id();
        self.db().execute(
            "insert into messages (mid, dir, agent_key, from_addr, from_info, to_addr, body, wake, created_at, status, target_device)
             values (?, 'out', ?, ?, 'tool', ?, ?, 1, ?, 'delivered', ?)",
            params![mid, a.key, self.d.addr(a), c.name, format!("{tool} {args}"), now_ms(), format!("h2h:{}", c.id)],
        )?;
        let req = |sid: &str| json!({ "t": "tool", "sid": sid, "mid": mid, "from": self.d.addr(a), "tool": tool, "args": args, "why": why });
        let t = Duration::from_secs(90);
        let mut r = self.call_t(&c.id, &req(&sid), t).await;
        if r.as_ref().is_err_and(|e| e.to_string().contains("no such session")) {
            sid = self.open_with(a, &c, &intent).await?;
            r = self.call_t(&c.id, &req(&sid), t).await;
        }
        let r = r.map_err(|e| older(&c, e))?;
        Ok(match r["status"].as_str().unwrap_or("") {
            "ok" => {
                let out = r["output"].as_str().unwrap_or("").to_string();
                let files: Vec<Value> = r["files"].as_array().cloned().unwrap_or_default();
                if files.is_empty() { out } else { format!("{out}\n\n{}", self.download_all(&c, &files).await).trim().to_string() }
            }
            "pending" => format!(
                "Waiting: {} (#{mid}). The result arrives in your inbox as a reply to #{mid}; carry on with other calls meanwhile.",
                r["note"].as_str().unwrap_or("they're being asked")
            ),
            "denied" => format!("Not shared by {}.", c.name),
            s => format!("Unexpected reply from {} ({s}).", c.name),
        })
    }
}

fn typesafe_key_missing() -> bool {
    crate::h2h::typesafe_key().is_none()
}

/// A 0.5 daemon answers tool calls with "unknown request".
fn older(c: &Contact, e: anyhow::Error) -> anyhow::Error {
    if e.to_string().contains("unknown request") {
        anyhow!("{}'s agentbus is older and doesn't take remote tool calls; ask them to run: agentbus upgrade", c.name)
    } else {
        e
    }
}

// --- the tools themselves (blocking; run on a worker thread) ---------------------------------------

pub(crate) fn run(tool: &str, path: &Path, args: &Value, never_paths: &[String]) -> Result<Ran> {
    let shown = tilde(&path.to_string_lossy());
    match tool {
        "read" => {
            let text = read_text(path)?;
            let total = text.lines().count();
            let start = args["offset"].as_u64().unwrap_or(1).max(1) as usize;
            let limit = args["limit"].as_u64().unwrap_or(400).clamp(1, 2000) as usize;
            let mut out = String::new();
            let mut last = start - 1;
            for (i, line) in text.lines().enumerate().skip(start - 1).take(limit) {
                let l = format!("{:>6}\t{}\n", i + 1, line.chars().take(2000).collect::<String>());
                if out.len() + l.len() > READ_MAX_CHARS && !out.is_empty() {
                    break;
                }
                out.push_str(&l);
                last = i + 1;
            }
            let note = if last < total { format!("(lines {start}-{last} of {total}; continue with offset {})", last + 1) } else { String::new() };
            if out.is_empty() {
                out = if total == 0 { "(empty file)".into() } else { format!("(the file has {total} lines)") };
            }
            Ok(Ran { items: vec![Item { path: shown, text: out }], note })
        }
        "grep" => {
            let pattern = args["pattern"].as_str().unwrap_or("");
            let re = RegexBuilder::new(pattern)
                .case_insensitive(args["ignore_case"].as_bool() == Some(true))
                .size_limit(1 << 20)
                .build()
                .map_err(|e| anyhow!("bad pattern: {e}"))?;
            let only = args["glob"].as_str().filter(|g| !g.is_empty()).map(glob_regex).transpose()?;
            let (mut items, mut matches, mut size, mut stopped) = (Vec::new(), 0, 0, false);
            let mut search = |p: &Path| -> bool {
                if only.as_ref().is_some_and(|g| !g.is_match(&p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default())) {
                    return true;
                }
                let Ok(text) = read_text(p) else { return true };
                let hits: Vec<String> = text
                    .lines()
                    .enumerate()
                    .filter(|(_, l)| re.is_match(l))
                    .take(50)
                    .map(|(i, l)| format!("  {}: {}", i + 1, l.trim().chars().take(300).collect::<String>()))
                    .collect();
                if !hits.is_empty() {
                    matches += hits.len();
                    let t = hits.join("\n");
                    size += t.len();
                    items.push(Item { path: tilde(&p.to_string_lossy()), text: t });
                }
                let more = matches < 200 && items.len() < 40 && size < OUTPUT_MAX_CHARS;
                stopped |= !more;
                more
            };
            if path.is_file() {
                search(path);
            } else {
                walk(path, never_paths, &mut search);
            }
            let note = if stopped { format!("(stopped at {matches} matches in {} files; narrow the search to see more)", items.len()) } else { String::new() };
            Ok(Ran { items, note })
        }
        "glob" => {
            let pattern = args["pattern"].as_str().unwrap_or("");
            let re = glob_regex(pattern)?;
            let by_name = !pattern.contains('/');
            let mut found = Vec::new();
            walk(path, never_paths, &mut |p: &Path| {
                let rel = p.strip_prefix(path).unwrap_or(p).to_string_lossy().into_owned();
                let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                if re.is_match(if by_name { &name } else { &rel }) {
                    found.push(tilde(&p.to_string_lossy()));
                }
                found.len() < 500
            });
            let note = if found.len() >= 500 { "(stopped at 500 files; narrow the pattern)".into() } else { String::new() };
            // One item per file (per folder when there are many), so a private name is held back without hiding the rest.
            if found.len() <= 60 {
                return Ok(Ran { items: found.into_iter().map(|f| Item { path: f.clone(), text: f }).collect(), note });
            }
            let mut by_dir: Vec<(String, Vec<String>)> = Vec::new();
            for f in found {
                let dir = f.rsplit_once('/').map(|(d, _)| d.to_string()).unwrap_or_default();
                match by_dir.iter_mut().find(|(d, _)| *d == dir) {
                    Some((_, fs)) => fs.push(f),
                    None => by_dir.push((dir, vec![f])),
                }
            }
            Ok(Ran { items: by_dir.into_iter().map(|(dir, fs)| Item { path: dir, text: fs.join("\n") }).collect(), note })
        }
        "ls" => {
            if !path.is_dir() {
                return Err(anyhow!("{shown} isn't a folder"));
            }
            let mut entries: Vec<(bool, String, u64)> = std::fs::read_dir(path)?
                .flatten()
                .filter(|e| !trust::is_sensitive(&e.path()) && !never_paths.iter().any(|n| e.path().starts_with(n)))
                .map(|e| {
                    let m = e.metadata().ok();
                    (m.as_ref().is_some_and(|m| m.is_dir()), e.file_name().to_string_lossy().into_owned(), m.map(|m| m.len()).unwrap_or(0))
                })
                .collect();
            entries.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.to_lowercase().cmp(&b.1.to_lowercase())));
            let n = entries.len();
            let lines: Vec<String> = entries.into_iter().take(500).map(|(d, name, size)| if d { format!("{name}/") } else { format!("{name}  ({})", human(size)) }).collect();
            let note = if n > 500 { format!("(first 500 of {n})") } else { String::new() };
            if lines.is_empty() {
                return Ok(Ran { items: vec![Item { path: shown, text: "(empty folder)".into() }], note });
            }
            // Each entry judged on its own (in groups of 10 for big folders), so one private name doesn't hide the rest.
            let per = if lines.len() <= 60 { 1 } else { 10 };
            let items = lines
                .chunks(per)
                .map(|c| Item { path: if per == 1 { format!("{shown}/{}", c[0].split("  (").next().unwrap_or("").trim_end_matches('/')) } else { shown.clone() }, text: c.join("\n") })
                .collect();
            Ok(Ran { items, note })
        }
        "copy" => {
            let meta = std::fs::metadata(path).map_err(|_| anyhow!("no file at {shown}"))?;
            if !meta.is_file() {
                return Err(anyhow!("{shown} isn't a file"));
            }
            // What Jev and the owner judge: the text itself, or for anything else, what the file is.
            let text = match read_text(path) {
                Ok(t) => t.chars().take(READ_MAX_CHARS).collect(),
                Err(_) => format!("(binary file {}, {})", base_name(&shown), human(meta.len())),
            };
            Ok(Ran { items: vec![Item { path: shown.clone(), text }], note: format!("({shown}, {}, sent as a file)", human(meta.len())) })
        }
        _ => Err(anyhow!("no tool {tool}")),
    }
}

/// A text file's contents; refuses binary files and anything over 10 MB.
fn read_text(p: &Path) -> Result<String> {
    let meta = std::fs::metadata(p).map_err(|_| anyhow!("no file at {}", tilde(&p.to_string_lossy())))?;
    if !meta.is_file() {
        return Err(anyhow!("{} isn't a file", tilde(&p.to_string_lossy())));
    }
    if meta.len() > 10_000_000 {
        return Err(anyhow!("{} is over 10 MB; use copy", tilde(&p.to_string_lossy())));
    }
    let bytes = std::fs::read(p)?;
    if bytes.iter().take(8192).any(|b| *b == 0) {
        return Err(anyhow!("{} is a binary file; use copy", tilde(&p.to_string_lossy())));
    }
    String::from_utf8(bytes).map_err(|_| anyhow!("{} isn't UTF-8 text; use copy", tilde(&p.to_string_lossy())))
}

/// Visits files under `root` (not following symlinks; skipping hidden files, build output, ~/Library from home, sensitive
/// paths and the owner's path nevers) until `f` returns false, 50,000 files, or 10 seconds.
fn walk(root: &Path, never_paths: &[String], f: &mut dyn FnMut(&Path) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let library = home_dir().join("Library");
    let mut stack = vec![root.to_path_buf()];
    let mut seen = 0;
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        let mut entries: Vec<std::fs::DirEntry> = rd.flatten().collect();
        entries.sort_by_key(|e| std::cmp::Reverse(e.file_name()));
        let mut files = Vec::new();
        for e in entries {
            let p = e.path();
            let name = e.file_name().to_string_lossy().into_owned();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_symlink() || name.starts_with('.') || trust::is_sensitive(&p) || never_paths.iter().any(|n| p.starts_with(n)) {
                continue;
            }
            if ft.is_dir() {
                if !SKIP_DIRS.contains(&name.as_str()) && (p != library || root.starts_with(&library)) {
                    stack.push(p);
                }
            } else if ft.is_file() {
                files.push(p);
            }
        }
        for p in files.iter().rev() {
            seen += 1;
            if seen > 50_000 || Instant::now() > deadline || !f(p) {
                return;
            }
        }
    }
}

/// `*` `?` `**` and `{a,b}` globs as an anchored regex.
fn glob_regex(pat: &str) -> Result<Regex> {
    let c: Vec<char> = pat.chars().collect();
    let (mut re, mut i, mut depth) = (String::from("^"), 0, 0);
    while i < c.len() {
        match c[i] {
            '*' if c.get(i + 1) == Some(&'*') => {
                if c.get(i + 2) == Some(&'/') {
                    re.push_str("(?:.*/)?");
                    i += 1;
                } else {
                    re.push_str(".*");
                }
                i += 1;
            }
            '*' => re.push_str("[^/]*"),
            '?' => re.push_str("[^/]"),
            '{' => {
                depth += 1;
                re.push_str("(?:");
            }
            '}' if depth > 0 => {
                depth -= 1;
                re.push(')');
            }
            ',' if depth > 0 => re.push('|'),
            ch => re.push_str(&regex::escape(&ch.to_string())),
        }
        i += 1;
    }
    re.push('$');
    Regex::new(&re).map_err(|e| anyhow!("bad pattern: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        let g = glob_regex("*.md").unwrap();
        assert!(g.is_match("plan.md") && !g.is_match("plan.mdx") && !g.is_match("a/plan.md"));
        let g = glob_regex("notes/**/*.{md,txt}").unwrap();
        assert!(g.is_match("notes/a.md") && g.is_match("notes/x/y/b.txt") && !g.is_match("other/a.md"));
    }

    #[test]
    fn walks_skip_private_and_hidden() {
        let root = std::env::temp_dir().join(format!("agentbus-walk-{}", short_id()));
        for p in ["a/notes.md", "a/.hidden.md", "node_modules/x.md", "b/secret/plan.md", "c.md"] {
            let f = root.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, "pricing").unwrap();
        }
        let root = root.canonicalize().unwrap();
        let never = vec![root.join("b/secret").to_string_lossy().into_owned()];
        let mut seen = Vec::new();
        walk(&root, &never, &mut |p| {
            seen.push(p.strip_prefix(&root).unwrap().to_string_lossy().into_owned());
            true
        });
        seen.sort();
        assert_eq!(seen, ["a/notes.md", "c.md"]);
        let _ = std::fs::remove_dir_all(&root);
    }
}
