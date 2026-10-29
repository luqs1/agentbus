//! agentbus: peer-to-peer messaging between AI coding agents (Claude Code, Codex, OpenCode, pi) on one machine
//! and across your Tailscale tailnet, and remote tools on other people's machines over iroh. Every device runs its own
//! daemon; there is no central hub.

mod daemon;
mod h2h;
mod install;
mod own;
mod remote;
mod shim;
mod trust;
mod util;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::time::Duration;
use util::*;

#[derive(Parser)]
#[command(name = "agentbus", version, about = "Peer-to-peer messaging for coding agents across your machines over Tailscale, and remote tools on other people's machines over iroh",
          after_help = "Addresses: <task>.<harness>@<machine>, e.g. payments.codex@m4air. Run from inside an agent's shell, \
                        the CLI speaks as that agent; otherwise as <--as>.cli (default me.cli).")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Agents here and on your other machines
    Agents {
        #[arg(long = "as")]
        as_: Option<String>,
    },
    /// Message agents: TO is an address, a,b,c, or "*"
    Send {
        to: String,
        #[arg(required = true, num_args = 1..)]
        message: Vec<String>,
        #[arg(long = "as")]
        as_: Option<String>,
        #[arg(long)]
        reply_to: Option<String>,
        /// Don't wake the recipient; it reads this at its next pause
        #[arg(long)]
        fyi: bool,
    },
    /// Read new messages (marks them read)
    Inbox {
        #[arg(long = "as")]
        as_: Option<String>,
        #[arg(long, default_value_t = 0)]
        wait: u64,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
    /// Open a session with a person you've paired with: say what you need (then use `agentbus call`)
    Open {
        to: String,
        #[arg(required = true, num_args = 1..)]
        intent: Vec<String>,
        #[arg(long = "as")]
        as_: Option<String>,
    },
    /// Call a tool on a paired person's machine: read, grep, glob, ls, copy, write
    Call {
        to: String,
        tool: String,
        /// The tool's arguments as JSON, e.g. '{"path": "notes/plan.md"}'
        #[arg(default_value = "{}")]
        args: String,
        /// Why you need this (they see it)
        #[arg(long)]
        why: String,
        #[arg(long = "as")]
        as_: Option<String>,
    },
    /// Send a file to a person you've paired with (you confirm it in a dialog)
    SendFile {
        to: String,
        path: String,
        #[arg(long, default_value = "")]
        note: String,
        #[arg(long = "as")]
        as_: Option<String>,
    },
    /// People: pair with other people, map who they are to you, and decide what their agents may do here
    H2h {
        #[command(subcommand)]
        cmd: H2hCmd,
    },
    /// Install the latest agentbus release (same as re-running the installer)
    Upgrade,
    /// Daemons found on the tailnet
    Peers,
    /// Is this device's daemon running?
    Status,
    /// Run this device's daemon
    Daemon,
    /// Install the daemon as a user service and wire up claude/codex/opencode/pi
    Install {
        #[arg(long)]
        no_service: bool,
        /// Add this person's contact code once installed (then send them yours)
        #[arg(long)]
        add: Option<String>,
        /// Your name, as that person will see it
        #[arg(long)]
        name: Option<String>,
    },
    /// stdio MCP server launched by agents (internal)
    Mcp { harness: String },
    /// Claude/Codex hook handler (internal)
    Hook { harness: String },
}

#[derive(Subcommand)]
enum H2hCmd {
    /// Your contact code, to send to someone you want to connect with
    Code,
    /// Add someone's contact code. You're connected once they've added yours too
    Add {
        code: String,
        /// What to call them here (default: the name in their code)
        #[arg(long = "as")]
        as_: Option<String>,
        /// A folder to always allow for them
        #[arg(long)]
        share: Option<String>,
        /// Another device of someone already in your map: link it to that person
        #[arg(long)]
        person: Option<String>,
    },
    /// People you've paired with
    Contacts,
    /// Show what you know about a person, or set who they are to you
    Person {
        name: String,
        /// Who they are to you, e.g. "co-founder at Acme"
        #[arg(long)]
        relation: Option<String>,
        #[arg(long)]
        note: Option<String>,
    },
    /// Add or update a group in your map: team, org, company, project, group or topic
    Entity {
        name: String,
        #[arg(long, default_value = "group")]
        kind: String,
        /// Who they are to you, e.g. "my employer", "client"
        #[arg(long)]
        relation: Option<String>,
        #[arg(long)]
        note: Option<String>,
    },
    /// Put someone (or a group) inside a group: statements about the group then apply to them
    Link {
        child: String,
        parent: String,
        /// member_of, part_of or works_on
        #[arg(long, default_value = "member_of")]
        rel: String,
    },
    /// Take someone (or a group) out of a group
    Unlink { child: String, parent: String },
    /// Everyone and every group in your map
    Map,
    /// Something that must never go to them: plain English ("anything financial") or a path (~/Documents/webex, enforced by code)
    Never {
        #[arg(required = true, num_args = 1..)]
        text: Vec<String>,
        /// A person or group (default: everyone)
        #[arg(long = "for")]
        for_: Option<String>,
    },
    /// Something they may have without asking you, in plain English
    Allow {
        #[arg(required = true, num_args = 1..)]
        text: Vec<String>,
        #[arg(long = "for")]
        for_: Option<String>,
    },
    /// Any other plain-English rule Jev should apply
    Rule {
        #[arg(required = true, num_args = 1..)]
        text: Vec<String>,
        #[arg(long = "for")]
        for_: Option<String>,
    },
    /// The hard nevers and all your statements
    Rules,
    /// Remove a statement by its number
    Unrule { id: String },
    /// Always allow a folder for a person or group ("everyone" for everyone); your nevers still apply
    Grant { name: String, folder: String },
    /// Withdraw always-allowed folders (all of them, or one)
    Ungrant { name: String, folder: Option<String> },
    /// Their reads skip the check before the call (your nevers still apply to output; changes still ask)
    Trust { name: String },
    /// Back to the default: your rules and Jev decide, and you're asked when nobody's sure
    Normal { name: String },
    /// Refuse all requests from a contact
    Block { name: String },
    /// Forget a contact (what you said about them stays in your map)
    Remove { name: String },
    /// Requests and questions waiting for you
    Pending,
    /// Allow a pending request (--always: always allow that folder for them)
    Approve {
        id: String,
        #[arg(long)]
        always: bool,
        /// Why (Jev learns from it)
        #[arg(long)]
        why: Option<String>,
    },
    /// Deny a pending request
    Deny {
        id: String,
        #[arg(long)]
        why: Option<String>,
    },
    /// Answer a question about someone (the first time they reach you)
    Answer {
        id: String,
        #[arg(num_args = 0..)]
        text: Vec<String>,
    },
    /// Every decision on contacts' calls, automatic ones included, with your reasons
    Log {
        #[arg(long, default_value_t = 30)]
        limit: i64,
    },
    /// Replay your recent decisions through Jev and report how often it agrees with you
    Eval {
        #[arg(long, default_value_t = 30)]
        limit: i64,
    },
    /// Files received from contacts, and files offered to them
    Files,
    /// Show settings, or set one: name, jev-threshold, typesafe-key, inbox ("" to clear)
    Config { key: Option<String>, value: Option<String> },
}

/// Posts to the local daemon's h2h API and prints its `text`.
fn h2h_call(route: &str, body: serde_json::Value, timeout: Duration) -> Result<()> {
    let r = post_json(&format!("{}/api/{route}", local_url()), &body, timeout)?;
    println!("{}", r["text"].as_str().unwrap_or(""));
    Ok(())
}

fn h2h(cmd: H2hCmd) -> Result<()> {
    let t = Duration::from_secs(15);
    let folder = |f: &str| std::fs::canonicalize(expand_home(f)).map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| f.to_string());
    match cmd {
        H2hCmd::Code => h2h_call("h2h-code", json!({}), t),
        H2hCmd::Add { code, as_, share, person } => {
            h2h_call("h2h-add", json!({ "code": code, "name": as_, "share": share.map(|f| folder(&f)), "person": person }), Duration::from_secs(60))
        }
        H2hCmd::Contacts => h2h_call("h2h-contacts", json!({}), t),
        H2hCmd::Person { name, relation, note } => h2h_call("h2h-person", json!({ "name": name, "relation": relation, "note": note }), t),
        H2hCmd::Entity { name, kind, relation, note } => h2h_call("h2h-entity", json!({ "name": name, "kind": kind, "relation": relation, "note": note }), t),
        H2hCmd::Link { child, parent, rel } => h2h_call("h2h-link", json!({ "child": child, "parent": parent, "rel": rel }), t),
        H2hCmd::Unlink { child, parent } => h2h_call("h2h-link", json!({ "child": child, "parent": parent, "remove": "1" }), t),
        H2hCmd::Map => h2h_call("h2h-map", json!({}), t),
        H2hCmd::Never { text, for_ } => h2h_call("h2h-statement", json!({ "kind": "never", "text": text.join(" "), "for": for_ }), t),
        H2hCmd::Allow { text, for_ } => h2h_call("h2h-statement", json!({ "kind": "allow", "text": text.join(" "), "for": for_ }), t),
        H2hCmd::Rule { text, for_ } => h2h_call("h2h-statement", json!({ "kind": "rule", "text": text.join(" "), "for": for_ }), t),
        H2hCmd::Rules => h2h_call("h2h-rules", json!({}), t),
        H2hCmd::Unrule { id } => h2h_call("h2h-unrule", json!({ "id": id }), t),
        H2hCmd::Grant { name, folder: f } => h2h_call("h2h-grant", json!({ "name": name, "folder": folder(&f) }), t),
        H2hCmd::Ungrant { name, folder: f } => h2h_call("h2h-ungrant", json!({ "name": name, "folder": f.map(|f| folder(&f)) }), t),
        H2hCmd::Trust { name } => h2h_call("h2h-level", json!({ "name": name, "level": "trusted" }), t),
        H2hCmd::Normal { name } => h2h_call("h2h-level", json!({ "name": name, "level": "normal" }), t),
        H2hCmd::Block { name } => h2h_call("h2h-level", json!({ "name": name, "level": "blocked" }), t),
        H2hCmd::Remove { name } => h2h_call("h2h-level", json!({ "name": name, "level": "remove" }), t),
        H2hCmd::Pending => h2h_call("h2h-pending", json!({}), t),
        H2hCmd::Approve { id, always, why } => {
            h2h_call("h2h-resolve", json!({ "id": id, "choice": if always { "always" } else { "allow" }, "text": why.unwrap_or_default() }), t)
        }
        H2hCmd::Deny { id, why } => h2h_call("h2h-resolve", json!({ "id": id, "choice": "deny", "text": why.unwrap_or_default() }), t),
        H2hCmd::Answer { id, text } => {
            let text = text.join(" ");
            h2h_call("h2h-resolve", json!({ "id": id, "choice": if text.trim().is_empty() { "deny" } else { "allow" }, "text": text }), t)
        }
        H2hCmd::Log { limit } => h2h_call("h2h-log", json!({ "limit": limit.to_string() }), t),
        H2hCmd::Eval { limit } => h2h_call("h2h-eval", json!({ "limit": limit.to_string() }), Duration::from_secs(30 * 60)),
        H2hCmd::Files => h2h_call("h2h-files", json!({}), t),
        H2hCmd::Config { key, value } => {
            if key.is_some() && value.is_none() {
                return Err(anyhow!("give a value (\"\" clears it)"));
            }
            h2h_call("h2h-config", json!({ "key": key.unwrap_or_default(), "value": value.unwrap_or_default() }), t)
        }
    }
}

/// Run from inside an agent's shell, the CLI speaks as that agent (same key as its MCP server and hooks).
fn identity(as_: Option<String>) -> Vec<(&'static str, String)> {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let cwd = || project_dir(&std::env::current_dir().unwrap_or_default());
    if let Some(n) = as_.or_else(|| env("AGENTBUS_NAME")) {
        let n = slug(&n);
        return vec![("key", format!("cli:{n}")), ("harness", "cli".into()), ("cwd", format!("/{n}"))];
    }
    if let Some(s) = env("CLAUDE_CODE_SESSION_ID") {
        return vec![("key", format!("claude:{s}")), ("harness", "claude".into()), ("cwd", cwd())];
    }
    if let Some(t) = env("CODEX_THREAD_ID") {
        return vec![("key", format!("codex:{t}")), ("harness", "codex".into())];
    }
    if let Some(p) = env("OPENCODE_PID") {
        return vec![("key", format!("opencode:pid{p}")), ("harness", "opencode".into()), ("cwd", cwd())];
    }
    vec![("key", "cli:me".into()), ("harness", "cli".into()), ("cwd", "/me".into())]
}

fn main() {
    let cli = Cli::parse();
    let res: Result<()> = (|| {
        let base = local_url();
        let t = Duration::from_secs(15);
        match cli.cmd {
            Cmd::Daemon => tokio::runtime::Runtime::new()?.block_on(daemon::run()),
            Cmd::Install { no_service, add, name } => {
                install::install(no_service)?;
                if let Some(n) = &name {
                    // Before the daemon reads it: it's how the person being added will see you.
                    h2h::set_config("name", &slug(n))?;
                }
                if let Some(code) = add {
                    // The service was just (re)started; give it a moment to come up.
                    let up = (0..40).any(|_| {
                        std::thread::sleep(Duration::from_millis(500));
                        get_json(&format!("{base}/health"), Duration::from_secs(2)).is_ok_and(|h| !h["h2h"].is_null())
                    });
                    if !up {
                        return Err(anyhow!("installed, but the daemon isn't answering yet; then run: agentbus h2h add {code}"));
                    }
                    println!();
                    h2h(H2hCmd::Add { code, as_: None, share: None, person: None })?;
                    println!();
                    h2h_call("h2h-code", json!({ "short": "1" }), t)?;
                }
                Ok(())
            }
            Cmd::H2h { cmd } => h2h(cmd),
            Cmd::Upgrade => {
                println!("agentbus {}: installing the latest release...", env!("CARGO_PKG_VERSION"));
                let st = std::process::Command::new("sh").args(["-c", "curl -fsSL https://luqmaan.dev/agentbus/install.sh | sh"]).status()?;
                if !st.success() {
                    return Err(anyhow!("upgrade failed"));
                }
                let v = std::process::Command::new(home().join(".local/share/agentbus/bin/agentbus")).arg("--version").output()?;
                println!("\nNow {}Restart agent sessions to load any new tools.", String::from_utf8_lossy(&v.stdout));
                Ok(())
            }
            Cmd::SendFile { to, path, note, as_ } => {
                let mut body = serde_json::Map::new();
                for (k, v) in identity(as_) {
                    body.insert(k.into(), json!(v));
                }
                let path = std::fs::canonicalize(&path).map(|p| p.to_string_lossy().into_owned()).unwrap_or(path);
                body.insert("to".into(), json!(to));
                body.insert("path".into(), json!(path));
                body.insert("note".into(), json!(note));
                println!("{}", post_json(&format!("{base}/api/send-file"), &body.into(), Duration::from_secs(20 * 60))?["text"].as_str().unwrap_or(""));
                Ok(())
            }
            Cmd::Open { to, intent, as_ } => {
                let mut body = serde_json::Map::new();
                for (k, v) in identity(as_) {
                    body.insert(k.into(), json!(v));
                }
                body.insert("to".into(), json!(to));
                body.insert("intent".into(), json!(intent.join(" ")));
                println!("{}", post_json(&format!("{base}/api/open"), &body.into(), Duration::from_secs(60))?["text"].as_str().unwrap_or(""));
                Ok(())
            }
            Cmd::Call { to, tool, args, why, as_ } => {
                let mut body = serde_json::Map::new();
                for (k, v) in identity(as_) {
                    body.insert(k.into(), json!(v));
                }
                let args: serde_json::Value = serde_json::from_str(&args).map_err(|_| anyhow!("args must be JSON, e.g. '{{\"path\": \"notes/plan.md\"}}'"))?;
                body.insert("to".into(), json!(to));
                body.insert("tool".into(), json!(tool));
                body.insert("args".into(), args);
                body.insert("why".into(), json!(why));
                println!("{}", post_json(&format!("{base}/api/call"), &body.into(), Duration::from_secs(150))?["text"].as_str().unwrap_or(""));
                Ok(())
            }
            Cmd::Mcp { harness } => shim::mcp(&harness),
            Cmd::Hook { harness } => shim::hook(&harness),
            Cmd::Status => {
                let h = get_json(&format!("{base}/health"), Duration::from_secs(3)).map_err(|e| anyhow!("daemon not running at {base} ({e})"))?;
                println!("agentbus {} on {}: ok ({base})", h["version"].as_str().unwrap_or("?"), h["device"].as_str().unwrap_or("?"));
                if let Some(id) = h["h2h"]["id"].as_str() {
                    println!("h2h: {id} as {}", h["h2h"]["name"].as_str().unwrap_or("?"));
                }
                if let Some(u) = h["update"].as_str() {
                    println!("{u}");
                }
                Ok(())
            }
            Cmd::Peers => {
                println!("{}", serde_json::to_string_pretty(&get_json(&format!("{base}/api/peers"), t)?)?);
                Ok(())
            }
            Cmd::Agents { as_ } => {
                println!("{}", get_json(&format!("{base}/api/agents?{}", query(&identity(as_))), t)?["text"].as_str().unwrap_or(""));
                Ok(())
            }
            Cmd::Send { to, message, as_, reply_to, fyi } => {
                let mut body = serde_json::Map::new();
                for (k, v) in identity(as_) {
                    body.insert(k.into(), json!(v));
                }
                body.insert("to".into(), json!(to));
                body.insert("message".into(), json!(message.join(" ")));
                body.insert("reply_to".into(), json!(reply_to));
                body.insert("wake".into(), json!(!fyi));
                println!("{}", post_json(&format!("{base}/api/send"), &body.into(), t)?["text"].as_str().unwrap_or(""));
                Ok(())
            }
            Cmd::Inbox { as_, wait, all, json: as_json } => {
                let mut q = identity(as_);
                q.push(("wait", wait.to_string()));
                if all {
                    q.push(("all", "1".into()));
                }
                let r = get_json(&format!("{base}/api/inbox?{}", query(&q)), Duration::from_secs(wait + 10))?;
                if as_json {
                    println!("{}", serde_json::to_string_pretty(&r["messages"])?);
                } else {
                    println!("{}\n\n{}", r["address"].as_str().unwrap_or(""), r["text"].as_str().unwrap_or(""));
                }
                Ok(())
            }
        }
    })();
    if let Err(e) = res {
        eprintln!("agentbus: {e}");
        std::process::exit(1);
    }
}
