//! Human-to-human (h2h): your agents calling tools on *other people's* machines, over iroh (QUIC dialed by public key,
//! NAT traversal, n0 relays as fallback), so neither side needs Tailscale.
//!
//! - **Pairing** is mutual: each person adds the other's contact code (their device's public key). Until both have,
//!   neither side's daemon lets the other in; connections from keys the owner hasn't added are closed right after the
//!   handshake, before anything is read. Codes aren't secrets, so there's nothing to leak.
//! - **Remote tools** (`remote.rs`): a contact's agent opens a session with an intent and calls read/grep/glob/ls/copy/
//!   write here directly. Every call goes through the trust engine (`trust.rs`): hard nevers, Jev before the call,
//!   Jev on its actual output, and the owner when nobody is sure.
//! - Every decision, automatic or manual, is logged with the owner's reason (`agentbus h2h log`).

use crate::daemon::{Agent, Daemon};
use crate::trust;
use crate::util::*;
use anyhow::{anyhow, Result};
use data_encoding::BASE64URL_NOPAD;
use iroh::{
    endpoint::{presets, AfterHandshakeOutcome, Connection, EndpointHooks, Side},
    protocol::{AcceptError, ProtocolHandler, Router},
    Endpoint, EndpointId, SecretKey,
};
use rusqlite::{params, Connection as Db, OptionalExtension};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::oneshot;

pub const ALPN: &[u8] = b"agentbus/h2h/1";
const CODE_PREFIX: &str = "ab2";
const NOT_ADDED: &[u8] = b"not a contact";
pub(crate) const MANUAL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const MAX_FILE_BYTES: u64 = 2 << 30; // 2 GiB, each way
const FILE_TTL_MS: i64 = 7 * 86_400_000;
/// Buttons of the dialog for a read: index 0 denies, 1 allows, 2 allows and always allows the folder.
pub(crate) const MANUAL_BUTTONS: [&str; 3] = ["Deny", "Allow", "Always allow folder"];

static H2H: OnceLock<Arc<H2h>> = OnceLock::new();

pub fn get() -> Option<&'static Arc<H2h>> {
    H2H.get()
}

pub struct H2h {
    pub(crate) d: Arc<Daemon>,
    router: Router,
    pending: Mutex<HashMap<String, Pending>>,
    flushing: AtomicBool,
    /// When each session last got a "Jev decided" banner.
    pub(crate) banners: Mutex<HashMap<String, i64>>,
}

struct Pending {
    info: Value,
    tx: Option<oneshot::Sender<Reply>>,
    dialog: Option<u32>,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum Choice {
    Deny,
    Allow,
    Always,
}

/// The owner's answer: a button, and whatever they typed (their reason, or a grounding answer).
pub(crate) struct Reply {
    pub choice: Choice,
    pub text: String,
}

#[derive(Clone)]
pub struct Contact {
    pub id: String,
    pub name: String,
    pub level: String,
    /// "waiting": we added them, they haven't added us yet; "connected": both have.
    pub state: String,
    pub last_seen: Option<i64>,
    /// Their person in the entity map.
    pub person: Option<i64>,
}

fn contact_row(r: &rusqlite::Row) -> rusqlite::Result<Contact> {
    Ok(Contact {
        id: r.get("id")?,
        name: r.get("name")?,
        level: r.get("level")?,
        state: r.get("state")?,
        last_seen: r.get("last_seen")?,
        person: r.get("person")?,
    })
}

// --- config -----------------------------------------------------------------------------------

fn config_path() -> PathBuf {
    data_dir().join("h2h.json")
}

pub fn config() -> Value {
    std::fs::read_to_string(config_path()).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(json!({}))
}

fn cfg(k: &str) -> Option<String> {
    config()[k].as_str().map(String::from).filter(|s| !s.is_empty())
}

pub const CONFIG_KEYS: [(&str, &str); 4] = [
    ("name", "your name, as contacts see it"),
    ("jev-threshold", "Jev decides on its own when it's at least this sure (default 0.85)"),
    ("typesafe-key", "TypeSafe API key for Jev (without it, everything not decided by your standing choices asks you)"),
    ("inbox", "where files from contacts are saved, one folder per person (default: ~/agentbus-inbox)"),
];

pub fn set_config(key: &str, value: &str) -> Result<()> {
    let k = key.replace('-', "_");
    if !CONFIG_KEYS.iter().any(|(c, _)| c.replace('-', "_") == k) {
        return Err(anyhow!("unknown setting \"{key}\"; one of: {}", CONFIG_KEYS.iter().map(|c| c.0).collect::<Vec<_>>().join(", ")));
    }
    let mut c = config();
    if value.is_empty() {
        c.as_object_mut().map(|o| o.remove(&k));
    } else if k == "jev_threshold" {
        let t: f64 = value.parse().map_err(|_| anyhow!("jev-threshold is a number between 0 and 1"))?;
        c[&k] = json!(t.clamp(0.0, 1.0));
    } else if k == "inbox" {
        let p = expand_home(value);
        std::fs::create_dir_all(&p)?;
        c[&k] = json!(p.canonicalize()?.to_string_lossy());
    } else {
        c[&k] = json!(value);
    }
    write_config(&c)
}

fn write_config(c: &Value) -> Result<()> {
    let path = config_path();
    std::fs::write(&path, serde_json::to_string_pretty(c)? + "\n")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn owner_name() -> String {
    cfg("name").unwrap_or_else(|| {
        let u = std::env::var("USER").ok().filter(|u| !u.is_empty()).unwrap_or_else(|| base_name(&home().to_string_lossy()));
        slug(&u)
    })
}

/// A folder that may be "always allowed": it exists, and isn't home, `/` or private.
fn check_folder(folder: &str) -> Result<PathBuf> {
    let p = expand_home(folder);
    let p = p.canonicalize().map_err(|_| anyhow!("{} is not a folder", p.display()))?;
    if !p.is_dir() {
        return Err(anyhow!("{} is not a folder", p.display()));
    }
    if trust::is_sensitive(&p) || p == trust::home_dir() || p == Path::new("/") {
        return Err(anyhow!("refusing to always allow {}: pick a specific folder", tilde(&p.to_string_lossy())));
    }
    Ok(p)
}

pub(crate) fn typesafe_key() -> Option<String> {
    cfg("typesafe_key").or_else(|| std::env::var("TYPESAFE_API_KEY").ok().filter(|k| !k.is_empty()))
}

fn load_key() -> Result<SecretKey> {
    let path = data_dir().join("iroh.key");
    if let Ok(b) = std::fs::read(&path) {
        if let Ok(bytes) = <[u8; 32]>::try_from(b.as_slice()) {
            return Ok(SecretKey::from_bytes(&bytes));
        }
    }
    let key = SecretKey::generate();
    std::fs::create_dir_all(data_dir())?;
    std::fs::write(&path, key.to_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(key)
}

// --- startup ----------------------------------------------------------------------------------

pub async fn start(d: Arc<Daemon>) -> Result<()> {
    {
        let db = d.db.lock().unwrap();
        db.execute_batch(
            "create table if not exists h2h_contacts (id text primary key, name text unique, level text not null default 'normal',
               created_at integer, last_seen integer);
             create table if not exists h2h_requests (rid text primary key, contact text, from_addr text, reply_mid text, body text,
               status text, answer text, created_at integer, finished_at integer);
             create table if not exists h2h_log (id integer primary key, rid text, contact text, kind text, tool text, resource text,
               decision text, by text, score real, created_at integer);
             create table if not exists h2h_grants (contact text, prefix text, created_at integer, primary key (contact, prefix));
             create table if not exists h2h_rules (id integer primary key, contact text, text text, created_at integer);
             create table if not exists h2h_files (token text primary key, contact text, path text, name text, size integer,
               created_at integer, fetches integer default 0);
             create table if not exists h2h_sessions (sid text primary key, contact text, intent text, from_addr text,
               calls integer not null default 0, created_at integer, last_at integer);
             create table if not exists h2h_out_sessions (agent_key text, contact text, sid text, intent text, at integer,
               primary key (agent_key, contact));",
        )?;
        // 0.4.0 paired both ways in one step, so its contacts are already mutual.
        let _ = db.execute("alter table h2h_contacts add column state text not null default 'connected'", []);
        let _ = db.execute("alter table h2h_contacts add column workspace text", []); // 0.5's shared folders, migrated to grants
        let _ = db.execute("alter table messages add column files text", []);
        trust::init(&db)?;
        // 0.5's default shared folder becomes a folder always allowed for everyone.
        let mut c = config();
        if let Some(ws) = c["workspace"].as_str().map(String::from) {
            trust::grant(&db, None, Path::new(&ws))?;
            c.as_object_mut().map(|o| o.remove("workspace"));
            let _ = write_config(&c);
        }
    }
    let ep = Endpoint::builder(presets::N0)
        .secret_key(load_key()?)
        .hooks(Gate { d: d.clone() })
        .bind()
        .await
        .map_err(|e| anyhow!("iroh: {e}"))?;
    let router = Router::builder(ep).accept(ALPN, Handler).spawn();
    let h = Arc::new(H2h { d, router, pending: Mutex::default(), flushing: AtomicBool::new(false), banners: Mutex::default() });
    let _ = H2H.set(h.clone());
    println!("h2h: {} as {} (iroh)", h.id(), owner_name());
    let me = h.clone();
    tokio::spawn(async move {
        me.router.endpoint().online().await;
        me.flush().await;
    });
    Ok(())
}

/// Closes incoming connections from keys the owner hasn't added (or has blocked) right after the TLS handshake,
/// before a byte of their request is read. The handshake itself proves who the key belongs to.
struct Gate {
    d: Arc<Daemon>,
}

impl std::fmt::Debug for Gate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Gate")
    }
}

impl EndpointHooks for Gate {
    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        if conn.side() != Side::Server {
            return AfterHandshakeOutcome::accept(); // our own outgoing calls
        }
        let id = conn.remote_id().to_string();
        let known: bool = self
            .d
            .db
            .lock()
            .unwrap()
            .query_row("select count(*) from h2h_contacts where id = ? and level != 'blocked'", [&id], |r| r.get::<_, i64>(0))
            .unwrap_or(0)
            > 0;
        if known {
            AfterHandshakeOutcome::accept()
        } else {
            AfterHandshakeOutcome::Reject { error_code: 403u32.into(), reason: NOT_ADDED.to_vec() }
        }
    }
}

// --- wire protocol: one bi-stream per call, a JSON request and a JSON response ------------------

#[derive(Debug, Clone)]
struct Handler;

impl ProtocolHandler for Handler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let from = conn.remote_id();
        let (mut send, mut recv) = conn.accept_bi().await?;
        let raw = recv.read_to_end(1 << 20).await.map_err(AcceptError::from_err)?;
        let req: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
        if req["t"] == "fetch" {
            // A file: one JSON header line, then the raw bytes.
            let file = match get() {
                Some(h) => h.open_offer(&from.to_string(), req["token"].as_str().unwrap_or("")).await,
                None => Err(anyhow!("not ready")),
            };
            match file {
                Ok((mut f, name, size)) => {
                    let head = json!({ "ok": true, "name": name, "size": size }).to_string() + "\n";
                    send.write_all(head.as_bytes()).await.map_err(AcceptError::from_err)?;
                    tokio::io::copy(&mut f, &mut send).await.map_err(AcceptError::from_err)?;
                }
                Err(e) => {
                    let head = json!({ "error": e.to_string() }).to_string() + "\n";
                    send.write_all(head.as_bytes()).await.map_err(AcceptError::from_err)?;
                }
            }
            send.finish()?;
            conn.closed().await;
            return Ok(());
        }
        let res = match get() {
            Some(h) => h.handle(from, &raw).await.unwrap_or_else(|e| json!({ "error": e.to_string() })),
            None => json!({ "error": "not ready" }),
        };
        send.write_all(&serde_json::to_vec(&res).unwrap_or_default()).await.map_err(AcceptError::from_err)?;
        send.finish()?;
        conn.closed().await;
        Ok(())
    }
}

impl H2h {
    pub fn id(&self) -> String {
        self.router.endpoint().id().to_string()
    }

    pub(crate) fn db(&self) -> std::sync::MutexGuard<'_, Db> {
        self.d.db.lock().unwrap()
    }

    async fn call(&self, id: &str, req: &Value) -> Result<Value> {
        self.call_t(id, req, Duration::from_secs(30)).await
    }

    pub(crate) async fn call_t(&self, id: &str, req: &Value, timeout: Duration) -> Result<Value> {
        let id: EndpointId = id.parse().map_err(|_| anyhow!("bad contact id"))?;
        let ep = self.router.endpoint();
        let conn = tokio::time::timeout(Duration::from_secs(20), ep.connect(id, ALPN))
            .await
            .map_err(|_| anyhow!("unreachable (timed out)"))?
            .map_err(|e| not_added_or(e, "unreachable"))?;
        // A rejection from their Gate arrives as the connection's close reason, not in the stream error.
        let why = |e: &dyn std::fmt::Display| format!("{e}; {:?}", conn.close_reason());
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| not_added_or(why(&e), "unreachable"))?;
        send.write_all(&serde_json::to_vec(req)?).await.map_err(|e| not_added_or(why(&e), "unreachable"))?;
        send.finish()?;
        let raw = tokio::time::timeout(timeout, recv.read_to_end(1 << 20))
            .await
            .map_err(|_| anyhow!("no reply"))?
            .map_err(|e| not_added_or(why(&e), "no reply"))?;
        conn.close(0u32.into(), b"done");
        let v: Value = serde_json::from_slice(&raw)?;
        match v["error"].as_str() {
            Some(e) => Err(anyhow!("{e}")),
            None => Ok(v),
        }
    }

    /// Only contacts the owner added get this far (see `Gate`).
    async fn handle(self: &Arc<Self>, from: EndpointId, raw: &[u8]) -> Result<Value> {
        let req: Value = serde_json::from_slice(raw)?;
        let c = self.contact_by_id(&from.to_string()).ok_or_else(|| anyhow!("not a contact"))?;
        if c.level == "blocked" {
            return Err(anyhow!("not a contact"));
        }
        // They reached us, so they've added us too: the pairing is mutual.
        self.connected(&c);
        match req["t"].as_str() {
            Some("hello") => Ok(json!({ "ok": true, "name": owner_name() })),
            Some("open") => self.accept_open(&c, &req),
            Some("tool") => self.accept_tool(&c, &req).await,
            Some("ask") => self.legacy_ask(&c, &req),
            Some("answer") => self.accept_answer(&c, &req),
            Some("file") => self.accept_push(&c, &req),
            _ => Err(anyhow!("unknown request")),
        }
    }

    fn connected(&self, c: &Contact) {
        let _ = self.db().execute("update h2h_contacts set last_seen = ?, state = 'connected' where id = ?", params![now_ms(), c.id]);
        if c.state == "waiting" {
            println!("h2h: connected with {}", c.name);
            notify_banner(
                "agentbus",
                &format!("Connected with {}. Their agents can now call tools here: your rules and Jev decide, and you're asked when nobody's sure.", c.name),
            );
        }
    }

    // --- contacts: both people add each other's code ----------------------------------------------

    pub fn contacts(&self) -> Vec<Contact> {
        let db = self.db();
        let mut st = db.prepare("select * from h2h_contacts order by name").unwrap();
        st.query_map([], contact_row).unwrap().filter_map(|r| r.ok()).collect()
    }

    fn contact_by_id(&self, id: &str) -> Option<Contact> {
        self.db().query_row("select * from h2h_contacts where id = ?", [id], contact_row).optional().ok().flatten()
    }

    pub fn contact_by_name(&self, name: &str) -> Result<Contact> {
        let n = slug(name);
        // Bind first: the guard from self.db() must be gone before the error path calls contacts() (std Mutex isn't reentrant).
        let found = self.db().query_row("select * from h2h_contacts where name = ?", [&n], contact_row).optional()?;
        found.ok_or_else(|| {
            let known: Vec<String> = self.contacts().into_iter().map(|c| c.name).collect();
            if known.is_empty() {
                anyhow!("no person \"{name}\": you haven't added anyone yet (agentbus h2h add <their code>)")
            } else {
                anyhow!("no person \"{name}\"; your contacts: {}", known.join(", "))
            }
        })
    }

    /// Stores a contact as "waiting" (until they've added us too), keeping names unique, and links it to a person in
    /// the map (`person`: an existing one, for someone's second device).
    fn add_contact(&self, id: &str, name: &str, person: Option<&str>) -> Result<Contact> {
        if let Some(c) = self.contact_by_id(id) {
            return Ok(c);
        }
        let db = self.db();
        let base = Some(slug(name)).filter(|n| !n.is_empty()).unwrap_or_else(|| "friend".into());
        let mut name = base.clone();
        for i in 2.. {
            let taken: bool = db.query_row("select count(*) from h2h_contacts where name = ?", [&name], |r| r.get::<_, i64>(0)).unwrap_or(0) > 0;
            if !taken {
                break;
            }
            name = format!("{base}-{i}");
        }
        let person = match person {
            Some(p) => trust::find(&db, p)?.id,
            None => trust::ensure_person(&db, &name)?,
        };
        db.execute(
            "insert into h2h_contacts (id, name, level, state, created_at, person) values (?, ?, 'normal', 'waiting', ?, ?)",
            params![id, name, now_ms(), person],
        )?;
        Ok(Contact { id: id.into(), name, level: "normal".into(), state: "waiting".into(), last_seen: None, person: Some(person) })
    }

    /// This device's contact code: its public key and the owner's name. Not a secret: knowing it lets nobody in
    /// until the owner adds *their* code too.
    pub fn code(&self) -> String {
        let t = json!({ "id": self.id(), "n": owner_name() });
        format!("{CODE_PREFIX}{}", BASE64URL_NOPAD.encode(t.to_string().as_bytes()))
    }

    pub async fn add(&self, code: &str, name: Option<&str>, share: Option<&str>, person: Option<&str>) -> Result<String> {
        let share = share.map(check_folder).transpose()?;
        let code = code.trim();
        if code.starts_with("ab1") {
            return Err(anyhow!("that's an old one-way invite; ask them for their contact code (agentbus h2h code)"));
        }
        let raw = code.strip_prefix(CODE_PREFIX).ok_or_else(|| anyhow!("not an agentbus contact code (should start with {CODE_PREFIX})"))?;
        let t: Value = serde_json::from_slice(&BASE64URL_NOPAD.decode(raw.as_bytes()).map_err(|_| anyhow!("code is damaged; copy it again"))?)?;
        let id = t["id"].as_str().unwrap_or("");
        if id.parse::<EndpointId>().is_err() {
            return Err(anyhow!("code is damaged; copy it again"));
        }
        if id == self.id() {
            return Err(anyhow!("that's your own code; add theirs"));
        }
        let c = self.add_contact(id, name.or(t["n"].as_str()).unwrap_or("friend"), person)?;
        if let Some(folder) = &share {
            let db = self.db();
            let e = c.person.and_then(|p| trust::entity(&db, p));
            trust::grant(&db, e.as_ref(), folder)?;
        }
        if c.state == "connected" {
            return Ok(format!("{} is already a contact.", c.name));
        }
        Ok(match self.hello(&c).await {
            Ok(()) => format!(
                "Connected with {n}: you've both added each other. Your agents can call {n}'s tools (open_session, then remote_call), and \
                 theirs can call yours: your rules and Jev decide, and you're asked when nobody's sure.",
                n = c.name
            ),
            Err(_) => format!(
                "Added {n}. Nothing can pass either way until {n} adds you too; send them your code:\n\n  {code}\n\n\
                 (they run: agentbus h2h add {code})\nYou'll get a notification when you're connected.",
                n = c.name,
                code = self.code()
            ),
        })
    }

    /// Checks whether a waiting contact has added us yet; marks them connected if so.
    pub(crate) async fn hello(&self, c: &Contact) -> Result<()> {
        self.call(&c.id, &json!({ "t": "hello", "name": owner_name() })).await?;
        self.connected(c);
        Ok(())
    }

    pub fn set_level(&self, name: &str, level: &str) -> Result<String> {
        let c = self.contact_by_name(name)?;
        let db = self.db();
        match level {
            "remove" => {
                db.execute("delete from h2h_contacts where id = ?", [&c.id])?;
                Ok(format!("Removed {} (what you said about them stays in your map: agentbus h2h person {}).", c.name, c.name))
            }
            "normal" | "trusted" | "blocked" => {
                db.execute("update h2h_contacts set level = ? where id = ?", params![level, c.id])?;
                Ok(match level {
                    "trusted" => format!("{} is trusted: their reads skip the check before the call; your nevers still hold back output. Changes still ask.", c.name),
                    "blocked" => format!("{} is blocked: their requests are refused.", c.name),
                    _ => format!("{} is back to normal: your rules and Jev decide, and you're asked when nobody's sure.", c.name),
                })
            }
            _ => Err(anyhow!("level is one of normal, trusted, blocked, remove")),
        }
    }

    pub(crate) fn mark(&self, mid: &str, status: &str) {
        let _ = self.db().execute("update messages set status = ?, attempts = attempts + 1 where mid = ? and dir = 'out'", params![status, mid]);
    }

    /// A result for one of our agents' calls (or an answer to a 0.5 `ask`).
    fn accept_answer(self: &Arc<Self>, c: &Contact, req: &Value) -> Result<Value> {
        let reply_to = req["reply_to"].as_str().unwrap_or("");
        let key: Option<String> = self
            .db()
            .query_row(
                "select agent_key from messages where mid = ? and dir = 'out' and from_info in ('ask', 'tool') and target_device = ?",
                params![reply_to, format!("h2h:{}", c.id)],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let key = key.ok_or_else(|| anyhow!("no call #{reply_to} to answer"))?;
        let body = req["body"].as_str().unwrap_or("").to_string();
        let from = format!("{} (person, via h2h)", c.name);
        let files: Vec<Value> = req["files"].as_array().cloned().unwrap_or_default();
        if files.is_empty() {
            self.d.deliver_to_key(&key, &from, "h2h result", &body, Some(reply_to))?;
            return Ok(json!({ "ok": true }));
        }
        // Fetch the files first, then hand the agent the result with their local paths.
        let (me, c, reply_to) = (self.clone(), c.clone(), reply_to.to_string());
        tokio::spawn(async move {
            let note = me.download_all(&c, &files).await;
            let _ = me.d.deliver_to_key(&key, &from, "h2h result", &format!("{body}\n\n{note}"), Some(&reply_to));
        });
        Ok(json!({ "ok": true }))
    }

    /// Sends a later result (one that waited for the owner) back to the asking agent, queued if they're offline.
    pub(crate) async fn send_answer(&self, c: &Contact, reply_mid: &str, body: &str, files: Value) {
        let mid = short_id();
        let _ = self.db().execute(
            "insert into messages (mid, dir, from_addr, from_info, to_addr, body, reply_to, wake, created_at, status, target_device, files)
             values (?, 'out', ?, 'answer', ?, ?, ?, 1, ?, 'queued', ?, ?)",
            params![mid, owner_name(), c.name, body, reply_mid, now_ms(), format!("h2h:{}", c.id), files.to_string()],
        );
        let req = json!({ "t": "answer", "mid": mid, "reply_to": reply_mid, "body": body, "files": files });
        match self.call(&c.id, &req).await {
            Ok(_) => self.mark(&mid, "delivered"),
            Err(e) if is_refusal(&e) => self.mark(&mid, "failed"),
            Err(_) => {}
        }
    }

    /// 0.5 agents ask questions for an agent here to answer; that's gone. Tell them what to do instead.
    fn legacy_ask(self: &Arc<Self>, c: &Contact, req: &Value) -> Result<Value> {
        let (me, c, mid) = (self.clone(), c.clone(), req["mid"].as_str().unwrap_or("").to_string());
        let text = format!(
            "{}'s agentbus no longer answers questions with an agent: your agents call tools on their machine directly, under their \
             permissions. Run `agentbus upgrade`, restart your agent, then use open_session and remote_call.",
            owner_name()
        );
        tokio::spawn(async move { me.send_answer(&c, &mid, &text, json!([])).await });
        Ok(json!({ "ok": true }))
    }

    // --- files -----------------------------------------------------------------------------------

    /// Makes `path` fetchable by `c` (only by them, for 7 days) and returns the offer to send them.
    pub(crate) fn offer(&self, c: &Contact, path: &Path) -> Result<Value> {
        let meta = std::fs::metadata(path)?;
        if !meta.is_file() {
            return Err(anyhow!("{} isn't a file", tilde(&path.to_string_lossy())));
        }
        if meta.len() > MAX_FILE_BYTES {
            return Err(anyhow!("{} is over the 2 GiB limit", tilde(&path.to_string_lossy())));
        }
        let token = format!("{:016x}{:016x}", rand::random::<u64>(), rand::random::<u64>());
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
        self.db().execute(
            "insert into h2h_files (token, contact, path, name, size, created_at) values (?, ?, ?, ?, ?, ?)",
            params![token, c.id, path.to_string_lossy(), name, meta.len() as i64, now_ms()],
        )?;
        Ok(json!({ "token": token, "name": name, "size": meta.len() }))
    }

    async fn open_offer(&self, from: &str, token: &str) -> Result<(tokio::fs::File, String, u64)> {
        let row: Option<(String, String)> = self
            .db()
            .query_row(
                "select path, name from h2h_files where token = ? and contact = ? and created_at > ?",
                params![token, from, now_ms() - FILE_TTL_MS],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (path, name) = row.ok_or_else(|| anyhow!("no such file offer (or it expired)"))?;
        let f = tokio::fs::File::open(&path).await.map_err(|_| anyhow!("{name} is no longer there"))?;
        let size = f.metadata().await?.len();
        let _ = self.db().execute("update h2h_files set fetches = fetches + 1 where token = ?", [token]);
        Ok((f, name, size))
    }

    fn inbox_dir(&self, c: &Contact) -> PathBuf {
        cfg("inbox").map(PathBuf::from).unwrap_or_else(|| home().join("agentbus-inbox")).join(&c.name)
    }

    /// Downloads one offered file into this person's inbox folder (never overwriting) and returns its path.
    async fn download(&self, c: &Contact, offer: &Value) -> Result<PathBuf> {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt};
        let size = offer["size"].as_u64().unwrap_or(0);
        if size > MAX_FILE_BYTES {
            return Err(anyhow!("over the 2 GiB limit"));
        }
        let id: EndpointId = c.id.parse().map_err(|_| anyhow!("bad contact id"))?;
        let conn = tokio::time::timeout(Duration::from_secs(20), self.router.endpoint().connect(id, ALPN))
            .await
            .map_err(|_| anyhow!("unreachable (timed out)"))?
            .map_err(|e| not_added_or(e, "unreachable"))?;
        let (mut send, recv) = conn.open_bi().await?;
        send.write_all(json!({ "t": "fetch", "token": offer["token"] }).to_string().as_bytes()).await?;
        send.finish()?;
        let mut reader = tokio::io::BufReader::new(recv);
        let mut head = Vec::new();
        reader.read_until(b'\n', &mut head).await?;
        let head: Value = serde_json::from_slice(&head).map_err(|_| anyhow!("bad reply"))?;
        if let Some(e) = head["error"].as_str() {
            return Err(anyhow!("{e}"));
        }
        let size = head["size"].as_u64().unwrap_or(0);
        if size > MAX_FILE_BYTES {
            return Err(anyhow!("over the 2 GiB limit"));
        }
        // Their name, but only the last component and no hidden files: it can't point anywhere else.
        let name = base_name(head["name"].as_str().unwrap_or("file")).trim_start_matches('.').to_string();
        let name = if name.is_empty() { "file".to_string() } else { name };
        let dir = self.inbox_dir(c);
        tokio::fs::create_dir_all(&dir).await?;
        let (stem, ext) = match name.rsplit_once('.') {
            Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
            _ => (name.clone(), String::new()),
        };
        let mut path = dir.join(&name);
        for i in 2.. {
            if !path.exists() {
                break;
            }
            path = dir.join(format!("{stem}-{i}{ext}"));
        }
        let part = path.with_extension("agentbus-part");
        let mut out = tokio::fs::File::create(&part).await?;
        let got = tokio::io::copy(&mut reader.take(size + 1), &mut out).await?;
        conn.close(0u32.into(), b"done");
        if got != size {
            let _ = tokio::fs::remove_file(&part).await;
            return Err(anyhow!("transfer cut short ({got} of {size} bytes)"));
        }
        tokio::fs::rename(&part, &path).await?;
        Ok(path)
    }

    /// Downloads every offer and describes the result for the agent or the owner.
    pub(crate) async fn download_all(&self, c: &Contact, files: &[Value]) -> String {
        let mut lines = vec![format!("Files from {}, saved here:", c.name)];
        for f in files {
            let name = f["name"].as_str().unwrap_or("file");
            let t = std::time::Instant::now();
            match self.download(c, f).await {
                Ok(p) => {
                    let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                    let secs = t.elapsed().as_secs_f64().max(0.001);
                    println!("h2h: received {} from {} ({}, {:.1} MB/s)", tilde(&p.to_string_lossy()), c.name, human(size), size as f64 / secs / 1e6);
                    lines.push(format!("- {} ({})", p.display(), human(size)));
                }
                Err(e) => lines.push(format!("- {name}: couldn't download ({e})")),
            }
        }
        lines.join("\n")
    }

    /// A contact sent us files unasked: save them to the inbox and tell the owner.
    fn accept_push(self: &Arc<Self>, c: &Contact, req: &Value) -> Result<Value> {
        let files: Vec<Value> = req["files"].as_array().cloned().unwrap_or_default();
        let note = req["note"].as_str().unwrap_or("").to_string();
        let (me, c) = (self.clone(), c.clone());
        tokio::spawn(async move {
            let saved = me.download_all(&c, &files).await;
            notify_banner(&format!("agentbus: {} sent you files", c.name), &format!("{note}\n{saved}"));
        });
        Ok(json!({ "ok": true }))
    }

    /// One of the owner's agents sends a contact a file. Always confirmed by the owner: it's their data leaving.
    pub async fn send_file(&self, a: &Agent, to: &str, path: &str, note: &str) -> Result<String> {
        let c = self.contact_by_name(to)?;
        let base = a.cwd.as_deref().map(PathBuf::from).unwrap_or_else(home);
        let path = resolve(&base, path);
        if trust::is_sensitive(&path) {
            return Err(anyhow!("{} is private and is never sent", tilde(&path.to_string_lossy())));
        }
        let size = std::fs::metadata(&path).map_err(|_| anyhow!("no file at {}", path.display()))?.len();
        let what = format!("{} ({})", tilde(&path.to_string_lossy()), human(size));
        let body = format!("Send {} this file?\n{what}\n\n{} wants to send it. {}", c.name, self.d.addr(a), note.chars().take(300).collect::<String>());
        let r = self.manual(&c, "push", "push", "send_file", &what, &body, &["Deny", "Send"]).await;
        let decision = if r.choice == Choice::Deny { "deny" } else { "allow" };
        trust::record(
            &self.db(),
            &trust::Rec {
                rid: "push", contact: &c.id, person: c.person.unwrap_or(0), kind: "push", tool: "send_file", resource: &path.to_string_lossy(),
                decision, by: "manual", score: None, phase: "", why: note, intent: "", reason: &r.text, excerpt: "",
            },
        );
        if r.choice == Choice::Deny {
            return Err(anyhow!("{} declined sending {what}", owner_name()));
        }
        let offer = self.offer(&c, &path)?;
        self.call(&c.id, &json!({ "t": "file", "files": [offer], "note": note, "from": self.d.addr(a) })).await?;
        Ok(format!("Sent {what} to {}. It's saved in their agentbus inbox.", c.name))
    }

    pub fn files_text(&self) -> String {
        let root = cfg("inbox").map(PathBuf::from).unwrap_or_else(|| home().join("agentbus-inbox"));
        let mut lines = vec![format!("Received (in {}):", tilde(&root.to_string_lossy()))];
        for c in self.contacts() {
            if let Ok(rd) = std::fs::read_dir(self.inbox_dir(&c)) {
                for e in rd.flatten() {
                    let size = e.metadata().map(|m| m.len()).unwrap_or(0);
                    lines.push(format!("  {}/{} ({})", c.name, e.file_name().to_string_lossy(), human(size)));
                }
            }
        }
        let db = self.db();
        let mut st = db
            .prepare("select coalesce(c.name, f.contact), f.path, f.size, f.fetches, f.created_at from h2h_files f
                      left join h2h_contacts c on c.id = f.contact order by f.created_at desc limit 20")
            .unwrap();
        let sent: Vec<String> = st
            .query_map([], |r| {
                Ok(format!("  {} <- {} ({}, fetched {}x, {})", r.get::<_, String>(0)?, tilde(&r.get::<_, String>(1)?),
                           human(r.get::<_, i64>(2)? as u64), r.get::<_, i64>(3)?, ago(r.get(4)?)))
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        lines.push("Offered to contacts:".into());
        lines.extend(sent);
        lines.join("\n")
    }

    /// Retries queued answers (and 0.5 asks) for contacts who were offline.
    pub async fn flush(&self) {
        if self.flushing.swap(true, Ordering::SeqCst) {
            return;
        }
        for c in self.contacts().into_iter().filter(|c| c.state == "waiting" && c.level != "blocked") {
            let _ = self.hello(&c).await;
        }
        let rows: Vec<(String, String, String, String, Option<String>, String, Option<String>)> = {
            let db = self.db();
            let mut st = db
                .prepare("select mid, target_device, from_info, from_addr, reply_to, body, files from messages
                          where dir = 'out' and status = 'queued' and target_device like 'h2h:%' order by rowid")
                .unwrap();
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))).unwrap().filter_map(|r| r.ok()).collect()
        };
        for (mid, target, kind, from, reply_to, body, files) in rows {
            let id = target.trim_start_matches("h2h:");
            let files: Value = files.and_then(|f| serde_json::from_str(&f).ok()).unwrap_or(json!([]));
            let req = if kind == "answer" {
                json!({ "t": "answer", "mid": mid, "reply_to": reply_to, "body": body, "files": files })
            } else {
                json!({ "t": "ask", "mid": mid, "from": from, "body": body })
            };
            match self.call(id, &req).await {
                Ok(_) => self.mark(&mid, "delivered"),
                Err(e) if is_refusal(&e) => self.mark(&mid, "failed"),
                Err(_) => {}
            }
        }
        self.flushing.store(false, Ordering::SeqCst);
    }

    // --- asking the owner --------------------------------------------------------------------------

    /// Asks the owner: a native dialog on macOS with a text field for their reason (a notification elsewhere), or
    /// `agentbus h2h approve|deny|answer` from any shell. `buttons[0]` denies (or skips), `[1]` allows, `[2]` always allows.
    pub(crate) async fn manual(&self, c: &Contact, rid: &str, kind: &str, tool: &str, what: &str, body: &str, buttons: &[&str]) -> Reply {
        let pid = short_id();
        let (tx, rx) = oneshot::channel();
        let verb = match kind {
            "read" if tool == "copy" => "get a copy of",
            "push" => "receive",
            "read" => "see",
            "write" => "change",
            "ground" => "tell you about",
            _ => "use",
        };
        let info = json!({ "id": pid, "rid": rid, "person": c.name, "kind": kind, "verb": verb, "tool": tool, "what": what,
                           "request": body.chars().take(600).collect::<String>(), "buttons": buttons, "created_at": now_ms() });
        self.pending.lock().unwrap().insert(pid.clone(), Pending { info, tx: Some(tx), dialog: None });
        if kind == "ground" {
            println!("h2h: question for you about {} (agentbus h2h answer {pid} \"…\")", c.name);
        } else {
            println!("h2h: waiting for you: {}: {what} (agentbus h2h approve {pid})", c.name);
        }
        let title = if kind == "ground" { format!("agentbus: who is {}?", c.name) } else { format!("agentbus: {}'s agent", c.name) };
        let buttons: Vec<String> = buttons.iter().map(|b| b.to_string()).collect();
        if let Some(h) = get() {
            let (h, pid2, body) = (h.clone(), pid.clone(), body.to_string());
            tokio::spawn(async move { h.dialog(&pid2, &title, &body, &buttons).await });
        }
        let reply = tokio::time::timeout(MANUAL_TIMEOUT, rx).await.ok().and_then(|r| r.ok()).unwrap_or(Reply { choice: Choice::Deny, text: String::new() });
        if let Some(p) = self.pending.lock().unwrap().remove(&pid) {
            if let Some(child) = p.dialog {
                let _ = std::process::Command::new("kill").arg(child.to_string()).status();
            }
        }
        reply
    }

    async fn dialog(&self, pid: &str, title: &str, text: &str, buttons: &[String]) {
        if std::env::var("AGENTBUS_NO_DIALOG").is_ok() {
            return; // tests and headless setups: decide with `agentbus h2h approve|deny|answer`
        }
        if !cfg!(target_os = "macos") {
            let _ = tokio::process::Command::new("notify-send").args([title, &format!("{text}\n\nagentbus h2h approve {pid}  |  agentbus h2h deny {pid}")]).status().await;
            return;
        }
        let q = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
        let script = format!(
            "display dialog {} default answer \"\" with title {} buttons {{{}}} default button {} giving up after {} with icon caution",
            q(text),
            q(title),
            buttons.iter().map(|b| q(b)).collect::<Vec<_>>().join(", "),
            q(&buttons[1]),
            MANUAL_TIMEOUT.as_secs()
        );
        let Ok(child) = tokio::process::Command::new("osascript").args(["-e", &script]).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).spawn() else {
            return;
        };
        if let Some(p) = self.pending.lock().unwrap().get_mut(pid) {
            p.dialog = child.id();
        }
        let Ok(out) = child.wait_with_output().await else { return };
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        // "button returned:Allow, text returned:she's my co-founder, gave up:false"
        if s.ends_with("gave up:true") {
            return;
        }
        let after = |key: &str| s.split_once(key).map(|(_, rest)| rest);
        let button = after("button returned:").map(|r| r.split(", text returned:").next().unwrap_or(r)).unwrap_or("");
        let typed = after(", text returned:").map(|r| r.rsplit_once(", gave up:").map(|(t, _)| t).unwrap_or(r)).unwrap_or("");
        let choice = match buttons.iter().position(|b| b == button) {
            Some(0) => Choice::Deny,
            Some(1) => Choice::Allow,
            Some(_) => Choice::Always,
            None => return, // dismissed or killed: leave it to the CLI or the timeout
        };
        self.resolve(pid, choice, typed.trim());
    }

    fn resolve(&self, pid: &str, choice: Choice, text: &str) -> bool {
        let mut pending = self.pending.lock().unwrap();
        match pending.get_mut(pid).and_then(|p| p.tx.take()) {
            Some(tx) => tx.send(Reply { choice, text: text.to_string() }).is_ok(),
            None => false,
        }
    }

    // --- local API (CLI) ---------------------------------------------------------------------------

    pub async fn api(self: &Arc<Self>, route: &str, p: &serde_json::Map<String, Value>) -> Result<Value> {
        let s = |k: &str| p.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let opt = |k: &str| p.get(k).and_then(|v| v.as_str()).map(String::from);
        // An entity named in a statement or grant; "" or "everyone" means everyone.
        let target = |db: &Db, name: &str| -> Result<Option<trust::Entity>> {
            if name.is_empty() || name.eq_ignore_ascii_case("everyone") { Ok(None) } else { trust::find(db, name).map(Some) }
        };
        let text = |t: String| Ok(json!({ "text": t }));
        match route {
            "h2h-code" => {
                let code = self.code();
                let text = if s("short") == "1" {
                    format!("Your contact code (send it back so they can add you):\n\n  {code}")
                } else {
                    format!(
                        "Your contact code, as {}. It's safe to share: it only identifies you, and nobody can reach your agents \
                         until you add their code too.\n\n  {code}\n\n\
                         Someone without agentbus installs it and adds you in one step (macOS, Linux or WSL; no Tailscale needed):\n\n  \
                         curl -fsSL https://luqmaan.dev/agentbus/install.sh | sh -s -- --add {code} --name <their name>\n\n\
                         If they already have it: agentbus h2h add {code}\n\
                         Then they send you their code and you run: agentbus h2h add <their code>",
                        owner_name()
                    )
                };
                Ok(json!({ "code": code, "text": text }))
            }
            "h2h-add" => text(
                self.add(&s("code"), opt("name").filter(|n| !n.is_empty()).as_deref(), opt("share").filter(|f| !f.is_empty()).as_deref(),
                         opt("person").filter(|f| !f.is_empty()).as_deref())
                    .await?,
            ),
            "h2h-contacts" => text(self.contacts_text()),
            "h2h-level" => text(self.set_level(&s("name"), &s("level"))?),
            "h2h-person" | "h2h-entity" => {
                let db = self.db();
                let name = s("name");
                let (kind, relation, note) = (opt("kind").filter(|k| !k.is_empty()), opt("relation"), opt("note"));
                let e = if route == "h2h-person" && kind.is_none() && relation.is_none() && note.is_none() {
                    trust::find(&db, &name)?
                } else {
                    let kind = kind.or_else(|| (route == "h2h-person").then(|| "person".to_string()));
                    trust::upsert(&db, &name, kind.as_deref(), relation.as_deref(), note.as_deref())?
                };
                text(trust::profile_text(&db, &e))
            }
            "h2h-link" => {
                let db = self.db();
                let (child, parent) = (trust::find(&db, &s("child"))?, trust::find(&db, &s("parent"))?);
                if s("remove") == "1" {
                    let gone = trust::unlink(&db, &child, &parent)?;
                    text(if gone { format!("{} is no longer in {}.", child.name, parent.name) } else { format!("{} wasn't in {}.", child.name, parent.name) })
                } else {
                    let rel = opt("rel").filter(|r| !r.is_empty()).unwrap_or_else(|| "member_of".into());
                    trust::link(&db, &child, &parent, &rel)?;
                    text(format!(
                        "{} is now in {} ({rel}). Statements about {} now apply to {} too.\n\n{}",
                        child.name, parent.name, parent.name, child.name, trust::profile_text(&db, &child)
                    ))
                }
            }
            "h2h-map" => text(trust::map_text(&self.db())),
            "h2h-statement" => {
                let db = self.db();
                let e = target(&db, &s("for"))?;
                let st = trust::add_statement(&db, e.as_ref(), &s("kind"), &s("text"), "owner")?;
                let who = e.as_ref().map(|e| format!("{} and everyone in it", e.name)).unwrap_or_else(|| "everyone".into());
                let anyone = e.as_ref().map(|e| format!("{} or anyone in it", e.name)).unwrap_or_else(|| "anyone".into());
                let how = match (st.kind.as_str(), &st.path) {
                    ("never", Some(p)) => format!("Enforced by code: nothing under {} is shared with {anyone}; Jev sees it too.", tilde(p)),
                    ("never", None) => format!("Jev withholds anything matching it from {anyone}, before a call runs and on its output."),
                    ("allow", _) => format!("Jev lets {who} have this without asking you, unless a never says otherwise."),
                    _ => format!("Jev applies it to {who}."),
                };
                let warn = if typesafe_key().is_none() && st.path.is_none() {
                    "\nNote: no TypeSafe key is set, so Jev can't apply it yet (agentbus h2h config typesafe-key …)."
                } else {
                    ""
                };
                text(format!("#{} {} for {who}: {}\n{how}{warn}", st.id, st.kind, st.text))
            }
            "h2h-rules" => text(trust::statements_text(&self.db())),
            "h2h-unrule" => {
                trust::remove_statement(&self.db(), s("id").trim_start_matches('#').parse().map_err(|_| anyhow!("give the statement's number"))?)?;
                text(format!("Removed #{}.", s("id").trim_start_matches('#')))
            }
            "h2h-grant" => {
                let folder = check_folder(&s("folder"))?;
                let db = self.db();
                let e = target(&db, &s("name"))?;
                trust::grant(&db, e.as_ref(), &folder)?;
                let who = e.as_ref().map(|e| e.name.clone()).unwrap_or_else(|| "everyone".into());
                text(format!(
                    "{} is always allowed for {who}: reads there skip the check before the call. Your nevers still hold back output.",
                    tilde(&folder.to_string_lossy())
                ))
            }
            "h2h-ungrant" => {
                let db = self.db();
                let e = target(&db, &s("name"))?;
                let folder = opt("folder").filter(|f| !f.is_empty()).map(|f| {
                    let p = expand_home(&f);
                    p.canonicalize().unwrap_or(p)
                });
                let n = trust::ungrant(&db, e.as_ref(), folder.as_deref())?;
                text(format!("Removed {n} always-allowed folder(s). Reads there now go through your rules, Jev and you."))
            }
            "h2h-pending" => {
                let items: Vec<Value> = self.pending.lock().unwrap().values().map(|p| p.info.clone()).collect();
                let text = if items.is_empty() {
                    "Nothing waiting for you.".into()
                } else {
                    items
                        .iter()
                        .map(|i| {
                            let g = |k: &str| i[k].as_str().unwrap_or("").to_string();
                            if g("kind") == "ground" {
                                format!("{}  question about {}: {}\n    answer: agentbus h2h answer {} \"…\"", g("id"), g("person"), g("what"), g("id"))
                            } else {
                                format!("{}  {}: {}\n    {}", g("id"), g("person"), g("what"), g("request").replace('\n', "\n    "))
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n\n")
                };
                Ok(json!({ "pending": items, "text": text }))
            }
            "h2h-resolve" => {
                let choice = match s("choice").as_str() {
                    "allow" => Choice::Allow,
                    "always" => Choice::Always,
                    _ => Choice::Deny,
                };
                if self.resolve(&s("id"), choice, &s("text")) {
                    text(format!("{:?}: done.", choice))
                } else {
                    Err(anyhow!("nothing pending with id {}", s("id")))
                }
            }
            "h2h-log" => text(self.log_text(s("limit").parse().unwrap_or(30))),
            "h2h-eval" => text(self.eval(s("limit").parse().unwrap_or(30)).await?),
            "h2h-files" => text(self.files_text()),
            "h2h-config" => {
                if !s("key").is_empty() {
                    set_config(&s("key"), &s("value"))?;
                }
                let c = config();
                let lines: Vec<String> = CONFIG_KEYS
                    .iter()
                    .map(|(k, help)| {
                        let v = match (*k, c[k.replace('-', "_")].clone()) {
                            ("typesafe-key", Value::String(_)) => "(set)".to_string(),
                            ("typesafe-key", _) if typesafe_key().is_some() => "(from TYPESAFE_API_KEY)".to_string(),
                            (_, Value::String(v)) => tilde(&v),
                            (_, Value::Number(n)) => n.to_string(),
                            ("name", _) => format!("{} (default)", owner_name()),
                            _ => "-".into(),
                        };
                        format!("  {k:<14} {v:<32} {help}")
                    })
                    .collect();
                text(format!("h2h id {}\n{}", self.id(), lines.join("\n")))
            }
            _ => Err(anyhow!("unknown h2h endpoint")),
        }
    }

    pub fn contacts_text(&self) -> String {
        let cs = self.contacts();
        if cs.is_empty() {
            return "No contacts yet. Share your code (agentbus h2h code) and add theirs (agentbus h2h add <code>).".into();
        }
        let db = self.db();
        cs.iter()
            .map(|c| {
                let seen = match (c.state.as_str(), c.last_seen) {
                    ("waiting", _) => "waiting for them to add you".to_string(),
                    (_, Some(t)) => format!("seen {}", ago(t)),
                    _ => "never seen".into(),
                };
                let chain = c.person.map(|p| trust::chain(&db, p)).unwrap_or_default();
                let mut l = format!("  {}: {}, {seen}", c.name, c.level);
                if let Some(e) = chain.first() {
                    l.push_str(&format!("\n      {}", trust::chain_label(&chain)));
                    if e.relation.is_none() {
                        l.push_str(&format!("\n      who are they to you? agentbus h2h person {} --relation \"…\"", e.name));
                    }
                }
                let n = trust::statements_for(&db, &chain).iter().filter(|(s, _)| s.entity.is_some()).count();
                let g = trust::grants_for(&db, &chain).len();
                if n + g > 0 {
                    l.push_str(&format!("\n      {n} statement(s), {g} always-allowed folder(s): agentbus h2h person {}", chain.first().map(|e| e.name.as_str()).unwrap_or(&c.name)));
                }
                l
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The "People" part of list_agents.
    pub fn people_text(&self) -> Option<String> {
        let cs: Vec<Contact> = self.contacts().into_iter().filter(|c| c.level != "blocked" && c.state == "connected").collect();
        if cs.is_empty() {
            return None;
        }
        let names: Vec<String> = cs.iter().map(|c| format!("  {} (seen {})", c.name, c.last_seen.map(ago).unwrap_or_else(|| "never".into()))).collect();
        Some(format!("people (call tools on their machine: open_session, then remote_call; not send)\n{}", names.join("\n")))
    }

    pub fn log_text(&self, limit: i64) -> String {
        let db = self.db();
        let mut st = db
            .prepare("select l.created_at, coalesce(c.name, l.contact), l.kind, l.tool, l.resource, l.decision, l.by, l.score, l.rid,
                             coalesce(l.phase, ''), l.reason
                      from h2h_log l left join h2h_contacts c on c.id = l.contact order by l.id desc limit ?")
            .unwrap();
        let rows: Vec<String> = st
            .query_map([limit], |r| {
                let score: Option<f64> = r.get(7)?;
                let by: String = r.get(6)?;
                let by = match (by.as_str(), score) {
                    ("jev", Some(s)) => format!("jev {s:.2}"),
                    ("manual", _) => "you".into(),
                    (b, _) => b.to_string(),
                };
                let reason: Option<String> = r.get(10)?;
                Ok(format!(
                    "{:>8}  #{}  {:<10} {:<5} {:<5} {:<5} {:<4} ({by})  {}{}",
                    ago(r.get(0)?),
                    r.get::<_, String>(8)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(9)?,
                    tilde(&r.get::<_, String>(4)?).chars().take(90).collect::<String>(),
                    reason.map(|r| format!("  \"{r}\"")).unwrap_or_default()
                ))
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        if rows.is_empty() { "No h2h activity yet.".into() } else { rows.join("\n") }
    }
}

/// Their daemon closed the connection because it doesn't know our key (they haven't added us, or removed us).
fn not_added_or(e: impl std::fmt::Display, otherwise: &str) -> anyhow::Error {
    let s = e.to_string();
    if s.contains(std::str::from_utf8(NOT_ADDED).unwrap_or("")) || s.contains("error_code: 403") || s.contains("code: 403") {
        anyhow!("they haven't added you as a contact (or removed you)")
    } else {
        anyhow!("{otherwise} ({s})")
    }
}

/// Errors that mean retrying won't help (the other side refused), as opposed to being offline.
fn is_refusal(e: &anyhow::Error) -> bool {
    let s = e.to_string();
    !s.starts_with("unreachable") && !s.starts_with("no reply")
}

/// Absolute, `..`-free path for `p` relative to `base` (symlinks resolved when the path exists).
pub(crate) fn resolve(base: &Path, p: &str) -> PathBuf {
    let p = expand_home(p);
    let joined = if p.is_absolute() { p } else { base.join(p) };
    if let Ok(c) = joined.canonicalize() {
        return c;
    }
    let mut out = PathBuf::new();
    for comp in joined.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            c => out.push(c),
        }
    }
    out
}

pub(crate) fn human(bytes: u64) -> String {
    match bytes {
        b if b < 1 << 10 => format!("{b} B"),
        b if b < 1 << 20 => format!("{:.1} KB", b as f64 / 1024.0),
        b if b < 1 << 30 => format!("{:.1} MB", b as f64 / 1048576.0),
        b => format!("{:.2} GB", b as f64 / 1073741824.0),
    }
}

pub(crate) fn notify_banner(title: &str, text: &str) {
    if std::env::var("AGENTBUS_NO_DIALOG").is_ok() {
        return;
    }
    let q = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
    let _ = if cfg!(target_os = "macos") {
        std::process::Command::new("osascript").args(["-e", &format!("display notification {} with title {}", q(text), q(title))]).spawn()
    } else {
        std::process::Command::new("notify-send").args([title, text]).spawn()
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_is_absolute_and_dotdot_free() {
        let ws = PathBuf::from("/nonexistent/ws");
        assert_eq!(resolve(&ws, "notes/a.md"), PathBuf::from("/nonexistent/ws/notes/a.md"));
        assert_eq!(resolve(&ws, "../../etc/x"), PathBuf::from("/etc/x"));
        assert_eq!(resolve(&ws, "~/.ssh/id"), home().join(".ssh/id"));
    }

    #[test]
    fn secrets_are_spotted() {
        assert_eq!(secret_scan("key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz"), Some("an Anthropic API key"));
        assert!(secret_scan("-----BEGIN OPENSSH PRIVATE KEY-----\nabc").is_some());
        assert!(secret_scan("token ghp_0123456789abcdefghijABCDEFGHIJ").is_some());
        assert_eq!(secret_scan("the relay runs on port 3340 in London; sk- is a prefix"), None);
    }
}
