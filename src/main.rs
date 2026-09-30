//! agentbus: peer-to-peer messaging between AI coding agents (Claude Code, Codex, OpenCode, pi) on one machine
//! and across your Tailscale tailnet. Every device runs its own daemon; there is no central hub.

mod daemon;
mod h2h;
mod install;
mod shim;
mod util;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::time::Duration;
use util::*;

#[derive(Parser)]
#[command(name = "agentbus", version, about = "Peer-to-peer messaging for coding agents: across your machines over Tailscale, and with other people over iroh",
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
    /// Ask a person you've paired with (h2h); the answer arrives in your inbox
    Ask {
        to: String,
        #[arg(required = true, num_args = 1..)]
        question: Vec<String>,
        #[arg(long = "as")]
        as_: Option<String>,
    },
    /// People: pair with other people's agentbus and control what their agents may do here
    H2h {
        #[command(subcommand)]
        cmd: H2hCmd,
    },
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
    },
    /// People you've paired with
    Contacts,
    /// Let a contact read anything inside your workspace without asking (changes still ask)
    Trust { name: String },
    /// Back to the default: reads follow your past decisions and Jev, and ask when unsure
    Normal { name: String },
    /// Refuse all requests from a contact
    Block { name: String },
    /// Forget a contact and the folders you shared with them
    Remove { name: String },
    /// Requests waiting for your decision
    Pending,
    /// Allow a pending request (--always: share that folder with them from now on)
    Approve {
        id: String,
        #[arg(long)]
        always: bool,
    },
    /// Deny a pending request
    Deny { id: String },
    /// Every decision on contacts' requests, automatic ones included
    Log {
        #[arg(long, default_value_t = 30)]
        limit: i64,
    },
    /// Show settings, or set one: name, workspace, responder, model, jev-threshold, typesafe-key ("" to clear)
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
    match cmd {
        H2hCmd::Code => h2h_call("h2h-code", json!({}), t),
        H2hCmd::Add { code, as_ } => h2h_call("h2h-add", json!({ "code": code, "name": as_ }), Duration::from_secs(60)),
        H2hCmd::Contacts => h2h_call("h2h-contacts", json!({}), t),
        H2hCmd::Trust { name } => h2h_call("h2h-level", json!({ "name": name, "level": "trusted" }), t),
        H2hCmd::Normal { name } => h2h_call("h2h-level", json!({ "name": name, "level": "normal" }), t),
        H2hCmd::Block { name } => h2h_call("h2h-level", json!({ "name": name, "level": "blocked" }), t),
        H2hCmd::Remove { name } => h2h_call("h2h-level", json!({ "name": name, "level": "remove" }), t),
        H2hCmd::Pending => h2h_call("h2h-pending", json!({}), t),
        H2hCmd::Approve { id, always } => h2h_call("h2h-resolve", json!({ "id": id, "choice": if always { "always" } else { "allow" } }), t),
        H2hCmd::Deny { id } => h2h_call("h2h-resolve", json!({ "id": id, "choice": "deny" }), t),
        H2hCmd::Log { limit } => h2h_call("h2h-log", json!({ "limit": limit.to_string() }), t),
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
                    h2h(H2hCmd::Add { code, as_: None })?;
                    println!();
                    h2h_call("h2h-code", json!({ "short": "1" }), t)?;
                }
                Ok(())
            }
            Cmd::H2h { cmd } => h2h(cmd),
            Cmd::Ask { to, question, as_ } => {
                let mut body = serde_json::Map::new();
                for (k, v) in identity(as_) {
                    body.insert(k.into(), json!(v));
                }
                body.insert("to".into(), json!(to));
                body.insert("question".into(), json!(question.join(" ")));
                println!("{}", post_json(&format!("{base}/api/ask"), &body.into(), Duration::from_secs(60))?["text"].as_str().unwrap_or(""));
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
