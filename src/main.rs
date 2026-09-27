//! agentbus: peer-to-peer messaging between AI coding agents (Claude Code, Codex, OpenCode, pi) on one machine
//! and across your Tailscale tailnet. Every device runs its own daemon; there is no central hub.

mod daemon;
mod install;
mod shim;
mod util;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::time::Duration;
use util::*;

#[derive(Parser)]
#[command(name = "agentbus", version, about = "Peer-to-peer messaging for coding agents over Tailscale",
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
    },
    /// stdio MCP server launched by agents (internal)
    Mcp { harness: String },
    /// Claude/Codex hook handler (internal)
    Hook { harness: String },
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
            Cmd::Install { no_service } => install::install(no_service),
            Cmd::Mcp { harness } => shim::mcp(&harness),
            Cmd::Hook { harness } => shim::hook(&harness),
            Cmd::Status => {
                let h = get_json(&format!("{base}/health"), Duration::from_secs(3)).map_err(|e| anyhow!("daemon not running at {base} ({e})"))?;
                println!("agentbus {} on {}: ok ({base})", h["version"].as_str().unwrap_or("?"), h["device"].as_str().unwrap_or("?"));
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
