//! What agents launch. `mcp`: a stdio MCP server that forwards to the daemon's /mcp, tagging each call with
//! this session's identity; for Claude it also pushes incoming messages into the session. `hook`: the
//! Claude/Codex hook handler (both harnesses share event names and output schema).

use crate::util::*;
use anyhow::Result;
use serde_json::{json, Value};
use std::io::{BufRead, Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub fn mcp(harness: &str) -> Result<()> {
    let harness = Some(slug(harness)).filter(|h| !h.is_empty()).unwrap_or_else(|| "agent".into());
    let cwd = project_dir(&std::env::current_dir()?);
    let session = std::env::var("CLAUDE_CODE_SESSION_ID").unwrap_or_else(|_| format!("pid{}", std::os::unix::process::parent_id()));
    let key = format!("{harness}:{session}");
    // Codex tags every call with its thread id (and its hooks report the real cwd); one shim can serve many threads.
    let mut headers = vec![("x-agentbus-harness", harness.clone())];
    if harness != "codex" {
        headers.push(("x-agentbus-key", key.clone()));
        headers.push(("x-agentbus-cwd", urlencoding::encode(&cwd).into_owned()));
    }
    let headers = Arc::new(headers);
    let session_id: Arc<Mutex<Option<String>>> = Arc::default();
    let stdout = Arc::new(Mutex::new(std::io::stdout()));

    if harness == "claude" {
        if let Some(sock) = claude_socket() {
            let (key, cwd) = (key.clone(), cwd.clone());
            std::thread::spawn(move || claude_push(&key, &cwd, &sock));
        }
    }

    let url = format!("{}/mcp", local_url());
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let (url, headers, session_id, stdout) = (url.clone(), headers.clone(), session_id.clone(), stdout.clone());
        std::thread::spawn(move || {
            let id = serde_json::from_str::<Value>(&line).ok().and_then(|m| m.get("id").cloned()).filter(|v| !v.is_null());
            let mut req = agent().post(&url).timeout(Duration::from_secs(700)).set("content-type", "application/json");
            for (k, v) in headers.iter() {
                req = req.set(k, v);
            }
            if let Some(s) = session_id.lock().unwrap().as_deref() {
                req = req.set("mcp-session-id", s);
            }
            let out = match req.send_string(&line) {
                Ok(res) => {
                    if let Some(s) = res.header("mcp-session-id") {
                        session_id.lock().unwrap().get_or_insert_with(|| s.to_string());
                    }
                    if res.status() == 202 { None } else { res.into_string().ok() }
                }
                Err(e) => id.map(|id| {
                    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000,
                            "message": format!("agentbus daemon not reachable at {}: {e}", local_url()) } }).to_string()
                }),
            };
            if let Some(out) = out {
                let mut o = stdout.lock().unwrap();
                let _ = writeln!(o, "{}", out.trim());
                let _ = o.flush();
            }
        });
    }
    std::process::exit(0);
}

struct ClaudeSocket {
    path: String,
    token: Option<String>,
}

fn claude_socket() -> Option<ClaudeSocket> {
    let token = std::env::var("CLAUDE_CODE_MESSAGING_TOKEN").ok();
    if let Ok(path) = std::env::var("CLAUDE_CODE_MESSAGING_SOCKET") {
        return Some(ClaudeSocket { path, token });
    }
    let pids = [std::env::var("CLAUDE_PID").ok(), Some(std::os::unix::process::parent_id().to_string())];
    pids.into_iter().flatten().find_map(|pid| {
        let s: Value = serde_json::from_str(&std::fs::read_to_string(home().join(format!(".claude/sessions/{pid}.json"))).ok()?).ok()?;
        s["messagingSocketPath"].as_str().map(|p| ClaudeSocket { path: p.to_string(), token: token.clone() })
    })
}

/// Posts into our own Claude session's inbox socket. Claude trusts a post from its own child process as peer input,
/// reads it between tool calls, and starts a turn if the session is idle.
fn post_to_claude(sock: &ClaudeSocket, text: &str) -> Result<()> {
    let mut c = std::os::unix::net::UnixStream::connect(&sock.path)?;
    c.set_read_timeout(Some(Duration::from_secs(5)))?;
    if let Some(t) = &sock.token {
        writeln!(c, "{}", json!({ "type": "auth", "token": t }))?;
    }
    writeln!(c, "{}", json!({ "type": "user", "message": { "role": "user", "content": text } }))?;
    c.shutdown(std::net::Shutdown::Write)?;
    let _ = c.read_to_end(&mut Vec::new()); // Claude closes once it has the lines
    Ok(())
}

fn claude_push(key: &str, cwd: &str, sock: &ClaudeSocket) {
    std::thread::sleep(Duration::from_secs(5)); // health checks (`claude mcp list`) exit before this; don't claim a name for them
    let base = local_url();
    let q = query(&[("key", key.into()), ("harness", "claude".into()), ("cwd", cwd.into()), ("peek", "1".into()), ("wake_only", "1".into()), ("wait", "55".into())]);
    loop {
        let res = get_json(&format!("{base}/api/inbox?{q}"), Duration::from_secs(70)).and_then(|r| {
            let msgs = r["messages"].as_array().cloned().unwrap_or_default();
            if !msgs.is_empty() {
                post_to_claude(sock, r["delivery"].as_str().unwrap_or(""))?;
                let ids: Vec<i64> = msgs.iter().filter_map(|m| m["rowid"].as_i64()).collect();
                post_json(&format!("{base}/api/ack"), &json!({ "key": key, "ids": ids }), Duration::from_secs(5))?;
            }
            Ok(())
        });
        if res.is_err() {
            std::thread::sleep(Duration::from_secs(5));
        }
    }
}

pub fn hook(harness: &str) -> Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let Ok(ev) = serde_json::from_str::<Value>(&input) else { return Ok(()) };
    if harness == "h2h" {
        return h2h_hook(&ev);
    }
    let harness = slug(harness);
    let q = query(&[
        ("key", format!("{harness}:{}", ev["session_id"].as_str().unwrap_or(""))),
        ("harness", harness.clone()),
        ("cwd", ev["cwd"].as_str().unwrap_or("").into()),
    ]);
    let event = ev["hook_event_name"].as_str().unwrap_or("");
    let base = format!("{}/api", local_url());
    let t = Duration::from_secs(3);
    // Never break the agent: if the daemon is down, say nothing.
    let out = if event == "SessionStart" {
        get_json(&format!("{base}/hello?{q}"), t).ok().map(|r| {
            json!({ "hookSpecificOutput": { "hookEventName": event, "additionalContext": format!(
                "agentbus: your address is {}. Other agents can message you; use the agentbus tools to reach them.",
                r["address"].as_str().unwrap_or("?")) } })
        })
    } else {
        get_json(&format!("{base}/inbox?{q}"), t).ok().filter(|r| r["messages"].as_array().is_some_and(|m| !m.is_empty())).map(|r| {
            let text = r["delivery"].as_str().unwrap_or("");
            if event == "Stop" {
                json!({ "decision": "block", "reason": text })
            } else {
                json!({ "hookSpecificOutput": { "hookEventName": event, "additionalContext": text } })
            }
        })
    };
    if let Some(o) = out {
        println!("{o}");
    }
    Ok(())
}

/// PreToolUse hook of an h2h responder: every tool call waits for the daemon's decision (which may be a person clicking
/// a dialog). Fails closed.
fn h2h_hook(ev: &Value) -> Result<()> {
    let rid = std::env::var("AGENTBUS_H2H_REQ").unwrap_or_default();
    let body = json!({ "rid": rid, "tool": ev["tool_name"], "input": ev["tool_input"] });
    let (allow, reason) = match post_json(&format!("{}/api/h2h-authorize", local_url()), &body, Duration::from_secs(20 * 60)) {
        Ok(r) => (r["allow"] == true, r["reason"].as_str().unwrap_or("").to_string()),
        Err(e) => (false, format!("agentbus couldn't check permissions: {e}")),
    };
    println!("{}", json!({ "hookSpecificOutput": { "hookEventName": "PreToolUse",
        "permissionDecision": if allow { "allow" } else { "deny" }, "permissionDecisionReason": reason } }));
    Ok(())
}
