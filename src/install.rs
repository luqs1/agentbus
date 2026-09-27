//! `agentbus install`: run the daemon as a user service and wire up the agents installed on this device.

use crate::util::*;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const PI_EXTENSION: &str = include_str!("pi-extension.ts");

fn has(cmd: &str) -> bool {
    Command::new("sh").args(["-c", &format!("command -v {cmd}")]).stdout(Stdio::null()).status().map(|s| s.success()).unwrap_or(false)
}

fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let st = Command::new(cmd).args(args).stdout(Stdio::null()).stderr(Stdio::null()).status()?;
    if st.success() { Ok(()) } else { Err(anyhow!("{cmd} {} failed", args.join(" "))) }
}

fn backup(f: &Path) {
    let b = PathBuf::from(format!("{}.bak-agentbus", f.display()));
    if f.exists() && !b.exists() {
        let _ = std::fs::copy(f, b);
    }
}

fn say(what: &str, msg: impl std::fmt::Display) {
    println!("  {what:<9} {msg}");
}

/// Replaces (or appends) the `[header]` table in a TOML file, keeping its line endings.
fn toml_block(file: &Path, header: &str, body: &str) -> Result<()> {
    let raw = std::fs::read_to_string(file).unwrap_or_default();
    let crlf = raw.contains("\r\n");
    let text = raw.replace("\r\n", "\n");
    let head = format!("[{header}]");
    let block = format!("{head}\n{body}\n");
    let mut out = Vec::new();
    let mut skipping = false;
    let mut replaced = false;
    for line in text.lines() {
        if line.trim() == head {
            skipping = true;
            replaced = true;
            out.push(block.trim_end().to_string());
            out.push(String::new());
            continue;
        }
        if skipping && line.trim_start().starts_with('[') {
            skipping = false;
        }
        if !skipping {
            out.push(line.to_string());
        }
    }
    let mut text = out.join("\n");
    if !replaced {
        text = format!("{}\n\n{block}", text.trim_end());
    }
    let text = format!("{}\n", text.trim_end());
    backup(file);
    std::fs::write(file, if crlf { text.replace('\n', "\r\n") } else { text })?;
    Ok(())
}

fn merge_hooks(file: &Path, command: &str) -> Result<()> {
    let mut cfg: Value = std::fs::read_to_string(file).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(json!({}));
    if !cfg["hooks"].is_object() {
        cfg["hooks"] = json!({});
    }
    for event in ["SessionStart", "UserPromptSubmit", "PostToolUse", "Stop"] {
        let mut list: Vec<Value> = cfg["hooks"][event].as_array().cloned().unwrap_or_default();
        list.retain(|g| !g.to_string().contains("agentbus"));
        let mut group = json!({ "hooks": [{ "type": "command", "command": command, "timeout": 10 }] });
        if event == "PostToolUse" {
            group["matcher"] = json!("*");
        }
        list.push(group);
        cfg["hooks"][event] = Value::Array(list);
    }
    backup(file);
    std::fs::create_dir_all(file.parent().unwrap())?;
    std::fs::write(file, serde_json::to_string_pretty(&cfg)? + "\n")?;
    Ok(())
}

/// JSONC -> JSON: drops comments and trailing commas outside strings.
fn strip_jsonc(s: &str) -> String {
    let c: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let (mut i, mut in_str) = (0, false);
    while i < c.len() {
        let ch = c[i];
        if in_str {
            out.push(ch);
            if ch == '\\' && i + 1 < c.len() {
                out.push(c[i + 1]);
                i += 1;
            } else if ch == '"' {
                in_str = false;
            }
        } else if ch == '"' {
            in_str = true;
            out.push(ch);
        } else if ch == '/' && c.get(i + 1) == Some(&'/') {
            while i < c.len() && c[i] != '\n' { i += 1; }
            continue;
        } else if ch == '/' && c.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < c.len() && !(c[i] == '*' && c[i + 1] == '/') { i += 1; }
            i += 2;
            continue;
        } else if ch == ',' {
            let next = c[i + 1..].iter().find(|x| !x.is_whitespace());
            if !matches!(next, Some('}') | Some(']')) {
                out.push(ch);
            }
        } else {
            out.push(ch);
        }
        i += 1;
    }
    out
}

fn install_service(exe: &str) -> Result<String> {
    let data = home().join(".local/share/agentbus");
    std::fs::create_dir_all(&data)?;
    if cfg!(target_os = "macos") {
        let plist = home().join("Library/LaunchAgents/dev.agentbus.plist");
        std::fs::create_dir_all(plist.parent().unwrap())?;
        let log = data.join("daemon.log");
        std::fs::write(&plist, format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>dev.agentbus</string>
  <key>ProgramArguments</key><array><string>{exe}</string><string>daemon</string></array>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin</string></dict>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>{log}</string><key>StandardOutPath</key><string>{log}</string>
</dict></plist>
"#, log = log.display()))?;
        let p = plist.to_string_lossy().to_string();
        let _ = run("launchctl", &["unload", &p]);
        run("launchctl", &["load", "-w", &p])?;
        return Ok(format!("launchd agent {p}"));
    }
    let unit = home().join(".config/systemd/user/agentbus.service");
    std::fs::create_dir_all(unit.parent().unwrap())?;
    std::fs::write(&unit, format!("[Unit]
Description=agentbus daemon (peer-to-peer messaging for coding agents)
After=network-online.target

[Service]
ExecStart={exe} daemon
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
"))?;
    run("systemctl", &["--user", "daemon-reload"])?;
    run("systemctl", &["--user", "enable", "agentbus"])?;
    run("systemctl", &["--user", "restart", "agentbus"])?;
    let user = std::env::var("USER").unwrap_or_default();
    let linger = if run("loginctl", &["enable-linger", &user]).is_ok() { "" } else { " (run `sudo loginctl enable-linger $USER` so it survives logout)" };
    Ok(format!("systemd user service {}{linger}", unit.display()))
}

/// Windows doesn't start WSL at login. A hidden Startup-folder script boots it (starting the daemon via systemd)
/// and holds one process open so WSL keeps running.
fn windows_startup(distro: &str) -> Result<String> {
    let out = Command::new("cmd.exe").args(["/c", "echo %APPDATA%"]).current_dir("/mnt/c").output()?;
    let appdata = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let p = Command::new("wslpath").args(["-u", &appdata]).output()?;
    let dir = PathBuf::from(String::from_utf8_lossy(&p.stdout).trim()).join("Microsoft/Windows/Start Menu/Programs/Startup");
    if !dir.exists() {
        return Err(anyhow!("no Startup folder at {}", dir.display()));
    }
    let file = dir.join("agentbus-wsl.vbs");
    std::fs::write(&file, format!(
        "' agentbus: start WSL ({distro}) hidden at login so the agentbus daemon is running, and keep it running.\r\n\
         CreateObject(\"WScript.Shell\").Run \"wsl.exe -d {distro} --exec sleep infinity\", 0, False\r\n"))?;
    Ok(format!("WSL starts at Windows login ({})", file.display()))
}

pub fn install(no_service: bool) -> Result<()> {
    let exe = std::env::current_exe()?.canonicalize()?.to_string_lossy().into_owned();
    println!("agentbus {} install ({exe})", env!("CARGO_PKG_VERSION"));
    if !no_service {
        say("daemon", install_service(&exe)?);
    }

    if has("claude") {
        let _ = run("claude", &["mcp", "remove", "-s", "user", "agentbus"]);
        run("claude", &["mcp", "add", "-s", "user", "agentbus", "--", &exe, "mcp", "claude"])?;
        say("claude", "MCP server added (user scope); messages are pushed into sessions via their inbox socket");
    } else {
        say("claude", "not installed");
    }

    let codex_home = std::env::var("CODEX_HOME").map(PathBuf::from).unwrap_or_else(|_| home().join(".codex"));
    let tool_opts = "tool_timeout_sec = 660\ndefault_tools_approval_mode = \"approve\"";
    if has("codex") || codex_home.join("config.toml").exists() {
        toml_block(&codex_home.join("config.toml"), "mcp_servers.agentbus",
                   &format!("command = {}\nargs = [\"mcp\", \"codex\"]\n{tool_opts}", json!(exe)))?;
        merge_hooks(&codex_home.join("hooks.json"), &format!("{exe} hook codex"))?;
        say("codex", format!("MCP server + hooks in {} (approve the hooks in Codex when asked)", codex_home.display()));
    }

    if is_wsl() {
        let distro = std::env::var("WSL_DISTRO_NAME").unwrap_or_else(|_| "Ubuntu".into());
        // Windows apps reach WSL through wsl.exe: WSL's Hyper-V firewall blocks Windows -> WSL TCP by default.
        for entry in std::fs::read_dir("/mnt/c/Users").into_iter().flatten().flatten() {
            let dir = entry.path().join(".codex");
            if !dir.join("config.toml").exists() {
                continue;
            }
            toml_block(&dir.join("config.toml"), "mcp_servers.agentbus",
                       &format!("command = \"wsl.exe\"\nargs = {}\n{tool_opts}", json!(["-d", distro, "-e", exe, "mcp", "codex"])))?;
            merge_hooks(&dir.join("hooks.json"), &format!("wsl.exe -d {distro} -e {exe} hook codex"))?;
            say("codex", format!("Windows app: MCP server + hooks in {} (approve the hooks in Codex when asked)", dir.display()));
        }
        match windows_startup(&distro) {
            Ok(m) => say("windows", m),
            Err(e) => say("windows", format!("couldn't add WSL login startup: {e}")),
        }
    }

    let oc_dir = home().join(".config/opencode");
    if has("opencode") || oc_dir.exists() {
        let file = ["opencode.jsonc", "opencode.json"].iter().map(|f| oc_dir.join(f)).find(|f| f.exists()).unwrap_or_else(|| oc_dir.join("opencode.json"));
        let cfg = if file.exists() {
            serde_json::from_str::<Value>(&strip_jsonc(&std::fs::read_to_string(&file)?)).ok()
        } else {
            Some(json!({ "$schema": "https://opencode.ai/config.json" }))
        };
        match cfg {
            Some(mut cfg) => {
                if !cfg["mcp"].is_object() {
                    cfg["mcp"] = json!({});
                }
                cfg["mcp"]["agentbus"] = json!({ "type": "local", "command": [exe, "mcp", "opencode"], "enabled": true });
                backup(&file);
                std::fs::create_dir_all(&oc_dir)?;
                std::fs::write(&file, serde_json::to_string_pretty(&cfg)? + "\n")?;
                say("opencode", format!("MCP server in {}", file.display()));
            }
            None => say("opencode", format!("could not parse {}; add mcp.agentbus by hand", file.display())),
        }
    } else {
        say("opencode", "not installed");
    }

    let pi_dir = home().join(".pi/agent");
    if has("pi") || pi_dir.exists() {
        let dest = pi_dir.join("extensions/agentbus.ts");
        std::fs::create_dir_all(dest.parent().unwrap())?;
        let _ = std::fs::remove_file(&dest);
        std::fs::write(&dest, PI_EXTENSION)?;
        say("pi", format!("extension at {}", dest.display()));
    } else {
        say("pi", "not installed");
    }

    if tailscale_bin().is_none() {
        println!("\nWARNING: tailscale CLI not found; the daemon runs local-only until Tailscale is installed and logged in.");
    }
    if is_wsl() {
        println!("\nWSL: its Hyper-V firewall blocks inbound connections by default, so other devices can't reach this one until,");
        println!("once, from an *admin* PowerShell on Windows (skip if already done):");
        println!("  New-NetFirewallHyperVRule -Name agentbus -DisplayName \"agentbus (WSL)\" -Direction Inbound -VMCreatorId '{{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}}' -Protocol TCP -LocalPorts {} -RemoteAddresses 100.64.0.0/10", port());
    }
    println!("\nRestart running agent sessions to pick up agentbus. Codex asks you to approve the new hooks once.");
    Ok(())
}
