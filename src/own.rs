//! Your own devices: an agent on one of your machines calls tools on another one directly, over the tailnet. A device
//! counts as yours when Tailscale says it's logged in as you (`Daemon::allow_peer`), so nothing is judged or asked:
//! they're your files on your machines. On top of the tools people get, there's `bash`, which people never get.

use crate::daemon::Agent;
use crate::h2h::{human, resolve};
use crate::remote;
use crate::util::*;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const TOOLS: [(&str, &str); 7] = [
    ("read", "Read a text file. args: {path, offset? (first line, 1-based), limit? (lines, default 400)}."),
    ("grep", "Search file contents with a regular expression. args: {pattern, path? (default ~), glob?, ignore_case?}. Skips hidden files and build folders; use bash for those."),
    ("glob", "Find files by name. args: {pattern, path? (default ~)}."),
    ("ls", "List a folder. args: {path}."),
    ("copy", "Download a file of any type (up to 2 GiB) to this machine. args: {path, dest? (a path here; default ~/agentbus-inbox/<device>/)}."),
    ("write", "Create or overwrite a text file. args: {path, content}."),
    ("bash", "Run a shell command there, in a login shell (so with its PATH). args: {command, cwd? (default ~), timeout? (seconds, default 120, max 600)}. Returns the exit code and output."),
];

const OUTPUT_MAX_CHARS: usize = 60_000;
const COPY_MAX_BYTES: u64 = 2 << 30;
const WRITE_MAX_BYTES: usize = 10 << 20;

pub fn tools_text() -> String {
    TOOLS.iter().map(|(n, d)| format!("  {n}: {d}")).collect::<Vec<_>>().join("\n")
}

fn path_arg(args: &Value, key: &str) -> PathBuf {
    resolve(&home(), args[key].as_str().filter(|p| !p.is_empty()).unwrap_or("~"))
}

// --- the device that runs the call -----------------------------------------------------------------

/// A call from one of the owner's other devices (blocking: run it on a worker thread).
pub fn serve(req: &Value) -> Result<String> {
    let (tool, args) = (req["tool"].as_str().unwrap_or(""), &req["args"]);
    let from = req["from"].as_str().unwrap_or("?");
    let path = path_arg(args, "path");
    println!("own: {from}: {tool} {}", if tool == "bash" { args["command"].as_str().unwrap_or("").chars().take(120).collect() } else { tilde(&path.to_string_lossy()) });
    match tool {
        "read" | "grep" | "glob" | "ls" => {
            let ran = remote::run(tool, &path, args, &[])?;
            if ran.items.is_empty() {
                return Ok(format!("Nothing found. {}", ran.note).trim().to_string());
            }
            Ok(remote::render(tool, &ran.items.iter().collect::<Vec<_>>(), 0, &ran.note))
        }
        "write" => {
            let content = args["content"].as_str().ok_or_else(|| anyhow!("write needs content"))?;
            if content.len() > WRITE_MAX_BYTES {
                return Err(anyhow!("content is over 10 MB"));
            }
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(&path, content)?;
            Ok(format!("Wrote {} ({}).", tilde(&path.to_string_lossy()), human(content.len() as u64)))
        }
        "bash" => bash(args),
        "copy" => Err(anyhow!("copy goes through /peer/fetch")),
        _ => Err(anyhow!("no tool \"{tool}\"; tools: {}", TOOLS.iter().map(|t| t.0).collect::<Vec<_>>().join(", "))),
    }
}

/// The file behind a `copy`: where it is, its name and size.
pub fn fetch(req: &Value) -> Result<(PathBuf, String, u64)> {
    let path = path_arg(&req["args"], "path");
    let meta = std::fs::metadata(&path).map_err(|_| anyhow!("no file at {}", tilde(&path.to_string_lossy())))?;
    if !meta.is_file() {
        return Err(anyhow!("{} isn't a file", tilde(&path.to_string_lossy())));
    }
    if meta.len() > COPY_MAX_BYTES {
        return Err(anyhow!("{} is over the 2 GiB limit", tilde(&path.to_string_lossy())));
    }
    println!("own: {}: copy {}", req["from"].as_str().unwrap_or("?"), tilde(&path.to_string_lossy()));
    Ok((path.clone(), base_name(&path.to_string_lossy()), meta.len()))
}

fn bash(args: &Value) -> Result<String> {
    let cmd = args["command"].as_str().filter(|c| !c.trim().is_empty()).ok_or_else(|| anyhow!("bash needs a command"))?;
    let cwd = path_arg(args, "cwd");
    let secs = args["timeout"].as_u64().unwrap_or(120).clamp(1, 600);
    let shell = std::env::var("SHELL").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| {
        if cfg!(target_os = "macos") { "/bin/zsh" } else { "/bin/bash" }.into()
    });
    let mut c = Command::new(&shell);
    c.args(["-lc", cmd]).current_dir(&cwd).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut c, 0); // so a timeout stops everything it started
    let mut child = c.spawn().map_err(|e| anyhow!("couldn't start {shell}: {e}"))?;
    let drain = |r: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut b = Vec::new();
            if let Some(mut r) = r {
                let _ = r.read_to_end(&mut b);
            }
            String::from_utf8_lossy(&b).into_owned()
        })
    };
    let out = drain(child.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>));
    let err = drain(child.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>));
    let deadline = Instant::now() + Duration::from_secs(secs);
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break Some(st);
        }
        if Instant::now() > deadline {
            let pg = format!("-{}", child.id());
            let _ = Command::new("kill").args(["-TERM", "--", &pg]).status();
            std::thread::sleep(Duration::from_millis(500));
            let _ = Command::new("kill").args(["-KILL", "--", &pg]).status();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(30));
    };
    let (out, err) = (out.join().unwrap_or_default(), err.join().unwrap_or_default());
    let head = match status {
        Some(st) => match st.code() {
            Some(code) => format!("exit {code}"),
            None => "killed by a signal".into(),
        },
        None => format!("stopped after {secs}s (timeout)"),
    };
    let (out, err) = (tail(&out, OUTPUT_MAX_CHARS), tail(&err, OUTPUT_MAX_CHARS / 4));
    let mut text = head;
    if !out.trim().is_empty() {
        text.push_str(&format!("\n{out}"));
    }
    if !err.trim().is_empty() {
        text.push_str(&format!("\n[stderr]\n{err}"));
    }
    Ok(text)
}

/// The end of `s` (where errors and results usually are), at most `max` characters, without carriage returns or
/// terminal escape codes (Windows programs through WSL interop are full of both).
fn tail(s: &str, max: usize) -> String {
    static ESC: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let esc = ESC.get_or_init(|| regex::Regex::new(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07|\r").unwrap());
    let s = esc.replace_all(s, "");
    let s = s.trim_start_matches('\n');
    let n = s.chars().count();
    if n <= max {
        return s.trim_end().to_string();
    }
    let rest: String = s.chars().skip(n - max).collect();
    format!("(first {} characters cut)\n{}", n - max, rest.trim_end())
}

// --- the device that asks --------------------------------------------------------------------------

/// Calls `tool` on the owner's device `device` (peer URL `url`).
pub async fn call(a: &Agent, from: &str, device: &str, url: &str, tool: &str, args: &Value) -> Result<String> {
    if !TOOLS.iter().any(|t| t.0 == tool) {
        return Err(anyhow!("no tool \"{tool}\"; tools on your own devices:\n{}", tools_text()));
    }
    let req = json!({ "tool": tool, "args": args, "from": from });
    let base = a.cwd.as_deref().map(PathBuf::from).unwrap_or_else(home);
    let (url, device, tool) = (url.to_string(), device.to_string(), tool.to_string());
    let dest = args["dest"].as_str().filter(|d| !d.is_empty()).map(|d| resolve(&base, d));
    tokio::task::spawn_blocking(move || {
        if tool == "copy" {
            return download(&url, &device, &req, dest);
        }
        let secs = if tool == "bash" { req["args"]["timeout"].as_u64().unwrap_or(120).clamp(1, 600) + 15 } else { 90 };
        match agent().post(&format!("{url}/peer/tool")).timeout(Duration::from_secs(secs)).send_json(req) {
            Ok(r) => Ok(r.into_json::<Value>()?["output"].as_str().unwrap_or("").to_string()),
            Err(e) => Err(peer_error(&device, e)),
        }
    })
    .await?
}

fn download(url: &str, device: &str, req: &Value, dest: Option<PathBuf>) -> Result<String> {
    let r = agent()
        .post(&format!("{url}/peer/fetch"))
        .timeout(Duration::from_secs(3600))
        .send_json(req.clone())
        .map_err(|e| peer_error(device, e))?;
    let name = urlencoding::decode(r.header("x-agentbus-name").unwrap_or("file")).map(|n| n.into_owned()).unwrap_or_default();
    let name = base_name(&name).trim_start_matches('.').to_string();
    let name = if name.is_empty() { "file".to_string() } else { name };
    let size: u64 = r.header("content-length").and_then(|s| s.parse().ok()).unwrap_or(0);
    let path = match dest {
        Some(d) if d.is_dir() => free_name(&d, &name),
        Some(d) => d,
        None => free_name(&home().join("agentbus-inbox").join(device), &name),
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let part = path.with_extension("agentbus-part");
    let t = Instant::now();
    let got = std::io::copy(&mut r.into_reader().take(COPY_MAX_BYTES + 1), &mut std::fs::File::create(&part)?)?;
    if size > 0 && got != size {
        let _ = std::fs::remove_file(&part);
        return Err(anyhow!("transfer cut short ({got} of {size} bytes)"));
    }
    std::fs::rename(&part, &path)?;
    let rate = got as f64 / t.elapsed().as_secs_f64().max(0.001) / 1e6;
    Ok(format!("Saved {} ({}, {rate:.1} MB/s).", path.display(), human(got)))
}

/// `dir/name`, or `dir/name-2.ext` and so on if that's taken.
fn free_name(dir: &Path, name: &str) -> PathBuf {
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
        _ => (name.to_string(), String::new()),
    };
    let mut p = dir.join(name);
    for i in 2.. {
        if !p.exists() {
            break;
        }
        p = dir.join(format!("{stem}-{i}{ext}"));
    }
    p
}

fn peer_error(device: &str, e: ureq::Error) -> anyhow::Error {
    match e {
        ureq::Error::Status(404, _) => anyhow!("{device} runs an older agentbus without remote tools; run `agentbus upgrade` there"),
        ureq::Error::Status(_, r) => {
            let v: Value = r.into_json().unwrap_or(Value::Null);
            anyhow!("{}", v["error"].as_str().unwrap_or("error on the other device"))
        }
        e => anyhow!("{device} is unreachable ({e})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bash_runs_and_times_out() {
        let r = bash(&json!({ "command": "echo hi; echo oops >&2; exit 3", "cwd": "/" })).unwrap();
        assert!(r.starts_with("exit 3\nhi") && r.contains("[stderr]\noops"), "{r}");
        let t = Instant::now();
        let r = bash(&json!({ "command": "sleep 30 & sleep 30", "timeout": 1 })).unwrap();
        assert!(r.contains("timeout") && t.elapsed() < Duration::from_secs(5), "{r}");
    }

    #[test]
    fn tails_keep_the_end() {
        assert_eq!(tail("abcdef", 10), "abcdef");
        assert!(tail("abcdef", 3).ends_with("\ndef"));
        assert_eq!(tail("\r\nWindows 11\r\n\x1b[?25l\x1b[32mok\x1b[0m\r\n", 100), "Windows 11\nok");
    }
}
