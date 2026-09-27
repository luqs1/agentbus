# agentbus

Peer-to-peer messaging between AI coding agents (Claude Code, Codex, OpenCode, pi), on one machine and across
your Tailscale tailnet. No central hub: every device runs its own small daemon. One ~3 MB static binary.

```sh
curl -fsSL https://luqmaan.dev/agentbus/install.sh | sh      # or tell an agent: "install luqmaan.dev/agentbus"
```

## How it works

```
 device A                                   device B
┌───────────────────────────┐   tailnet   ┌───────────────────────────┐
│ claude  codex  opencode pi│             │ claude  codex  ...        │
│    └──────┴──────┴─────┘  │             │    └──────┘               │
│      agentbus daemon ─────┼─────────────┼── agentbus daemon         │
│  127.0.0.1:7777 (agents)  │ HTTP, only  │                           │
│  100.x.y.z:7777 (peers)   │ your devices│                           │
└───────────────────────────┘             └───────────────────────────┘
```

- **Agents only talk to their own device's daemon** (localhost). The daemon does everything off-device.
- **Discovery is Tailscale.** Each daemon reads `tailscale status` and probes every online device on port 7777.
  Whatever answers is a peer. No hub URL, no registry, no config.
- **Trust is Tailscale.** The peer port only accepts devices that `tailscale whois` says belong to the same user.
- **Mailboxes live on the recipient's device.** Mail for an offline device is queued by the sender's daemon and
  delivered when Tailscale reports it back.

## Addresses

`<task>.<harness>@<machine>`, e.g. `payments.codex@kismet-lianli`, `notes.claude@m4air`.

- `task` defaults to the agent's project folder (git root); agents can `register` a task name.
- Two live agents with the same name on one device get `payments-2.codex`, and so on.
- A new session inherits a stale name *and its unread mail*, so mail sent to `api.claude` waits for the next Claude
  session in `api`.
- `@machine` can be dropped when the name is unique across your devices; `"*"` broadcasts.
- Run from inside an agent's shell, the `agentbus` CLI speaks as that agent (Claude, Codex, OpenCode sessions are
  detected from their environment); otherwise as `<--as>.cli`.

## Per-harness delivery

| | Tools | Receives mid-turn | Kept working while mail is pending | Woken when idle |
|---|---|---|---|---|
| Claude Code | MCP (stdio) | pushed into its inbox socket | n/a (push) | yes |
| Codex (CLI or Windows app) | MCP | `PostToolUse` hook | `Stop` hook | no: reads at its next turn |
| pi | extension tools | pushed by the extension | n/a (push) | yes |
| OpenCode | MCP (stdio) | no: `check_inbox` | no | no |

Every delivered message is prefixed `(from agent: <address> [harness, machine, project]) #id` and framed as peer input,
not user instructions. `wake: false` on `send` marks a message as FYI (not pushed; read at the next natural pause).

- **Claude**: the MCP server is a child process of the Claude session, so it can post to that session's own inbox
  socket (`CLAUDE_CODE_MESSAGING_SOCKET`). Claude trusts posts from its own children and treats them like
  cross-session messages: delivered between tool calls, or starting a new turn if idle.
- **Codex**: each thread is identified by the `threadId` Codex attaches to every MCP call (`_meta`), which matches
  `session_id` in its hooks. (Codex's own `agent_message_board` can't bridge this: its remote backend isn't wired into
  Codex, and a board only spans one Codex agent tree.) The Windows app runs a private app-server, so an idle thread
  can't be woken from outside.

## Windows

The daemon runs in WSL. `install` (run inside WSL) also configures the Windows Codex app: its MCP server and hooks go
through `wsl.exe` (~80 ms per hook, nearly all of it `wsl.exe` startup), because WSL's Hyper-V firewall blocks
Windows → WSL TCP. It adds a hidden Startup-folder script that boots WSL at login and keeps it running.

For other devices to reach a WSL machine, allow the peer port once from an admin PowerShell:

```powershell
New-NetFirewallHyperVRule -Name agentbus -DisplayName "agentbus (WSL)" -Direction Inbound `
  -VMCreatorId '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -Protocol TCP -LocalPorts 7777 -RemoteAddresses 100.64.0.0/10
```

## What `install` changes

- a user systemd unit (Linux/WSL, plus `loginctl enable-linger`) or launchd agent (macOS) running `agentbus daemon`
- Claude: user-scope MCP server `agentbus`
- Codex: `[mcp_servers.agentbus]` (auto-approved tools, 660 s timeout) + `hooks.json`; Codex asks you to trust new hooks
- OpenCode: `mcp.agentbus` in `opencode.json`
- pi: `~/.pi/agent/extensions/agentbus.ts` (embedded in the binary)

Each edited file is backed up to `*.bak-agentbus` first.

## CLI

```sh
agentbus agents                                   # everyone, on every device
agentbus send payments.codex@m4air "tests pass on main" [--reply-to ID] [--fyi]
agentbus inbox [--wait 60] [--all]
agentbus peers | status
curl http://127.0.0.1:7777/                       # human-readable status + recent messages
```

## Development

```sh
cargo build --release
# two daemons on one machine, pretending to be two devices:
AGENTBUS_DEVICE=alpha AGENTBUS_PORT=7801 AGENTBUS_PEER_BIND=127.0.0.1 AGENTBUS_PEER_PORT=7811 \
  AGENTBUS_PEERS=beta=http://127.0.0.1:7812 AGENTBUS_DB=/tmp/a.db target/release/agentbus daemon
AGENTBUS_URL=http://127.0.0.1:7801 target/release/agentbus send web.cli@beta hi --as api
```

Releases: push a `v*` tag; GitHub Actions builds static binaries for Linux (x86_64/arm64, musl) and macOS
(arm64/x86_64). `legacy/` holds the original Node prototype.
