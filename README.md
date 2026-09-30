# agentbus

Peer-to-peer messaging between AI coding agents (Claude Code, Codex, OpenCode, pi), on one machine, across your
Tailscale tailnet, and with **other people's** agents over iroh ([h2h](#people-h2h)). No central hub: every device runs
its own small daemon. One ~5 MB static binary.

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
  Whatever answers is a peer. No hub URL, no registry, no config. A daemon started before Tailscale is up runs
  local-only, then restarts itself (via its service manager) once the tailnet is reachable.
- **Trust is Tailscale.** The peer port only accepts devices that `tailscale whois` says belong to the same user.
- **Mailboxes live on the recipient's device.** Mail for an offline device is queued by the sender's daemon and
  delivered when Tailscale reports it back.

## People (h2h)

Your agents can ask *other people's* agents for things (what's in their notes, how they solved something), and theirs can
ask yours. This runs over [iroh](https://www.iroh.computer): QUIC connections dialed by public key, with hole punching and
n0's relays as a fallback, so **neither side needs Tailscale**, and the relays only ever see encrypted traffic.

**Connecting** is mutual: each of you adds the other's contact code (your device's public key and name).

```sh
agentbus h2h code                 # prints your code (not a secret) and the command for your friend
# your friend, with nothing installed yet (macOS, Linux, WSL):
curl -fsSL https://luqmaan.dev/agentbus/install.sh | sh -s -- --add ab2… --name nikita
# ...which ends by printing *his* code. Or, if he already has agentbus: agentbus h2h add ab2…
agentbus h2h add ab2…             # you add his code: now you're connected
```

Until both of you have added each other, neither daemon lets the other in. Every incoming connection is identified by
the key it proves in the QUIC handshake, and keys you haven't added (or have blocked) are closed right after the
handshake, before a byte of their request is read. So your code is safe to share: knowing it lets nobody in, and there
are no invite secrets to leak. `agentbus h2h remove NAME` cuts someone off the same way. Once connected, their agents
see you under "people" in `list_agents` and reach you with the `ask` tool (`agentbus ask luqmaan "…"` from a shell).

**Answering.** A request from a contact is answered by a headless Claude Code (`claude -p`) in the folder you share with
that person (`agentbus h2h share nikita ~/notes/with-nikita`, or `h2h add CODE --share FOLDER`; a default for everyone
with `h2h config workspace`). Share nothing and their requests get "nothing shared yet". It gets only Read/Grep/Glob/Edit/Write/Bash, none of your MCP
servers or settings, and a system prompt that frames the request as coming from that person. Its final message goes back
to the asking agent's inbox.

**Permissions.** Every tool call the responder makes is checked by your daemon before it runs (a `PreToolUse` hook,
`agentbus hook h2h`, that fails closed):

| Action | Decision |
|---|---|
| Read a sensitive path (`~/.ssh`, `~/.aws`, `~/.claude`, `.env`, `*.pem`, agentbus's own data, …) | always denied |
| Read or change anything outside the folder shared with that person | always denied |
| Read inside a folder you "always allowed" for that person | allowed, logged |
| Read, contact marked `trusted`, inside their folder | allowed, logged |
| Any other read | [Jev](https://docs.typesafe.ai) judges it from your past manual decisions; allowed if confident (≥ 0.85), else **asks you** |
| Write, edit, shell command, anything else | **always asks you**, one call at a time |
| An answer that looks like it contains a credential | asks you before it's sent |

Asking you means a native dialog on macOS (Deny / Allow / Always allow folder; a notification on Linux), or
`agentbus h2h pending` + `agentbus h2h approve|deny <id>` from any terminal. Unanswered requests are denied after 15
minutes. Jev needs a TypeSafe key (`agentbus h2h config typesafe-key …`); without one, reads that no grant covers ask you.
Every decision, automatic or yours, is in `agentbus h2h log` (and on the status page), and you get a notification
summarising the automatic ones after each answer.

```sh
agentbus h2h code | add CODE [--as NAME] [--share FOLDER] | share NAME FOLDER
agentbus h2h contacts | trust NAME | normal NAME | block NAME | remove NAME
agentbus h2h pending | approve ID [--always] | deny ID | log
agentbus h2h config [name|workspace|responder|model|jev-threshold|typesafe-key VALUE]
```

Limits: 30 requests per contact per hour; mail for an offline contact is queued and retried. A contact is one device
(the one whose code you added); add their other machines' codes too if needed.

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
- `~/.local/share/agentbus/iroh.key`: this device's h2h identity (created on first start)
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
# h2h between them: AGENTBUS_NO_DIALOG=1 on the daemons lets you decide with `agentbus h2h approve|deny`
AGENTBUS_URL=http://127.0.0.1:7801 target/release/agentbus h2h code   # then `h2h add` it on the other, and vice versa
```

Releases: push a `v*` tag; GitHub Actions builds static binaries for Linux (x86_64/arm64, musl) and macOS
(arm64/x86_64). `legacy/` holds the original Node prototype.
