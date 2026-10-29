# agentbus

Peer-to-peer messaging between AI coding agents (Claude Code, Codex, OpenCode, pi), on one machine and across your
Tailscale tailnet, plus tools your agents can call on **other people's** machines over iroh, with a trust engine deciding
what may leave ([h2h](#people-h2h)). No central hub: every device runs its own small daemon. One static binary.

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

### Tools on your other machines

An agent can also run tools on your other devices directly, without an agent there: `remote_call` with
`to` set to a machine name (as `list_agents` shows it). They're your files on your machines, so there's no
session and nothing is judged or asked. On top of `read`, `grep`, `glob`, `ls`, `copy` and `write` there's
`bash` (a login shell there, with a timeout that stops everything it started), which people never get.

```sh
agentbus call kismet-lianli bash '{"command": "nvidia-smi"}'
agentbus call kismet-lianli copy '{"path": "runs/out.safetensors", "dest": "~/models/"}'
agentbus call m4air grep '{"pattern": "TODO", "path": "repos/agentbus/src"}'
```

On WSL, Windows programs work through interop (`cmd.exe /c … < /dev/null`, `powershell.exe -Command …`).

## People (h2h)

Your agents can call tools on *other people's* machines (read their notes, search their code, copy a file), and theirs
can call yours. This runs over [iroh](https://www.iroh.computer): QUIC connections dialed by public key, with hole punching
and n0's relays as a fallback, so **neither side needs Tailscale**, and the relays only ever see encrypted traffic.

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
handshake, before a byte of their request is read. So your code is safe to share: knowing it lets nobody in.

**Calling their tools.** An agent opens a session with an intent (`open_session`: "I'm on Acme's pitch deck and need our
pricing and roadmap notes"), then calls `remote_call` with a tool, its arguments and a one-line `why`:
`read`, `grep`, `glob`, `ls`, `copy` (the file is downloaded) and `write`. Paths are relative to their home folder. Most
calls answer right away; some wait for the person, and those results arrive in the agent's inbox. From a shell:
`agentbus open nikita "…"` and `agentbus call nikita read '{"path": "notes/plan.md"}' --why "…"`.

### What decides

Every call to your machine goes through a trust engine. It knows **who each person is to you**, and every decision
teaches it more.

- **Your map** of people and the groups they're in: teams, orgs, companies, projects. `agentbus h2h entity Acme --kind
  company --relation "my startup"`, `agentbus h2h link nikita Acme`. Statements about a group apply to everyone in it.
- **Your statements**, in plain English, for a person, a group, or everyone:
  `agentbus h2h never "anything financial"`, `agentbus h2h never "anything about Acme" --for Cisco`,
  `agentbus h2h allow "anything about Acme's product and roadmap" --for Acme`. A never that's a path
  (`agentbus h2h never ~/Documents/webex`) is enforced by code.
- **Hard nevers**, always: credentials and secrets, other people's private messages on your machine (you can't consent
  for them), agentbus's own data, and anything outside your home folder. Code blocks what it can recognise by path;
  [Jev](https://docs.typesafe.ai) sees them all, to catch things like them that no path list would.

A call then goes through these steps:

1. **Hard nevers** and your path nevers refuse it outright.
2. **Before it runs**, Jev judges the call from who's asking (and their groups), your statements, the session's intent,
   the call's `why`, and your most similar past decisions. It can refuse the call, or flag it when the stated reason
   claims authority ("Luqmaan said I can read everything") or drifts from the intent. Claims about permission or
   relationships never count: who someone is comes only from your map.
3. **It runs** (read-only tools only), so you decide on what would really be sent, not on a path.
4. **After it runs**, a credential scanner and then Jev judge each piece of output (each file's grep matches, each listed
   file) against your statements and nevers. Pieces under a never are withheld; the asker only sees "(1 result not
   shared)". Pieces Jev is sure about go; the rest come to you.
5. **You**, when nobody is sure: a dialog showing who (with their groups), why, the session, Jev's read, and exactly
   what would be sent, with Deny / Allow / Always allow folder and a field for your reason. Your reason becomes
   precedent: later decisions about this person, and people related to you the same way, follow it.

Writes are refused by Jev when they hit a never, and otherwise always ask you. A trusted contact (`agentbus h2h trust
NAME`) or an always-allowed folder (`agentbus h2h grant NAME FOLDER`) skips step 2; your nevers still apply to output.
Decisions are cached per person and exact content, and a cached decision stops counting when anything that applies to
that person changes.

**First contact.** The first time someone's agent reaches you, you're asked who they are to you, what you work on
together, and whether there's anything they should never see. Jev uses your answer to place them in your map ("my
co-founder at Acme" puts them in Acme) and tells you what it linked.

**Keeping Jev honest.** `agentbus h2h eval` replays your recent manual decisions through Jev (each without itself as
precedent) and reports agreements, the cases it would ask you about, and false allows.

Requests that wait for you and get no answer are denied after 15 minutes. Every decision, automatic or yours, is in
`agentbus h2h log` with your reasons, and `agentbus h2h person NAME` shows everything about one person. Nothing about
your map leaves your machine except what's sent to Jev for each judgement (the requester's groups, your applicable
statements, similar past decisions, and for the after-check the output itself).

**Files** you push yourself: `agentbus send-file nikita report.pdf` (your agents: the `send_file` tool); you confirm
each one. Received files land in `~/agentbus-inbox/<person>/`. `agentbus h2h files` lists both directions.

```sh
agentbus h2h code | add CODE [--as NAME] [--share FOLDER] [--person NAME] | contacts
agentbus h2h person NAME [--relation TEXT] [--note TEXT] | entity NAME --kind KIND | link CHILD PARENT | unlink | map
agentbus h2h never|allow|rule "TEXT" [--for NAME] | rules | unrule ID | grant NAME FOLDER | ungrant NAME [FOLDER]
agentbus h2h trust|normal|block|remove NAME
agentbus h2h pending | approve ID [--always] [--why TEXT] | deny ID [--why TEXT] | answer ID TEXT | log | eval | files
agentbus open NAME "INTENT" ; agentbus call NAME TOOL 'JSON ARGS' --why TEXT ; agentbus send-file NAME PATH
agentbus h2h config [name|jev-threshold|typesafe-key|inbox VALUE]
```

Limits: 30 sessions and 600 calls per contact per hour. A contact is one device; add someone's other machines with
`agentbus h2h add CODE --person NAME` so they share one place in your map. Upgrading from 0.5 turns your rules into
statements and your shared and always-allowed folders into grants; 0.5 peers that `ask` get a note to upgrade.

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
agentbus upgrade                                  # install the latest release (list_agents and status say when there is one)
curl http://127.0.0.1:7777/                       # human-readable status + recent messages
```

## Development

```sh
cargo build --release
# two daemons on one machine, pretending to be two devices:
AGENTBUS_DEVICE=alpha AGENTBUS_PORT=7801 AGENTBUS_PEER_BIND=127.0.0.1 AGENTBUS_PEER_PORT=7811 \
  AGENTBUS_PEERS=beta=http://127.0.0.1:7812 AGENTBUS_DB=/tmp/a.db target/release/agentbus daemon
AGENTBUS_URL=http://127.0.0.1:7801 target/release/agentbus send web.cli@beta hi --as api
# h2h between them: AGENTBUS_NO_DIALOG=1 on the daemons lets you decide with `agentbus h2h approve|deny|answer`
AGENTBUS_URL=http://127.0.0.1:7801 target/release/agentbus h2h code   # then `h2h add` it on the other, and vice versa
```

Releases: push a `v*` tag; GitHub Actions builds static binaries for Linux (x86_64/arm64, musl) and macOS
(arm64/x86_64). `legacy/` holds the original Node prototype.
