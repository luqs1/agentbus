# agentbus: notes for agents working on this repo

Rust daemon + CLI connecting AI coding agents across your machines (Tailscale) and to other people's machines (h2h over
iroh). Read README.md for what it does. The design, every decision the owner has made, and the open decisions are in
the Obsidian note `~/repos/notes/Entrepreneurs First/Agents between people (agentbus)/agentbus - system architecture.md`.
Its §1 ("What you've told me") is the source of truth: anything that contradicts it is wrong.

## Design rules the owner set (don't drift from these)

- **No agent on the other side.** A's agent calls tools on B's machine directly. B spends no LLM tokens; the only model on
  B's side is the permission classifier (Jev, TypeSafe). `ask` was removed on purpose: don't bring it back.
- **Never-lists, not allow-lists.** Hard nevers are enforced in code *and* shown to Jev. Jev runs before the call
  (refuse or flag only) and after it, on each piece of real output.
- **Every owner decision is stored with its reason** and becomes precedent. Relationships live in an entity map
  (person -> team -> company) on the owner's machine, never on a server.
- **Your own devices need no permissions.** Tailnet peers logged in as the same Tailscale user get every tool, plus
  `bash`, with no session or checks. People never get `bash`.
- Coordination server (planned) carries metadata only; data goes peer to peer.

## Layout

| File | What |
|---|---|
| `src/daemon.rs` | Local HTTP + MCP server, tailnet peer API (`/peer/*`, guarded by `tailscale whois` same-login), routing of `remote_call` (own device vs person) |
| `src/own.rs` | Tools on your own devices: serve, `bash`, streamed `copy` |
| `src/h2h.rs` | iroh endpoint, handshake Gate (drops unknown keys), contacts and codes, owner dialogs, local API for `agentbus h2h …` |
| `src/remote.rs` | Remote tools for people: sessions, the reveal pipeline (hard nevers -> pre-check -> run -> post-check -> owner), writes, grounding, eval; the tool runners themselves (`run`, `walk`) |
| `src/trust.rs` | Trust engine: schema, entity map, statements, grants, hard nevers, precedent, cache, all Jev questions |
| `src/main.rs` | CLI (clap) |
| `src/shim.rs`, `src/install.rs`, `src/util.rs` | stdio MCP shim, service install, helpers |

## Build and test

```sh
cargo build --release && cargo test --release
```

**Two machines for real** (this Mac and the Windows box `kismet-lianli`, agentbus in WSL): test daemons on port 7790 with
their own data, so the installed daemons (7777) are never touched.
- Mac: `~/labs/agentbus-test/mac/ab <cmd>` (wrapper; binary at `~/labs/agentbus-test/mac/agentbus`, copy a new build
  there). Start: `~/labs/agentbus-test/mac/ab daemon`.
- WSL: source copy in `~/labs/agentbus-test/src` (no git; sync with
  `git archive HEAD src | ssh luqmaan@100.126.216.11 "wsl -d Ubuntu-24.04 -- bash -c 'tar -x -C ~/labs/agentbus-test/src'"`),
  build there with cargo, copy `target/release/agentbus` to `~/labs/agentbus-test/wsl/`, and run
  `~/labs/agentbus-test/ab daemon` in tmux session `abtest` (kill the session before copying the binary). Run WSL
  commands by piping a script: `ssh luqmaan@100.126.216.11 "wsl -d Ubuntu-24.04 -- bash -l" < script.sh`.
- Scripts in `~/labs/agentbus-test/`: `own-test.sh` (own-device tools), `h2h-test.sh open|ground|calls|log`,
  `h2h-learn.sh`, `h2h-mixed.sh`. In the h2h tests the Mac is `luqmaan` and WSL is the person `kian`, paired over iroh.
- Test daemons run with `AGENTBUS_NO_DIALOG=1`; decide with `ab h2h pending` / `approve ID --why` / `deny` / `answer`.
- Jev needs a TypeSafe key (`ab h2h config typesafe-key …`). Never print it.

## Careful

- The installed agentbus on this Mac (0.5) has a real contact, Nikita, on 0.5. Installing 0.6 changes what her agent
  gets. Ask before installing or upgrading either machine's real daemon.
- Releases: push a `v*` tag and GitHub Actions builds the binaries; `agentbus upgrade` installs the latest release.
  `main` is ahead of the latest release (0.5) until v0.6.0 is tagged. Ask before tagging.
- Commit messages explain why.
