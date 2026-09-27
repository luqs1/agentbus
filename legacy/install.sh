#!/bin/sh
# Install agentbus on this device: its own daemon (peer-to-peer, no hub) plus wiring for local agents.
#   curl -fsSL http://<any-device-running-agentbus>:7777/install.sh | sh
set -e
SRC="__SOURCE__"
command -v node >/dev/null || { echo "agentbus needs Node.js >= 22.5" >&2; exit 1; }
DIR="$HOME/.local/share/agentbus/app"
mkdir -p "$DIR" "$HOME/.local/bin"
curl -fsSL "$SRC/agentbus.mjs" -o "$DIR/agentbus.mjs"
curl -fsSL "$SRC/pi-extension.ts" -o "$DIR/pi-extension.ts"
curl -fsSL "$SRC/install.sh" -o "$DIR/install.sh"
chmod +x "$DIR/agentbus.mjs"
ln -sf "$DIR/agentbus.mjs" "$HOME/.local/bin/agentbus"
node "$DIR/agentbus.mjs" install
