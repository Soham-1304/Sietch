#!/bin/sh
# Launcher for Kiro hook scripts.
#
# Kiro runs hook commands with /bin/sh and a minimal PATH, without the user's shell profile.
# Node installed through nvm, fnm, Volta, or a keg-only Homebrew formula is then invisible,
# and a plain `node script.mjs` fails with exit 127. That exit code is an error, not a block,
# so a guard hook silently stops guarding. This launcher finds node itself.
#
# Usage: run-node.sh <closed|open> <script.mjs> [args passed to the script...]
#   closed: if node can't be found, exit 2 (block). Use for guards like host-guard.
#   open:   if node can't be found, warn on stderr and exit 1 (don't block). Use where
#           blocking would lock the user out, like a Prompt Submit hook.
#
# Stdin (the hook event JSON) is passed straight through to the script.

mode="$1"
script="$2"

# Hook environments can have an empty or partial PATH. Make sure basic tools are reachable.
PATH="${PATH:+$PATH:}/usr/bin:/bin:/usr/sbin:/sbin"
export PATH

if [ -z "$script" ] || { [ "$mode" != "closed" ] && [ "$mode" != "open" ]; }; then
  echo "run-node.sh: usage: run-node.sh <closed|open> <script.mjs>" >&2
  exit 2
fi

found=""
try() {
  if [ -z "$found" ] && [ -n "$1" ] && [ -x "$1" ]; then
    found="$1"
  fi
}

# 1. Whatever is already on PATH.
try "$(command -v node 2>/dev/null)"

# 2. nvm: prefer the major version in .nvmrc, else the newest installed.
nvm_dir="${NVM_DIR:-${HOME:+$HOME/.nvm}}"
if [ -z "$found" ] && [ -n "$nvm_dir" ] && [ -d "$nvm_dir/versions/node" ]; then
  want=""
  [ -f .nvmrc ] && want="$(tr -d ' \nv' < .nvmrc)"
  if [ -n "$want" ]; then
    for dir in "$nvm_dir/versions/node/v$want".*; do try "$dir/bin/node"; done
  fi
  if [ -z "$found" ]; then
    newest="$(ls "$nvm_dir/versions/node" 2>/dev/null | sed 's/^v//' | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1)"
    [ -n "$newest" ] && try "$nvm_dir/versions/node/v$newest/bin/node"
  fi
fi

# 3. Other common install locations.
try /opt/homebrew/opt/node@24/bin/node
try /opt/homebrew/bin/node
try /usr/local/opt/node@24/bin/node
try /usr/local/bin/node
if [ -n "$HOME" ]; then
  try "$HOME/.volta/bin/node"
  try "$HOME/.local/share/fnm/aliases/default/bin/node"
  try "$HOME/.fnm/aliases/default/bin/node"
  try "$HOME/.asdf/shims/node"
fi

if [ -z "$found" ]; then
  if [ "$mode" = "closed" ]; then
    echo "Blocked: this guard hook couldn't find Node.js, so it can't check the command. Install Node (see .nvmrc), or disable the hook in .kiro/hooks/ while you fix it." >&2
    exit 2
  fi
  echo "Warning: a hook couldn't find Node.js and was skipped. Install Node (see .nvmrc)." >&2
  exit 1
fi

shift 2
exec "$found" "$script" "$@"
