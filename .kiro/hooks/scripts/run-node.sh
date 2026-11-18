#!/bin/sh
# Launcher for Kiro hook scripts.
#
# Kiro runs hook commands with /bin/sh and a minimal PATH, without the user's shell profile.
# Node installed through nvm, fnm, Volta, or a keg-only Homebrew formula is then invisible,
# and a plain `node script.mjs` fails with exit 127. That exit code is an error, not a block,
# so a guard hook would silently stop guarding. This launcher finds node itself.
#
# Usage: run-node.sh <closed|open> <script.mjs> [args passed to the script...]
#   closed: if node can't be found, exit 2 (block). Use for guards.
#   open:   if node can't be found, exit 1 (error shown to the agent). Use for checks that
#           can't block anyway, such as PostFileSave.
#
# Stdin (the hook event JSON) is passed straight through to the script.

mode="$1"
script="$2"

if [ -z "$script" ] || { [ "$mode" != "closed" ] && [ "$mode" != "open" ]; }; then
  echo "run-node.sh: usage: run-node.sh <closed|open> <script.mjs> [args...]" >&2
  exit 2
fi

# Keep only absolute PATH entries. The hook PATH Kiro provides ends with ".", which would let a file
# named "node" in the repo run in place of the real one. Then add the system directories.
clean_path=""
old_ifs="$IFS"
IFS=":"
for entry in $PATH; do
  case "$entry" in
    /*) clean_path="${clean_path:+$clean_path:}$entry" ;;
  esac
done
IFS="$old_ifs"
PATH="${clean_path:+$clean_path:}/usr/bin:/bin:/usr/sbin:/sbin"
export PATH

found=""
try() {
  case "$1" in
    /*) ;;
    *) return ;;
  esac
  if [ -z "$found" ] && [ -f "$1" ] && [ -x "$1" ]; then
    found="$1"
  fi
}

# 1. Whatever is on the cleaned PATH.
try "$(command -v node 2>/dev/null)"

# 2. nvm: prefer the major version in .nvmrc (digits only), else the newest installed.
nvm_dir="${NVM_DIR:-${HOME:+$HOME/.nvm}}"
if [ -z "$found" ] && [ -n "$nvm_dir" ] && [ -d "$nvm_dir/versions/node" ]; then
  want=""
  if [ -f .nvmrc ]; then
    want="$(tr -d ' \nv' < .nvmrc)"
    case "$want" in
      ''|*[!0-9]*) want="" ;;
    esac
  fi
  if [ -n "$want" ]; then
    for dir in "$nvm_dir/versions/node/v$want".*; do try "$dir/bin/node"; done
  fi
  if [ -z "$found" ]; then
    newest="$(ls "$nvm_dir/versions/node" 2>/dev/null | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sed 's/^v//' | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1)"
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
    echo "Blocked: this guard hook couldn't find Node.js, so it can't check anything. Install Node (see .nvmrc), or turn the hook off in the Kiro panel while you fix it." >&2
    exit 2
  fi
  echo "This hook couldn't find Node.js and didn't run. Install Node (see .nvmrc)." >&2
  exit 1
fi

shift 2
exec "$found" "$script" "$@"
