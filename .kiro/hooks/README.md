# Kiro hooks

| Hook | Trigger | Job | On failure |
|---|---|---|---|
| `host-guard` | Pre Tool Use (shell) | Blocks dangerous shell commands on the host. | **Blocks** (fail closed). |
| `secret-guard` | Prompt Submit | Blocks chat messages that contain real-looking secrets. | **Blocks** (fail closed). |
| `check-on-save` | Post File Save (`base/`, `apps/` TypeScript) | Typechecks the package and runs related tests. | Reports an error to the agent (a save can't be blocked). |
| `post-task-verify` | Post Task Execution | Asks the agent to run checks and update the log. | Agent prompt, no script. |

All command hooks start through `scripts/run-node.sh`, which finds Node without the shell profile and ignores relative `PATH` entries. Tests: `pnpm vitest run --project hooks`.

## How host-guard decides

1. It parses the command with a strict shell parser (`scripts/lib/shell.mjs`). If the parser isn't sure, the command is **blocked**.
2. It unwraps wrappers (`sudo`, `env`, `timeout`, `xargs`, `npx`, `pnpm dlx`, `bash -c`, `eval`, `find -exec`, ...) and analyses the command that actually runs, including `$(...)`, backticks, `<(...)`, unquoted heredocs, and shell scripts in the repo or temp folders.
3. It blocks five classes: registry writes (publish, unpublish, deprecate, login), containers with host access, code piped into a shell or interpreter, malware corpora on the Mac, and demo packages outside Docker.
4. It blocks anything built at run time that it can't resolve: `$VAR` in a command name or package-manager argument, globs, brace expansion, and dynamic `eval`. Variables are resolved only when assigned once, unconditionally, with a literal value.
5. Everything else is allowed.

## Known gaps (accepted, with the reason)

host-guard is a guard rail for development. The real security boundary is the sandbox, and these gaps are covered by other controls.

| Gap | Why it's accepted | Other control |
|---|---|---|
| A Node or Python **script file** that runs `npm publish` itself (for example `node x.mjs`). Only shell scripts are inspected. | Parsing other languages reliably isn't possible here. Inline code (`node -e`, `python -c`, heredocs) is scanned as text. | **No npm token exists on this machine** (`~/.npmrc` absent, `npm whoami` fails), and publishing only happens from CI with OIDC trusted publishing. A publish attempt fails for lack of credentials. |
| Shell scripts **outside** the repo and temp folders (for example `~/.nvm/nvm.sh`) aren't parsed. | These are installed tools, and parsing them would block normal work. | The agent's own scripts live in the repo or temp folders, which are inspected. |
| **Docker Compose files** aren't parsed, only command-line options. | Compose files in this repo are reviewed code. | `security-review` covers compose files. |
| **File-writing tools** (not the shell) can edit `.kiro/hooks/` itself, and so turn a guard off. | Hooks must stay editable while we build them. | Changes to `.kiro/hooks/` show in `git diff` and are reviewed before commit. |
| Code that runs in the background and outlives the check. | Out of scope for a pre-run check. | The sandbox. |
