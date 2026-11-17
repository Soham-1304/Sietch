# Build log

A dated record of how Kiro was used to build Sietch. This file is the raw material for the hackathon's Kiro write-up, so record what actually happened, including what didn't work.

Sections:
- **Log**: dated entries, newest at the bottom.
- **PBT findings**: counterexamples found by property-based tests.
- **Hook catches**: times a hook blocked something or caught a problem.

---

## Log

### 2026-11-16 — Ideation and planning (Kiro IDE, chat)

- Compared five ideas across the four categories in `docs/ideation.md`. Chose Sietch, in the Skeleton Crew category.
- Used web search and fetch inside Kiro to check facts before planning:
  - Shai-Hulud 2.0 ran in preinstall, installed Bun, and detached a background process (Unit 42).
  - Verdaccio filter plugins don't block tarball downloads.
  - Kiro Pre Tool Use hooks can block tool calls with exit code 2.
  - The `sietch` npm name is taken.
- These findings changed the design: a 60-second watch after install, a separate tarball-blocking plugin, and Agent Guard built on Pre Tool Use.
- Wrote `docs/plan.md` (architecture, data, hosting, demo, schedule).
- Reworked hosting to a $0 budget: GCP trial credit, Atlas free cluster, DuckDNS, plus a static replay mode as a fallback.

### 2026-11-17 — Kiro setup

- **Steering** (`.kiro/steering/`):
  - Always on: `product`, `tech`, `structure`, `security`.
  - File-match: `testing` loads only for test and core files.
  - Manual: `plan-reference` and `hackathon-rules`. Both use `#[[file:...]]` links to the live docs, so they never go out of date.
- **Hooks** (`.kiro/hooks/`):
  - `host-guard` (Pre Tool Use, shell) turns the most important `security.md` rules into a hard block. Steering asks the agent to behave; the hook enforces it. Covers: local publish, privileged or host-network Docker, `curl | sh`, malware samples on the Mac, and demo packages outside Docker.
  - `secret-guard` (Prompt Submit) stops real secrets being pasted into chat.
  - `post-task-verify` (Post Task Execution) runs checks after each spec task.
  - Both guard scripts were tested with 31 sample hook events before use.
- **Custom agent**: `sandbox-reviewer`, a read-only reviewer loaded with the security steering, for any sandbox or hosting change.
- Design choice: `host-guard` is the same idea as App 2 (Agent Guard), applied to our own build. It is a working prototype of the product's core mechanism.

---

### 2026-11-17 — Spike 3: does a Pre Tool Use hook block in Kiro IDE?

- **The first try failed silently.** The hook command `node host-guard.mjs` exited 127 (`/bin/sh: node: command not found`). Kiro runs hook commands with `/bin/sh` and a minimal PATH, without the shell profile, so Node installed through nvm was invisible. Exit 127 counts as an error, not a block (only exit 2 blocks), so the guard wasn't guarding anything.
- **Fix:** `.kiro/hooks/scripts/run-node.sh` finds Node itself: PATH first, then nvm (using `.nvmrc`), then Homebrew, Volta, fnm, and asdf. It takes a mode. `closed` blocks if Node can't be found and is used by `host-guard`. `open` only warns and is used by `secret-guard`, so a missing Node can't lock you out of chat.
- **Verified:** with a completely empty environment (`env -i PATH=`), the launcher found nvm's Node and blocked the unsafe command. All 31 hook cases still pass.
- **Confirmed in the IDE:** `host-guard` blocked two of my own agent shell commands because their text contained the publish command (one was a test harness, the other a build-log edit). Kiro didn't run them and passed the hook's reason back to the agent. So Pre Tool Use blocking works in Kiro IDE, which App 2 depends on.
- **Known false positive:** the guard matches the command text anywhere, including inside heredocs and quoted strings. We kept it strict on purpose, because a guard should err on the side of blocking. The workaround is to edit files with Kiro's file tools instead of shell heredocs.
- **Lesson for App 2 (Agent Guard):** a guard whose runtime is missing must fail closed. The Agent Guard hook will use the same launcher pattern.

### 2026-11-17 — Workspace scaffold

- **Checked current versions before writing config,** as `tech.md` requires. Every tool turned out to be a major version newer than the agent remembered: TypeScript 7 (native Go compiler), Vitest 5, pnpm 12, Biome 2.6. Config written from memory would have used removed options, such as pnpm's `onlyBuiltDependencies`, which pnpm 11 replaced with `allowBuilds`. The current versions and their changed options are now recorded in `tech.md`, so later sessions don't repeat the mistake.
- **pnpm's own supply-chain settings, used on ourselves:** a 1-day minimum release age, `trustPolicy: no-downgrade`, and strict install scripts. The first install pulled 42 packages, none needing an install script, and pnpm reported "Lockfile passes supply-chain policies".
- **`base/core` purity is enforced by tools, not just by steering.** Its `tsconfig` loads no Node types, so `node:fs` and `process` are type errors, and Biome refuses `Date`, `fetch`, timers, `crypto`, and `Buffer` there. A temporary probe file confirmed both catch violations.
- **New hook, `check-on-save` (PostFileSave):** typechecks the saved file's package and runs `vitest related`. Failures go back to the agent. Testing it found a bug in `run-node.sh`: it dropped the arguments after the script name, so the hook never received the saved file path and passed every save without checking anything. That was the second time a hook failed open silently. Fixed, then confirmed: a broken file now gives exit 1 with the TypeScript error.
- Wrote the `rules-engine` spec prompt in `docs/spec-prompts.md`. The raw-log parser was moved out of that spec because its input format depends on Spike 1.

## PBT findings

_None yet._

## Hook catches

- **2026-11-17, testing `check-on-save`:** found that the launcher dropped hook arguments, so the hook passed every file without checking. Fixed before it was relied on.
- **2026-11-17, `host-guard`:** blocked two agent shell commands whose text contained the publish command. Both were false positives (a test harness and a heredoc edit), but they proved that blocking works in the IDE. See the Spike 3 entry.
