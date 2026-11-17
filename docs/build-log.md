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

## PBT findings

_None yet._

## Hook catches

_None yet._
