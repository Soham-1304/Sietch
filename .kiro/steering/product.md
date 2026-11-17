---
inclusion: always
---

# Product: Sietch

Sietch is a verification checkpoint for npm packages. Before a package version reaches a real machine, Sietch detonates it in a locked-down sandbox that holds only fake credentials (honeytokens), records what it does (files, processes, network), and gives a deterministic verdict backed by evidence. Each version is checked once, and the whole organisation reuses the verdict.

"Sietch" is a working name. Branding is decided later, so keep the name easy to change: use it in config and constants, not scattered through prose and identifiers.

## Who it is for

- **Security and platform teams** who run Sietch for their company.
- **Developers and CI pipelines** that install packages through it.
- **AI coding agents** (Kiro first) that install packages and MCP servers on their own.

## Shape of the project (Kiroween 2026, Skeleton Crew category)

The hackathon category requires one base and **exactly two apps**, each in its own folder.

| Part | Folder | Role |
|---|---|---|
| Base | `base/` | The detonation engine: sandbox, honeytokens, behaviour recording, rules engine, verdict store, API, CLI. |
| App 1: Registry Gate | `apps/registry-gate/` | Private npm registry (Verdaccio + Sietch plugins) and the dashboard. For developers and CI. |
| App 2: Agent Guard | `apps/agent-guard/` | MCP server, Kiro power, and hooks that protect AI agents from unsafe packages and MCP servers. |

Do not add a third app. New ecosystems (PyPI and so on) are adapters in the base, documented in the README.

## Product principles

1. **Deterministic verdicts.** The rules engine is a pure function. No LLM or AI decides a verdict.
2. **Evidence or it didn't happen.** Every finding links to the exact recorded events that caused it.
3. **Fail closed.** If a scan errors or times out, the version is blocked, not allowed.
4. **Scan once, trust everywhere.** Verdicts are keyed by name, version, and integrity hash, and reused across the organisation.
5. **Honest limits.** Never claim the sandbox catches everything. State known gaps in docs and UI copy.

## Scope discipline

- The plan, priorities (P0, P1, P2), and the cut list live in `docs/plan.md`. The task checklist lives in `docs/checklist.md`. Load them with `#plan-reference` when needed.
- Build P0 first. Don't start P1 or P2 work unless the user asks or the checklist says P0 is done.
- Don't add features, dependencies, or abstractions that the plan doesn't call for. Suggest them instead.

## Constraints

- **Budget is $0.** Use only free services and free tiers. Never suggest a paid service without saying so and offering a free alternative.
- **Solo developer**, a student, with limited frontend experience. Prefer component libraries and simple UI over custom design work.
- **Deadline:** Fri Dec 4, 2026, 2:00 PM PT (Sat Dec 5, 3:30 AM IST).
- **License:** Apache-2.0. New dependencies must have a compatible license.
- **The `.kiro/` folder is part of the submission.** Never add it, or anything inside it, to `.gitignore`.

## Build log

`docs/build-log.md` feeds the hackathon write-up about how Kiro was used. After any of these events, add a short, dated entry:

- a spec is created or finished,
- a hook blocks something or catches a problem,
- a property-based test finds a counterexample,
- a steering change noticeably changes results,
- an MCP server or power is used in a way that saved real effort.
