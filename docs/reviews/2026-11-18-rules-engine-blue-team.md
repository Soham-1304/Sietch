# Blue-team pass: rules engine

**Date:** 2026-11-18. **Skill:** `blue-team`. **Scope:** `base/core/src` after the security review fixes. The question: if I wrote malware and had read Sietch's source, how would I get a SAFE verdict?

Design-time cards BT-1 to BT-15 are in `.kiro/specs/rules-engine/design.md`. This pass adds BT-16 onwards. Every "fixed" card was first shown to give SAFE with a probe test, and it now has a regression test.

## Threat cards (ranked: likelihood in real npm malware × impact)

| ID | Goal | Technique | State before | Control or detection now | Fixture or test | Residual risk |
|---|---|---|---|---|---|---|
| BT-16 | D | Write through a symlinked directory: `/tmp/g -> project/.github`, then write `/tmp/g/workflows/x.yml` | **Missed** (SAFE) | Path views through earlier links (`views.ts`). A write is allowed only if every view is allowed (SR-2) | `rules.test.ts` "review regressions" | Links the trace doesn't record (relies on the normaliser contract) |
| BT-17 | D | Read `~/.npmrc` as `/proc/self/root/home/dev/.npmrc` | **Missed** (SAFE) | `/proc/<p>/root` and `/proc/<p>/task/<t>/root` canonicalised (SR-1) | same | `/proc/<p>/cwd/x` is checked as home and project only |
| BT-20 | B/D | Send the token in a body bigger than the sink's capture limit, to an allowlisted host, so R1 only sees the start | **Missed** (SAFE) | R13 fires on any `bodyTruncated` request | `rules.test.ts` "R13 incomplete trace" | None: a cut-off body is always SUSPICIOUS |
| BT-18 | B | Raw TCP to the sink on an odd port, so no `http` event is made | **Missed** (SAFE) | R3 flags sink ports other than 53, 80, and 443 (SR-3) | "review regressions" | The sink must really record 53, 80, and 443 (sandbox-runner spec) |
| BT-19 | A | Make judging slow (many tokens × huge bodies) to tie up workers | Possible | Caps: 16 honeytokens, 24 MiB of scanned text (SR-4) | `schema.test.ts` | None known |
| BT-21 | B | Drop a script outside `node_modules` and run it with `node` (not as an executable) | R4 silent | Not needed for detection: the script's own behaviour is traced, and R1 to R10 apply to it | — | None for detection. R4's signal is about executables only. |
| BT-22 | D | Overwrite another package's file or `node_modules/.bin` shim, so the project's own tools run attacker code later | **Missed** (allowed: inside `node_modules`) | **Open.** It needs to know which directory belongs to which package. Candidate rule R14 for the sandbox-runner spec | — | Real, until R14. Partly mitigated: a package that does this and also steals anything is already caught |
| BT-23 | C | Sleep longer than the observation window, then act | R10 if the process is still alive at teardown | R10 (High) | `rules.test.ts` R10 | A process that exits and leaves a cron-like trigger. There's no cron in the sandbox, so behaviour on a real machine is unseen |
| BT-24 | C | Detect the sandbox (`/proc/1/cgroup`, `/.dockerenv`, gVisor's `dmesg`) and stay quiet | Missed | **Open.** Reads of these paths are a candidate signal (P2). The realistic fake environment lowers the odds | — | Accepted limitation |
| BT-25 | D | Exfiltrate data that isn't a honeytoken (source code, the project's own files) to an allowlisted host | Missed | R1 only knows honeytokens | — | Accepted limitation |
| BT-26 | B | base32, XOR, gzip, reversed, or chunked tokens | R1 silent. R2 and R3 usually still fire | As in design BT-5 | — | Accepted limitation |

## Top 5 actions

1. **Write the normaliser contract into the `trace-normaliser` and `sandbox-runner` specs** (design "Contract for the trace producer"). Add that the sandbox runner's own processes (the container's init and its timers) are left out of the events, or R10 fires on every scan. Add that `bodyTruncated` must be set honestly, and that the syscall list is chosen per architecture (Spike 1).
2. **The capture sink must record DNS, HTTP, and HTTPS on ports 53, 80, and 443**, and only those, to match `SINK_RECORDED_PORTS`.
3. **R14 (P1): tampering with other packages.** Writes into another package's directory or into `node_modules/.bin` after install. The runner must report each package's directory.
4. **Sandbox-detection reads (P2):** reading `/proc/1/cgroup`, `/.dockerenv`, or `/proc/self/mountinfo` as a Medium signal, reported but not blocking.
5. **Replay real-shaped traces** through the engine once the runner exists: the worm lookalike in `demo/`, and benign packages with install scripts (esbuild, sharp, bcrypt) to measure false positives.

## Accepted limitations (for the README)

- Code that only runs in a browser, or only when imported by a particular parent package, isn't seen.
- Behaviour delayed past the observation window, or triggered on a real machine only, isn't seen.
- Malware that detects the sandbox and stays quiet gets SAFE, unless its static code is flagged (R11 and R12, planned).
- Tokens encoded in ways other than raw, hex, base64, double base64, and URL encoding aren't recognised by R1. R2 and R3 still flag the read and the destination.
- Data other than our fake credentials (for example a project's source code) sent to an allowlisted host isn't detected.
- Tampering with other packages inside `node_modules` isn't detected yet (R14 planned).

## Coverage table

| Rule | Scenario fixtures | Unit cases (`rules.test.ts`) |
|---|---|---|
| R1 | worm | body, header, path, DNS, DNS split across labels, npm process |
| R2 | worm | stores, `/proc` environ, `.env`, symlink, `/proc/self/root`, `..` after link |
| R3 | worm, esbuild-like (negative) | unknown host, look-alike, raw IP, mapped IP, sink odd port |
| R4 | Shai-Hulud 2.0 | dropped executable, rename into place, bun |
| R5 | Shai-Hulud 2.0 | curl, busybox applet, openssl s_client, behind a symlink |
| R6 | worm | home write, workflow rename target, device, `/proc` root, symlinked dir, hard link, link loop |
| R7 | — | HTTP PUT, whoami with path tricks, `npm pu`, npm-cli.js |
| R8 | — | repo creation, runner token, `/user`, git push, gh |
| R9 | Shai-Hulud 2.0 | 20 fires, 19 doesn't |
| R10 | worm | no exit, linger activity, PID reuse |
| R13 | — | event cap, truncated body |

R7, R8, and R13 have no scenario fixture yet: a worm that publishes itself (R7) and creates a repo (R8) is added with the `demo/` worm lookalike.
