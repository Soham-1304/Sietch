# Security review: rules engine (`base/core/src`)

**Date:** 2026-11-18. **Skill:** `security-review`. **Scope:** every file in `base/core/src` (rules engine, tasks 1–9). **Verdict: FAIL** (2 High, 2 Medium, 2 Low). Fixes are tracked at the end.

Each finding was confirmed with a probe test that ran the trace through `judge()` before any fix.

## Findings

| ID | Severity | Location | Class | Trigger | Impact | Fix |
|---|---|---|---|---|---|---|
| SR-1 | **High** | `context.ts` `isCredentialPath`; all path rules | Path alias bypass | Read `/proc/self/root/home/dev/.npmrc`. `/proc/<pid>/root` is a link to `/`, so this reads `~/.npmrc`. | The credential read gets **SAFE** (R2 silent). Writes through `/proc/self/root/…` to `.github/workflows` are only High, not Critical. | Canonicalise `/proc/<x>/root/…` and `/proc/<x>/task/<t>/root/…` to `/…`. For `/proc/<x>/cwd/<rest>`, also check `<rest>` under `home` and `projectDir`. |
| SR-2 | **High** | `context.ts`, R2, R4, R5, R6, R7 | Symlink write-through | `symlink /tmp/g -> /work/app/.github`, then `create /tmp/g/workflows/x.yml`. Also `symlink /tmp/h -> ~`, then write `/tmp/h/.bashrc`. | The workflow is planted and the verdict is **SAFE**: the path is under `/tmp`, which is an allowed write root. The same trick hides `curl` behind `/tmp/c` from R5 (only R4 fires). | Resolve every path through the symlinks and hard links the trace created **before** that event, up to `MAX_SYMLINK_HOPS`. A write is allowed only if **every** view (raw and resolved) is allowed, and unresolvable loops are not allowed. Credential, workflow, and program checks apply to **any** view. Hard links to files outside the allowed area are R6. |
| SR-3 | Medium | `rules/r03-unexpected-destination.ts` | Unseen channel | Resolve an allowlisted name (which goes to the sink), then `connect` to the sink on port 4444 and send the token as raw TCP. | No `http` event is recorded, so R1 can't see the payload, and R3 skips the sink address: **SAFE**. | A `connect` to a sink address on a port the sink doesn't record (anything but 53, 80, 443) is R3 High. |
| SR-4 | Medium | `schema.ts` limits | Resource exhaustion | 64 honeytokens × 44 patterns × 3 decode rounds, over 16 MiB of bodies plus headers. | Judging could take minutes, which ties up a worker (denial of service by one package). | Cap honeytokens at 16. Cap all text R1 scans (hosts, paths, headers, bodies, DNS names) at 24 MiB in total. |
| SR-5 | Low | `schema.ts` environment checks | Unsafe configuration | `tmpDirs: ["/"]`, or `nodeModulesDir === projectDir`. | Every write is allowed, so a home-directory write or a planted workflow gets **SAFE**. The environment comes from our own runner, not from the package, so this is defence in depth. | Reject temp directories that are `/` or contain `home` or `projectDir`. Require `nodeModulesDir` to be strictly inside `projectDir`, and `home` not to be `/`. |
| SR-6 | Low | `programs.ts` `PM_SCRIPTS` | Prototype lookup | `node __proto__ publish`. A plain-object lookup with a package-chosen key returns `Object.prototype`. | It over-blocks (R7 fires with a garbled name). It's not a bypass, but it's wrong. | Use a `Map`. |

## Fallback audit

| Location | Path | Ends in |
|---|---|---|
| `verdict.ts` `judgeWith` catch | any exception | **block** (ERROR) |
| `verdict.ts` | validation fails, no exec events, truncated and empty, bad evidence | **block** (ERROR) |
| `schema.ts` `validateScanInput` | zod failure, or too many events | **block** (ERROR) |
| `hosts.ts` `normaliseHost` → null | malformed host or IP | **block**: never allowlisted, so R3 is High |
| `hosts.ts` `canonicalIp` → null | odd IP form | **block**: counted as external, R3 |
| R7 and R8, `host === null` → `continue` | malformed Host header to the registry or GitHub | **block** through R3 (High), not R7/R8 (Critical). Accepted: still blocked. |
| `programs.ts` busybox with an empty `argv[1]` | `programName` returns `busybox` | allow, but nothing runs |
| `programs.ts` `packageManagerCall` → null | `node -e …` | allow for R7. Child processes are traced separately. |
| `context.ts` `lastSeq ?? 0` | only read when there are events | n/a |
| `r09-wiper.ts` `example ?? ""` | display only | n/a |

## Checked and clean

- **ReDoS:** every regular expression is anchored, with no ambiguous nested quantifiers (`HOST_NAME` repeats a group that must start with `.`). Lengths are checked before host regexes run. Matching uses `indexOf`.
- **Output safety:** every untrusted value in a finding goes through `ctx.show()` (honeytokens redacted case-insensitively, then `quote()`). Validation reasons contain only field paths and issue codes. Property 8 checks for leaked tokens over generated inputs.
- **Determinism:** no clock, randomness, or I/O, enforced by tsconfig and Biome. Order-independence and copy-equality hold (Property 1, 5,000 runs × 3 seeds).
- **Fail closed:** Property 2 (never throws, for `fc.anything()`, including null-prototype objects, Maps, Sets, and BigInts) passes.
- **Cache key:** injective (Property 9). Only SHA-512 SRI is accepted.
- **Prototype pollution:** untrusted keys only go into `Map`s, except SR-6.
- **Skipped (not applicable):** process execution, Docker, tarballs, HTTP routes, and dependencies. zod 4.6.7 (MIT, no install scripts) is the only new dependency.

## Questions

- A dropped script run by an interpreter (`node ~/.cache/stage2.js`) isn't R4, because R4 only covers executables. The script's own behaviour is still traced by every other rule, so this isn't a bypass of detection. It's noted for the blue-team pass.

## Fix status

| ID | Status |
|---|---|
| SR-1 | Fixed: `/proc` root aliases canonicalised, `cwd` tails checked against home and project. Tests: `review regressions` in `rules/rules.test.ts`. |
| SR-2 | Fixed: path views through earlier links in `context.ts`, used by R2, R4, R5, R6, R7, and R8. Tests as above. |
| SR-3 | Fixed: R3 flags sink connects on unrecorded ports. Test as above. |
| SR-4 | Fixed: `MAX_HONEYTOKENS = 16`, `MAX_TOTAL_SCANNED_TEXT = 24 MiB`. Test in `schema.test.ts`. |
| SR-5 | Fixed: environment refinements. Tests in `schema.test.ts`. |
| SR-6 | Fixed: `Map`. Test in `rules/rules.test.ts`. |

## Independent review (new session, `sandbox-reviewer` agent, 2026-11-18)

A second review, run in a separate session with fresh context, gave **FAIL on one Medium finding**. It found no wrong-SAFE verdict, and it confirmed that the fixes for SR-1, SR-2, SR-3, SR-5, SR-6, and the blue-team cards are correct.

| ID | Severity | Location | Class | Trigger | Impact | Fix |
|---|---|---|---|---|---|---|
| SR-7 | Medium | `views.ts` (introduced by the SR-2 fix) | Resource exhaustion | A self-referential symlink (`/tmp/x -> /tmp/x/x`) plus many reads of ~4 KB paths through it took **minutes**. Follow-up: with *any* symlink in the trace, every long path cost about 51 ms. | One package could tie up a scan worker. Both earlier reviews missed it. | (1) Walk with persistent linked lists and a link-name trie, so no step copies data. (2) A per-path work budget and a budget shared by the whole trace. (3) A fast path: a path with no `.`/`..` and no link prefix isn't walked at all. (4) Roots split once, and each path split once per check. When a budget runs out, the views are incomplete: writes through them are forbidden, and **R13 reports it** (High), so running out can't help a package. |

**After the fix** (4,000 reads of ~4 KB paths): one unrelated link took 1.36 s (SAFE), a self-link 1.30 s, `..`-heavy paths 1.08 s, and 10,000 chained links 1.33 s (all three SUSPICIOUS through R13). Regression tests: "review regressions" in `rules/rules.test.ts`, with timeouts.

Lesson: the SR-2 fix closed a bypass and opened a denial of service. A reviewer with fresh context caught what the fixing author couldn't see.
