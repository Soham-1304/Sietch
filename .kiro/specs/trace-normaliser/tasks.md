# Implementation Plan

All code is in `base/core/src/trace/` (pure, like the rest of `base/core`). Property tests are required. Run `/security-review` on the result before committing, because the input is attacker-shaped.

- [ ] 1. Close the open questions in the VM
  - Extend `demo/trace-sample/probe.sh` with: a 4,096-byte path, an `execve` with 600 arguments, and a UDP `sendto` (node `dgram` with an explicit address). Record what gVisor prints for each. Add the results to `docs/spikes/trace-sample.md`.
  - Refresh the fixture `__fixtures__/gvisor/sample-arm64.strace.jsonl`.
  - _Requirements: 4.4, 6.4, 3.5_

- [ ] 2. Rules engine changes
  - `connect.address` may be `null`, and R3 flags it. `exec.argvTruncated` is optional, and R13 flags it. `RULESET_VERSION` becomes `1.2.0`. Unit tests for both. All existing tests stay green.
  - _Requirements: 7.1, 7.2, 7.3_

- [ ] 3. Framing and timestamps (`trace/frame.ts`)
  - Size and record limits, JSON per line, keep `strace.go` records, pure RFC 3339 parser.
  - Unit tests: a non-JSON line, a JSON array, a missing `msg`, an empty middle line, a huge input, a bad time.
  - _Requirements: 1.1–1.4, 6.2_

- [ ] 4. Record parsing (`trace/record.ts`)
  - Prefix, comm window, E/X, syscall name, result suffix scanner (no regex on attacker text).
  - Unit tests: every line kind in the fixture, plus a comm containing ` X openat(`, and a comm with a newline.
  - [ ] 4.1 Property tests: **Property 3** (comm can't move the split). **Validates: 2.1**
  - _Requirements: 2.1–2.3_

- [ ] 5. Argument parsers (`trace/syscalls.ts`)
  - One parser per syscall in the design table, each counting its possible splits. A quoted-list scanner for argv. Discard envp.
  - Unit tests per syscall, plus ambiguity cases: a cwd named `a, 0x1 /etc`, a path ending in `, O_RDONLY, 0o0`, a symlink target containing `, AT_FDCWD /x, 0x1 `, and an execve path containing `, 0x1 ["x"]`.
  - [ ] 5.1 Property tests: **Property 2** (framing can't be forged), **Property 4** (argument text can't add or change fields), **Property 8** (linear time). **Validates: 1.1, 1.2, 2.4, 3.2, 8.3**
  - _Requirements: 2.4, 2.5, 3.1–3.5, 3.7, 4.1–4.4_

- [ ] 6. Checkpoint: `pnpm check` passes.

- [ ] 7. Processes, exits, roles, and phases (`trace/processes.ts`)
  - Parent table from non-thread clones, roles from init's first two children, inheritance, runner-process dropping, one exit per lifetime (exit_group, or wait4/waitid), phases.
  - Unit tests: a killed child reaped by wait4, PID reuse, an orphan whose parent exited, a thread clone, a missing load child (`MISSING_PHASE`).
  - [ ] 7.1 Property test: **Property 7** (one exit per lifetime). **Validates: 3.6, 5.2**
  - _Requirements: 3.6, 5.1–5.7_

- [ ] 8. `normaliseTrace` and output (`trace/index.ts`)
  - Wire the stages, seq and t, `MAX_EVENTS` truncation, error codes and reasons. Export from `base/core/src/index.ts`.
  - [ ] 8.1 Property tests: **Property 1** (never throws), **Property 5** (deterministic), **Property 6** (output is valid engine input). **Validates: 6.1, 8.1, 8.2**
  - _Requirements: 6.1–6.5, 8.1, 8.2_

- [ ] 9. Golden and end-to-end tests
  - The real fixture gives the expected events for the interesting lines (see the design's Testing strategy).
  - Fixture to `normaliseTrace` to `judge()` doesn't give ERROR, and R2 fires for `/home/probe/.npmrc`.
  - _Requirements: 3.1–3.6, 5.3–5.5_

- [ ] 10. Review and docs
  - `/security-review` and `/blue-team` on `base/core/src/trace/`. Then an independent `sandbox-reviewer` run in a new session. Fix every Critical, High, and Medium finding.
  - Update `base/core/README.md` (public API and the runner layout contract), `docs/build-log.md`, and `docs/checklist.md`.
