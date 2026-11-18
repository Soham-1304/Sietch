# Security review: trace normaliser (commit `c4854ca`)

**Date:** 2026-11-18. **Who:** the `sandbox-reviewer` agent in a fresh session, using `security-review` and `blue-team`. It formed its own attack list before reading the tests. **Verdict: FAIL** (1 High, 1 Medium, 2 Low). Fixes are in the next commit.

| ID | Severity | Finding | Fix |
|---|---|---|---|
| TN-1 | **High** | `cwdOf()` searched a record's arguments for `AT_FDCWD ` anywhere. An `execve` whose program path contained it (`/opt/AT_FDCWD /evil`) overwrote the tracked working directory. A later relative exec of a dropped file (`./mal`) was then recorded at the wrong path, so R4 missed "ran a file it dropped". | **Fixed.** The working directory is read only from the leading dirfd of syscalls that have one (`openat`, `mkdirat`, `unlinkat`, `renameat`, `renameat2`, `linkat`, `fchmodat`, `execveat`), and only after the record's arguments were split unambiguously. Tests: `trace.test.ts` "TN-1" (the path doesn't move the cwd), and `trace.prop.test.ts` "TN-1" (R4 still fires end to end). |
| TN-2 | Medium | The trace doesn't show the socket type, so every `connect` is labelled `tcp`. R3 allows TCP to the sink on 53, 80, and 443, so a UDP (QUIC) send to the sink on 443 would be treated like HTTPS, and its payload would go unseen. | **Closed in the sandbox, not the engine.** New sandbox-runner contract item: the capture sink and the sandbox network accept UDP **only on port 53** (DNS), and drop all other UDP. Such a packet then reaches nothing. A test pins today's verdict so a change is noticed. Tracing `socket` to learn the type remains a later improvement. |
| TN-3 | Low | `waitid` reaps aren't turned into exits (the format hasn't been seen yet), so a process reaped only that way looks lingering, and R10 over-fires. | Documented. The direction is safe (it can only add a finding). Parse it once a real sample exists. The `clone3` and `sendto` guesses are in the same class and fail safe. |
| TN-4 | Info | A path with a control character (such as a newline) makes the scan ERROR, because the engine refuses such paths. | Intended (fail closed), and tested. |

**Checked and clean:** JSON framing, the comm marker window, end-anchored result parsing, separator counting for every syscall, execve argv/envp splitting (envp discarded), connect family parsing (`AF_UNIX` with a fake `{Family: AF_INET…}` is ignored), threads versus processes, PID reuse, exits, ReDoS, and error texts (codes and line numbers only).

**Open questions:** the real `sendto`, `waitid`, and `clone3` formats, and the x86-64 formats. To be recorded on the cloud VM.
