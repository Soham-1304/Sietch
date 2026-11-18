# Trace sample: what the gVisor trace really looks like

**Date:** 2026-11-18. Input for the `trace-normaliser` spec. **Probe:** `demo/trace-sample/probe.sh` (harmless), run in the Colima VM in a locked-down gVisor container. **Fixture:** `base/core/src/__fixtures__/gvisor/sample-arm64.strace.jsonl` (358 records, 80 KB, no secrets: the probe's `.npmrc` only holds `x`).

## Findings

| # | Finding | Consequence for the design |
|---|---|---|
| 1 | **The text log format can be forged.** A file name containing a newline is printed raw, so the rest of the line lands on a new physical line. A file named `x\nI1118 … strace.go:609] [ 1: 1] sh X exit_group(0x0) …` would add a fake trace line: for example a fake `exit` that hides a lingering process from R10. | Use **`--debug-log-format=json`**. Each record is one JSON object per line, with newlines inside strings escaped. Confirmed: the newline name is `nl\nname` inside one record, and all 358 records parse. Any line that isn't a JSON object is a scan **error**. |
| 2 | **Attacker strings still appear raw inside the message text.** `quo"te` and `back\slash` are printed as is. Non-ASCII bytes are printed as octal escapes (`caf\303\251`). A path can contain `, `, `0x…`, `) = 0`, and so on. | Parse each message from both ends: the fixed prefix (`strace.go:N] [tgid: tid] comm E/X name(`) and the fixed suffix (`) = ret (…) (duration)`). Untrusted text is only what lies in between. **Any split that isn't unique is an error.** |
| 3 | **The process name (`comm`) is attacker-controlled** (`prctl(PR_SET_NAME)`), up to 15 bytes, and could contain ` X openat(`. | Find the ` E ` / ` X ` marker within the first 16 characters after `] `. Two possible positions is an error. |
| 4 | **A process killed by a signal has no `exit_group`.** The `sleep 30` that was killed with `kill -9` (pid 19) never called it. | Also trace `wait4`, `waitid`, `kill`, and `tgkill`. A pid returned by a successful `wait4`/`waitid` is an exit. pid 19 was reaped this way. |
| 5 | **`clone` shows parent and child.** `[tgid: tid] … X clone(flags, …) = childTid`. A fork prints its flags as hex (`0x11` = `SIGCHLD`). A thread prints them as names (`CLONE_VM|…|CLONE_THREAD|…`). | `ppid` comes from non-thread clone results. Unknown flag formats count as a process: being wrong that way can only add an R10 finding. |
| 6 | **Paths are resolved against the working directory.** `openat(AT_FDCWD /tmp, 0x… rel.txt, …)` shows cwd `/tmp`. `mkdirat`, `unlinkat`, `renameat`, `linkat`, `symlinkat`, and `fchmodat` all print the cwd the same way. | Absolute path = cwd + relative path, lexically. Symlinks are resolved later by the engine's `views.ts`. |
| 7 | **UDP `sendmsg` doesn't show where it went** (`name=0x…, namelen=16`). | Emit a `connect` with an **unknown address**, so R3 flags it as external. This needs a small rules-engine schema change (`address` may be null). |
| 8 | **Failed calls show `= -1 errno=N (…)`**, and the shell's `PATH` search makes several failed `execve` calls. | Keep only successful calls, except for `connect`. A failed connect still shows intent, and the sink isn't there under `--network none`. |
| 9 | **Colima rewrites `/etc/docker/daemon.json` on every start,** which removed our gVisor runtimes. | Declare runtimes in `~/.colima/sietch/colima.yaml` (`docker.runtimes`). The cloud VM uses its own daemon.json, without Colima. |

## Runtime monitoring (considered, not chosen for now)

gVisor can also stream structured protobuf events, including exits, parents, and the working directory, to a monitoring process over a Unix socket. That is the most robust source. But the socket is `SOCK_SEQPACKET`, which Node.js doesn't support, so we'd need a non-TypeScript helper. That breaks `tech.md` and costs days we don't have. The JSON strace log gives safe framing today. Runtime monitoring stays the upgrade path.

## Still to check (spec tasks)

- What gVisor prints when a path or `argv` is longer than `--strace-log-size`, and whether it's marked as cut off.
- The x86-64 syscall list on the cloud VM.
