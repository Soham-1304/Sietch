# Spike 1: can we record a package's behaviour from outside the sandbox?

**Date:** 2026-11-18. **Result: yes.** gVisor's built-in syscall trace records what we need, including the work of a detached child process after its parent has exited, and package code can't reach it.

## Setup

- **VM:** Colima 0.10.3 profile `sietch` (Apple Virtualization, aarch64, 2 CPUs, 4 GiB). Started with `--mount none`, so **no Mac folder is visible inside the VM**, and `--activate=false`, so Docker Desktop stays the default context. Ubuntu, kernel 6.8.
- **gVisor:** `runsc release-20261116.0`, installed from the signed apt repository (key fingerprint `6F1D F85E 3A71 C249 18E7 27D5 6FC6 D554 E32B D943`). The direct-download URLs from older guides return 404 since gVisor's 2026 packaging change, so the apt repo or the `gvisor.tar.zstd` tarball is now the way to install it.
- **Probe:** `demo/spike1-probe/`. A harmless parent reads a fake `.npmrc`, starts a detached child, and exits. 1.5 s later the child reads the file again, runs `/bin/sh` (a grandchild), and tries to connect to `192.0.2.10:443` (TEST-NET-1, never routed). The files were copied into the VM over `colima ssh` and their SHA-256 checksums matched.
- **Container settings:** `--runtime=runsc-trace-min --network none --read-only --tmpfs /tmp --tmpfs /home/probe --user 1000:1000 --cap-drop=ALL --security-opt no-new-privileges --memory 256m --pids-limit 64 --cpus 1`.
- **Tracing runtime:**
  ```sh
  sudo runsc install --runtime runsc-trace-min -- \
    --strace --strace-syscalls=execve,execveat,openat,unlinkat,renameat,renameat2,symlinkat,linkat,fchmodat,mkdirat,connect,sendto,sendmsg,clone,clone3,exit_group \
    --strace-log-size=512 --debug --debug-log=/var/log/runsc/%ID%/
  ```

## What the trace showed

| Question | Answer | Evidence (from the `*.boot.txt` log) |
|---|---|---|
| Is the detached child's file read seen after the parent exits? | **Yes** | Parent (pid 3) read `.npmrc` at 03.799 and exited at 03.953. The child (pid 10) read it again at **05.571**. |
| Is a grandchild process and its arguments seen? | **Yes** | `[18:18] X execve(/bin/sh, ["/bin/sh", "-c", "echo grandchild-ran > /tmp/marker"], …)` |
| Are network attempts seen, with address and port? | **Yes** | `[10:10] X connect(…{Family: AF_INET, Addr: 192.0.2.10, Port: 443}…) = -1 errno=101` |
| Can we build the process tree? | **Yes** | Each line starts `[tgid: tid]`. `clone` results give parent to child (pid 3 to 10, pid 10 to 18). Threads (node's worker threads, pids 11–15) have to be dropped using `CLONE_THREAD`. |
| Is every exit seen? | **Yes** | One `exit_group` per process (3, 10, 18, …). |
| Are paths absolute? | **Yes** | `openat(AT_FDCWD /, … /home/probe/.npmrc …)` shows the cwd and the path. |
| Are results visible, to skip failed calls? | **Yes** | Each `X` (exit) line carries `= <value>` or `= -1 errno=…`. The shell's `PATH` search shows several failed `execve` calls before the real one. |
| Can the package reach or switch off the recorder? | **No** | The trace is written by the gVisor kernel (the Sentry) to `/var/log/runsc/<id>/` on the VM, outside the container. Package code only ever talks to the Sentry. Turning it off would mean breaking out of gVisor. |
| How big is it? | **Small with a filter** | Unfiltered: 15,926 trace lines (2.5 MB) for this tiny probe. With the syscall filter: **174 lines**. |

## Decisions

1. **Recording method: gVisor `--strace` with a syscall filter**, written to a per-container log directory. It needs no extra tooling.
2. **The syscall list depends on the CPU architecture.** ARM64 has no `open`, `creat`, `unlink`, `rename`, `symlink`, `link`, `chmod`, or `fork`, and naming one makes the sandbox **fail to start**. The first filtered run failed for exactly this reason. The x86-64 VM list must add those legacy syscalls. The runner picks the list by architecture, and a sandbox that fails to start is an ERROR verdict (fail closed).
3. **The normaliser parses text lines.** It must:
   - use `tgid`, not `tid`, as the pid (matching contract item 1 in the rules-engine design),
   - use `clone` results without `CLONE_THREAD` for ppid,
   - keep only successful calls,
   - treat any line it can't parse as a scan **error**, never skip it.
4. **gVisor runtime monitoring** (`--pod-init-config`, structured events) is the upgrade path if text parsing turns out fragile. It isn't needed for P0.

## Things the next specs must handle

- **The trace contains honeytokens in full.** `execve` lines include the environment (`envp`), and our fake tokens are in it. Raw trace files must stay on the worker's disk, be deleted after normalising, and never be served by the API or the dashboard. Only normalised events, with redacted findings, leave the worker.
- **`strace-log-size` caps captured buffers at 512 bytes,** which covers argv and env previews. Socket payloads are captured by the capture sink, not by strace.
- **Clean up `/var/log/runsc/<id>/`** after each scan. Logs stay behind when the container is removed.
- **The `%ID%` placeholder becomes `<unknown>`** for runsc commands that run without a container (such as `features`), so per-scan files must be picked by container ID.
- **`--debug` adds a lot of non-strace output.** Check whether strace lines still appear without it, to shrink the logs.
- **Not covered here:** the capture sink (DNS, HTTP, and HTTPS bodies), and timing with a real `npm install`. Those belong to the `sandbox-runner` spec.

## Reproduce

```sh
colima start --profile sietch --vm-type vz --cpu 2 --memory 4 --disk 20 --mount none --activate=false --runtime docker
# install runsc from the apt repo (see https://gvisor.dev/docs/user_guide/install/), then the runtime above
colima ssh -p sietch -- mkdir -p probe
for f in parent.js child.js run-in-vm.sh; do colima ssh -p sietch -- sh -c "cat > probe/$f" < demo/spike1-probe/$f; done
colima ssh -p sietch -- sh probe/run-in-vm.sh
colima stop -p sietch   # when done
```
