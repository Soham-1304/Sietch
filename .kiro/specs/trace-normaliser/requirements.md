# Requirements Document

## Introduction

The trace normaliser turns gVisor's raw syscall log into the `ScanInput.events` list that the rules engine judges. It is step 4 of the scan pipeline ("tidy the notes"). It lives in `base/core`, and it is pure: it takes the log text and the runner's layout as data, and returns events or a typed error. It never reads files, runs programs, or uses the clock.

The log was produced while hostile code was running, so it contains attacker-chosen text: file names, process names, and argument strings. The normaliser must never let that text create, hide, or change events. When it can't be certain, it fails, and the scan becomes ERROR, which blocks.

Sources: `docs/spikes/spike-1-recording.md`, `docs/spikes/trace-sample.md`, and the "Contract for the trace producer" in `.kiro/specs/rules-engine/design.md`.

Out of scope: running the sandbox, the capture sink (which produces `dns` and `http` events), and gVisor runtime monitoring.

## Glossary

- **Normaliser**: `normaliseTrace(log, layout)` in `base/core`.
- **Record**: one line of gVisor's JSON debug log (`--debug-log-format=json`).
- **Strace message**: a record whose `msg` starts with `strace.go:<n>] `.
- **Layout**: data from the sandbox runner: the init pid, the order of the init process's children (install, load), and limits.
- **Runner process**: the container's init process and any of its direct children other than the install and load processes (for example the observation-window timer).
- **Incomplete**: the normaliser saw something it can't fully interpret, but a correct result is still possible. It sets a flag that rule R13 reports.

## Requirements

### Requirement 1: Safe framing

**User Story:** As a security engineer, I want each log record read exactly as gVisor wrote it, so that a file name with a newline can't forge an event.

#### Acceptance Criteria

1. THE Normaliser SHALL split the log on newline characters and parse every non-empty line as JSON.
2. IF any non-empty line is not a JSON object with a string `msg`, THEN THE Normaliser SHALL fail with `UNFRAMED_RECORD`.
3. THE Normaliser SHALL ignore records whose `msg` doesn't start with `strace.go:<digits>] `.
4. IF the log is larger than the size limit in the design, or has more records than the record limit, THEN THE Normaliser SHALL fail with `TRACE_TOO_LARGE`.

### Requirement 2: Unambiguous parsing

**User Story:** As a security engineer, I want parsing to fail rather than guess, so that crafted names can't make one call look like another.

#### Acceptance Criteria

1. THE Normaliser SHALL parse the prefix `[<tgid>: <tid>] <comm> <E|X> <syscall>(` and find the ` E ` or ` X ` marker within the first 16 characters after `] `. IF there is no such position, or more than one, THEN it SHALL fail with `AMBIGUOUS_RECORD`.
2. THE Normaliser SHALL use only exit (`X`) records, except for `exit_group`, where the enter (`E`) record also counts as the process ending.
3. THE Normaliser SHALL parse the result suffix `) = <ret> (<hex>|errno=<n> (<text>)) (<duration>)` from the end of the message, and SHALL fail with `MALFORMED_RECORD` if it's missing on an exit record.
4. FOR each supported syscall, THE Normaliser SHALL locate every argument using separators that can't come from attacker text, or, where they can, SHALL require exactly one way to split the arguments. Otherwise it SHALL fail with `AMBIGUOUS_RECORD`.
5. THE Normaliser SHALL keep attacker strings exactly as printed, including gVisor's octal escapes. It SHALL NOT decode them.

### Requirement 3: Supported syscalls and events

**User Story:** As the rules engine, I want each relevant syscall turned into the right event.

#### Acceptance Criteria

1. THE Normaliser SHALL turn successful `execve` and `execveat` into `exec` events, with the path and argv.
2. THE Normaliser SHALL turn successful `openat` into `file_read` when the access mode is read-only, and into `file_write` otherwise: `truncate` when `O_TRUNC` is set, `create` when `O_CREAT` is set (without `O_TRUNC`), and `write` otherwise.
3. THE Normaliser SHALL turn successful `mkdirat`, `unlinkat` (`delete`), `renameat` and `renameat2` (`rename`, with a target), `symlinkat` (`symlink`, with a target), `linkat` (`hardlink`, with a target), and `fchmodat` (`chmod`) into `file_write` events.
4. THE Normaliser SHALL turn `connect` into a `connect` event, whether or not it succeeded, for `AF_INET` and `AF_INET6`. It SHALL ignore `AF_UNIX`.
5. WHEN `sendto` or `sendmsg` names a destination address that the log doesn't show, THE Normaliser SHALL emit a `connect` event with an unknown address.
6. THE Normaliser SHALL emit one `exit` event per process: at its `exit_group`, or when a `wait4` or `waitid` returns its pid, whichever comes first.
7. THE Normaliser SHALL ignore syscalls it doesn't use, but SHALL fail with `UNEXPECTED_SYSCALL` for a syscall outside the configured trace list.

### Requirement 4: Paths

**User Story:** As the rules engine, I want absolute paths, so that path rules work.

#### Acceptance Criteria

1. WHEN a path is relative, THE Normaliser SHALL join it to the working directory printed with `AT_FDCWD`.
2. IF a path argument is relative to a directory file descriptor other than `AT_FDCWD`, and the log doesn't print that directory, THEN THE Normaliser SHALL fail with `UNRESOLVED_PATH`.
3. THE Normaliser SHALL NOT resolve symlinks. The rules engine does that.
4. IF a path is printed as cut off, THEN THE Normaliser SHALL fail with `TRUNCATED_PATH`.

### Requirement 5: Processes and attribution

**User Story:** As the rules engine, I want correct pids, parents, and phases, so that the package manager's own behaviour can be told apart.

#### Acceptance Criteria

1. THE Normaliser SHALL use the thread group id (the first number in `[tgid: tid]`) as `pid`.
2. THE Normaliser SHALL record a process's parent from the first successful `clone`, `clone3`, `fork`, or `vfork` that created it, ignoring clones that create threads.
3. THE Normaliser SHALL identify the install and load processes as the init process's first and second non-thread children, in clone order, as given by the Layout.
4. THE Normaliser SHALL assign phases: `install` until the install process exits, `load` until the load process exits, and `linger` after that.
5. THE Normaliser SHALL drop events from runner processes. It SHALL keep events from every descendant of the install and load processes.
6. IF the install or load process never appears, THEN THE Normaliser SHALL fail with `MISSING_PHASE`.
7. THE Normaliser SHALL report the install process's pid as `packageManagerPid`.

### Requirement 6: Output and completeness

**User Story:** As the scan worker, I want the output ready to pass to `judge()`.

#### Acceptance Criteria

1. THE Normaliser SHALL return `{ ok: true, events, packageManagerPid, eventsTruncated, argvTruncated }` or `{ ok: false, code, reason }`. It SHALL NOT throw.
2. THE Normaliser SHALL number events with consecutive `seq` values in record order, and SHALL set `t` to milliseconds since the first strace record.
3. WHEN more events than the engine's limit would be produced, THE Normaliser SHALL keep the first ones and set `eventsTruncated`.
4. WHEN an `execve` argument list is printed as cut off, THE Normaliser SHALL keep what was printed and set the event's `argvTruncated` flag, which R13 reports.
5. THE `reason` SHALL name the record number and the problem without copying attacker text.

### Requirement 7: Rules engine changes

**User Story:** As a security engineer, I want the engine to judge what the normaliser can't fully see.

#### Acceptance Criteria

1. THE rules engine SHALL accept `connect.address` as `null`, meaning "not recorded", and R3 SHALL treat it as an external destination.
2. THE rules engine SHALL accept an optional `argvTruncated` flag on `exec` events, and R13 SHALL report it (High).
3. THE `RULESET_VERSION` SHALL be bumped.

### Requirement 8: Determinism and safety

#### Acceptance Criteria

1. THE Normaliser SHALL return the same result for the same input.
2. FOR any input string, THE Normaliser SHALL return a result and SHALL NOT throw.
3. THE Normaliser SHALL run in time linear in the log size, with no backtracking regular expressions on attacker text.
