# Requirements Document

## Introduction

The rules engine is the decision-maker of Sietch. It takes a recorded trace of what a package did inside the sandbox (processes, file access, network) and returns a verdict (SAFE, SUSPICIOUS, MALICIOUS, or ERROR), where every finding cites the exact events that caused it.

It lives in `base/core` and is a pure function: no file system, network, clock, or randomness. The same input always gives the same verdict. Both apps (Registry Gate and Agent Guard) reuse it through the base.

Everything in the trace was caused by hostile code, so the engine treats all of it as attacker-controlled data, validates it strictly, and fails closed.

Source: `docs/plan.md` sections 5.1, 5.3, 5.4, 5.5, 5.6. Out of scope: parsing raw syscall logs (depends on Spike 1), anything that runs packages, and rules R11 and R12 (static analysis).

## Glossary

- **Rules_Engine**: the `judge` function in `base/core` and the modules it uses.
- **Scan_Input**: the data passed to the Rules_Engine: package identity, sandbox environment, allowlist, honeytokens, and events.
- **Event**: one normalised record of behaviour: `exec`, `file_read`, `file_write`, `connect`, `dns`, `http`, or `exit`.
- **Phase**: when an event happened. `install` (lifecycle scripts running), `load` (the package being required and imported), or `linger` (after both finished, during the observation window).
- **Package_Manager_Process**: the npm process that runs the install. It reads config such as `~/.npmrc` and writes the lockfile legitimately.
- **Package_Event**: any event not made by the Package_Manager_Process during the `install` phase. Events with no process ID (`dns`, `http`) are always Package_Events.
- **Honeytoken**: a fake credential planted in the sandbox for one scan.
- **Allowlist**: host patterns a package may contact, such as `registry.npmjs.org` or `*.githubusercontent.com`.
- **Finding**: a rule match with a rule ID, a severity, an explanation, and evidence.
- **Evidence**: the sequence numbers (`seq`) of the events that caused a finding.
- **Severity**: `Low` < `Medium` < `High` < `Critical`.
- **Verdict**: `SAFE`, `SUSPICIOUS`, `MALICIOUS`, or `ERROR`. Only `SAFE` allows an install.
- **Ruleset_Version**: the version string of the rules, owned by the Rules_Engine.
- **Allowed_Write_Roots**: `nodeModulesDir`, the temp directories, `~/.npm`, `~/.cache`, `~/.node-gyp`, and the harmless devices `/dev/null`, `/dev/stdout`, `/dev/stderr`, `/dev/tty`, `/dev/pts/*`.

## Requirements

### Requirement 1: Validate the scan input

**User Story:** As a security engineer, I want the engine to reject anything malformed, so that a trace shaped by hostile code can't confuse the rules.

#### Acceptance Criteria

1. THE Rules_Engine SHALL validate the Scan_Input against a strict schema that rejects unknown fields, unknown event types, and values of the wrong type.
2. THE Rules_Engine SHALL reject a Scan_Input whose events contain a duplicate `seq`.
3. THE Rules_Engine SHALL reject any event path, environment directory, or link target that is not an absolute path, or that contains a NUL or other control character.
4. THE Rules_Engine SHALL reject a Scan_Input that exceeds any size limit in the design (number of events, string lengths, header counts, body sizes, total body size, number of honeytokens, allowlist entries).
5. THE Rules_Engine SHALL reject honeytoken values that are not printable ASCII, are shorter than 16 or longer than 512 characters, or are duplicated.
6. THE Rules_Engine SHALL reject a Scan_Input where `nodeModulesDir` is not inside `projectDir`.
7. THE Rules_Engine SHALL reject a `dns` or `http` event that carries a process ID, and a process event (`exec`, `file_read`, `file_write`, `connect`, `exit`) that lacks one.
8. WHEN validation fails, THE Rules_Engine SHALL return an ERROR verdict whose reason names the failing field and the problem, without copying the offending value.

### Requirement 2: Fail closed

**User Story:** As a security engineer, I want every unexpected condition to block the package, so that malware can't get a SAFE verdict by breaking the scan.

#### Acceptance Criteria

1. IF the Rules_Engine hits any internal error while judging, THEN THE Rules_Engine SHALL return an ERROR verdict and SHALL NOT throw.
2. IF a Scan_Input has no `exec` event, THEN THE Rules_Engine SHALL return an ERROR verdict, because the recording almost certainly failed.
3. IF `eventsTruncated` is true and the event list is empty, THEN THE Rules_Engine SHALL return an ERROR verdict.
4. THE Rules_Engine SHALL provide `errorVerdict(reason)` so that callers can record a failed or timed-out scan as ERROR.
5. THE Rules_Engine SHALL provide `allowsInstall(verdict)`, which returns true only for a SAFE verdict.

### Requirement 3: Attribute events

**User Story:** As a security engineer, I want the package manager's own normal behaviour ignored, so that every package isn't flagged for npm reading `~/.npmrc`.

#### Acceptance Criteria

1. THE Rules_Engine SHALL treat an event as a Package_Event unless it was made by the Package_Manager_Process during the `install` phase.
2. THE Rules_Engine SHALL apply rules R2 to R6, R9, and R10 to Package_Events only.
3. THE Rules_Engine SHALL apply rules R1, R7, and R8 to all events, including those of the Package_Manager_Process.
4. THE Rules_Engine SHALL process events in ascending `seq` order, whatever their order in the input array.

### Requirement 4: Detect honeytokens in any supported encoding

**User Story:** As a security engineer, I want stolen fake credentials recognised even when encoded, so that simple obfuscation can't hide theft.

#### Acceptance Criteria

1. WHEN a honeytoken value appears in a text, THE Honeytoken_Matcher SHALL report the honeytoken's ID and the encoding.
2. THE Honeytoken_Matcher SHALL detect the value raw, as hexadecimal (either case), as base64 (standard or URL-safe alphabet, with or without padding, at any byte alignment inside a larger encoded payload), and as double base64 (base64 of base64).
3. THE Honeytoken_Matcher SHALL also detect each of those encodings after one or two rounds of percent-decoding of the text.
4. THE Honeytoken_Matcher SHALL ignore whitespace inside base64 text, so that line-wrapped base64 is still detected.
5. THE Honeytoken_Matcher SHALL run in time linear in the text length for a fixed set of honeytokens, with no backtracking regular expressions.

### Requirement 5: Rule R1, honeytoken exfiltration (Critical)

**User Story:** As a security engineer, I want any fake credential leaving the sandbox flagged as malicious, because no legitimate package sends a developer's tokens anywhere.

#### Acceptance Criteria

1. WHEN a honeytoken is detected in an `http` event's host, path, header names or values, or body, THE Rules_Engine SHALL produce a Critical R1 finding citing that event.
2. WHEN a honeytoken is detected in a `dns` event's name, with or without the dots, THE Rules_Engine SHALL produce a Critical R1 finding citing that event.
3. THE Rules_Engine SHALL apply R1 to allowlisted hosts as well.

### Requirement 6: Rule R2, credential access (High)

**User Story:** As a security engineer, I want reads of credential stores flagged, so that a stealer is caught even if its exfiltration fails or is hidden.

#### Acceptance Criteria

1. WHEN a Package_Event reads a credential path, THE Rules_Engine SHALL produce a High R2 finding citing that event.
2. WHEN a Package_Event creates a symlink or hardlink whose target is a credential path, THE Rules_Engine SHALL produce a High R2 finding citing that event.
3. THE credential paths SHALL be: inside `home`, the entries `.npmrc`, `.yarnrc`, `.yarnrc.yml`, `.config/gh`, `.git-credentials`, `.netrc`, `.aws`, `.ssh`, `.docker/config.json`, `.kube`, `.config/gcloud`, `.azure`, `.gnupg`, `.pypirc`, `.bash_history`, and `.zsh_history` (the entry itself or anything inside it); `/proc/<any>/environ` and `/proc/<any>/mem`; any file named `.env` or `.env.<suffix>` outside `nodeModulesDir`; and every path in `extraCredentialPaths`.

### Requirement 7: Rule R3, unexpected network destinations (High)

**User Story:** As a security engineer, I want contact with unknown hosts flagged, so that exfiltration and payload downloads are visible.

#### Acceptance Criteria

1. WHEN a `dns` event queries a name that doesn't match the Allowlist, THE Rules_Engine SHALL produce a High R3 finding.
2. WHEN an `http` event's host doesn't match the Allowlist, THE Rules_Engine SHALL produce a High R3 finding.
3. WHEN a Package_Event `connect` targets an address that is not a sink address, not loopback, and not on the Allowlist, THE Rules_Engine SHALL produce a High R3 finding.
4. THE Rules_Engine SHALL match a host against an Allowlist pattern only if the normalised host equals the pattern, or the pattern is `*.<suffix>` and the host ends with `.<suffix>` with at least one label before it.
5. THE Rules_Engine SHALL normalise hosts by lowercasing them and removing a trailing dot and a port. A host that can't be normalised SHALL be treated as not allowlisted.

### Requirement 8: Rule R4, running new executables (High)

**User Story:** As a security engineer, I want packages that drop and run a binary or an alternative runtime flagged, because that is how Shai-Hulud 2.0 avoided Node-level monitoring.

#### Acceptance Criteria

1. WHEN a Package_Event executes a path that a Package_Event created, wrote, or renamed into earlier in the trace, and that path is outside `nodeModulesDir`, THE Rules_Engine SHALL produce a High R4 finding citing both events.
2. WHEN a Package_Event executes `bun`, `bunx`, or `deno`, THE Rules_Engine SHALL produce a High R4 finding.

### Requirement 9: Rule R5, network tools (High)

**User Story:** As a security engineer, I want install-time use of network and DNS tools flagged, because they are common exfiltration channels.

#### Acceptance Criteria

1. WHEN a Package_Event executes `curl`, `wget`, `nc`, `ncat`, `netcat`, `socat`, `telnet`, `ssh`, `scp`, `sftp`, `ftp`, `tftp`, `rsync`, `dig`, `nslookup`, or `host`, THE Rules_Engine SHALL produce a High R5 finding.
2. WHEN a Package_Event executes `openssl` with the argument `s_client`, THE Rules_Engine SHALL produce a High R5 finding.
3. WHEN the executed program is `busybox` or `toybox`, THE Rules_Engine SHALL judge the applet named in `argv[1]` instead.

### Requirement 10: Rule R6, writes outside the package's area (High or Critical)

**User Story:** As a security engineer, I want writes outside the package's own area flagged, so that persistence, tampering, and planted workflows are caught.

#### Acceptance Criteria

1. WHEN a Package_Event writes, creates, truncates, deletes, renames, chmods, or links a path outside the Allowed_Write_Roots, THE Rules_Engine SHALL produce a High R6 finding.
2. WHEN that path, or a rename or link destination, contains a `.github/workflows` directory segment, THE Rules_Engine SHALL make the finding Critical.
3. THE Rules_Engine SHALL check both the source and the destination of a rename.

### Requirement 11: Rule R7, npm registry writes (Critical)

**User Story:** As a security engineer, I want any attempt to publish, or to validate an npm token, flagged as malicious, because that is how the worm spreads.

#### Acceptance Criteria

1. WHEN an `http` event to an npm registry host uses `PUT` or `DELETE`, or targets a path starting with `/-/npm/v1/tokens`, `/-/whoami`, or `/-/user/`, THE Rules_Engine SHALL produce a Critical R7 finding.
2. WHEN an `exec` event runs npm, pnpm, yarn, or bun with an argument that is a publish, unpublish, deprecate, login, adduser, or token command (including npm's accepted abbreviations), THE Rules_Engine SHALL produce a Critical R7 finding.

### Requirement 12: Rule R8, GitHub writes (Critical or High)

**User Story:** As a security engineer, I want repository creation, workflow injection, runner registration, and pushes flagged, because Shai-Hulud used all of them.

#### Acceptance Criteria

1. WHEN an `http` event to `api.github.com`, `uploads.github.com`, or `github.com` uses `POST`, `PUT`, `PATCH`, or `DELETE`, except a path ending in `/git-upload-pack` (a clone or fetch), THE Rules_Engine SHALL produce a Critical R8 finding.
2. WHEN an `exec` event runs `git` with the argument `push`, THE Rules_Engine SHALL produce a Critical R8 finding.
3. WHEN an `http` event to `api.github.com` requests `/user` or a path under it, THE Rules_Engine SHALL produce a High R8 finding (token validation).
4. WHEN an `exec` event runs `gh`, THE Rules_Engine SHALL produce a High R8 finding.

### Requirement 13: Rule R9, wiping files (Critical)

**User Story:** As a security engineer, I want mass deletion flagged as malicious, because Shai-Hulud 2.0 wiped home directories when theft failed.

#### Acceptance Criteria

1. WHEN Package_Events delete, truncate, or rename away at least 20 distinct paths outside the Allowed_Write_Roots, THE Rules_Engine SHALL produce one Critical R9 finding citing those events.

### Requirement 14: Rule R10, processes left running (High)

**User Story:** As a security engineer, I want processes that outlive the install flagged, because detaching is how malware hides its real work from short scans.

#### Acceptance Criteria

1. WHEN a process ID's last event in `seq` order is not an `exit` event, THE Rules_Engine SHALL produce a High R10 finding for that process.
2. WHEN a Package_Event from a process happens in the `linger` phase, THE Rules_Engine SHALL produce a High R10 finding for that process.
3. THE Rules_Engine SHALL treat events after a process's `exit` with the same process ID as a new process (PID reuse).
4. THE evidence SHALL be the first event of that process.

### Requirement 15: Rule R13, incomplete trace (High)

**User Story:** As a security engineer, I want a cut-off trace treated as suspicious, so that malware can't push its behaviour past the event cap.

#### Acceptance Criteria

1. WHEN `eventsTruncated` is true, THE Rules_Engine SHALL produce a High R13 finding citing the last event.

### Requirement 16: Findings and evidence

**User Story:** As a security engineer reviewing a verdict, I want every finding tied to exact events, so that I can check it myself.

#### Acceptance Criteria

1. THE Rules_Engine SHALL include in every finding at least one evidence `seq`, and every evidence `seq` SHALL exist in the input.
2. THE Rules_Engine SHALL list evidence in ascending order without duplicates, with at most 20 entries per finding.
3. THE Rules_Engine SHALL return at most 25 findings per rule, and SHALL report the number omitted.
4. THE Rules_Engine SHALL NOT include any honeytoken value in full in any finding text. It SHALL show a redacted form (the first 6 characters followed by `…`).
5. THE Rules_Engine SHALL cap each value quoted in a finding to 200 characters, and SHALL replace control characters and Unicode bidirectional overrides with visible escapes.

### Requirement 17: Verdict

**User Story:** As a developer installing packages, I want a simple, predictable verdict.

#### Acceptance Criteria

1. IF any finding is Critical, THEN THE Rules_Engine SHALL return MALICIOUS.
2. IF no finding is Critical and any finding is High, THEN THE Rules_Engine SHALL return SUSPICIOUS.
3. IF no finding is High or Critical, THEN THE Rules_Engine SHALL return SAFE.
4. THE Rules_Engine SHALL compare severities by an explicit rank, never by string comparison.
5. THE Rules_Engine SHALL record the Ruleset_Version in every verdict.

### Requirement 18: Determinism

**User Story:** As a security engineer, I want the same evidence to always give the same answer, so that verdicts are reproducible and auditable.

#### Acceptance Criteria

1. THE Rules_Engine SHALL return deep-equal verdicts for deep-equal inputs.
2. THE Rules_Engine SHALL return the same verdict whatever the order of the input event array.
3. THE Rules_Engine SHALL sort findings by rule order, then by first evidence `seq`, then by explanation.
4. THE `base/core` package SHALL NOT use the clock, randomness, environment, file system, or network.

### Requirement 19: Verdict cache key

**User Story:** As a platform engineer, I want verdicts cached by exact package identity, so that a re-published tarball can never reuse an old SAFE verdict.

#### Acceptance Criteria

1. THE Rules_Engine SHALL provide `verdictCacheKey(name, version, integrity, rulesetVersion)` that returns the same key only when all four values are equal.
2. THE Rules_Engine SHALL accept only `sha512-` integrity values in Subresource Integrity format, and SHALL throw a typed error for anything else.
3. THE key SHALL use an encoding in which no component can contain the separator.

### Requirement 20: Test fixtures

**User Story:** As a developer, I want realistic fixtures, so that the engine is proven against a worm and a normal package.

#### Acceptance Criteria

1. THE test suite SHALL include a hand-written worm-like trace that reads `~/.npmrc`, leaves a detached process, and sends the npm honeytoken base64-encoded inside JSON to an unknown `.invalid` host, and it SHALL be judged MALICIOUS.
2. THE test suite SHALL include an esbuild-like trace that downloads a binary from an allowlisted host into `nodeModulesDir`, runs it, and exits cleanly, and it SHALL be judged SAFE with no findings.
3. THE fixtures SHALL contain no real credentials. Honeytoken values SHALL be built at run time.
