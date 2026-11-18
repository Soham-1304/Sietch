# Security review checklist

Work through every section that applies. Each item names the bad pattern and what correct code looks like.

## 1. Process execution and shell

- **Never use a shell with untrusted data.** No `exec`, `execSync`, or `spawn(..., { shell: true })` when any part of the command is untrusted. Use `spawn` or `execFile` with an argument array.
- **No string-built commands.** Concatenating or templating a command string, even with "escaping", is a finding.
- **Argument injection:** an untrusted value that starts with `-` becomes a flag (for example a package name `--registry=http://evil`). Put `--` before positional arguments, or validate the value doesn't start with `-`.
- **Docker arguments** are built only from constants and validated values. Image names, mounts, network names, and environment variables never come from package data.
- **Environment passed to children** is an explicit allowlist. Never pass `process.env` through to a sandbox or tool, because it carries real secrets.
- **Timeouts and kill:** every child process has a timeout, and the whole process group is killed on timeout, not just the parent.
- **Executable lookup:** resolve tools to absolute paths. Never trust a relative `PATH` entry or `.` in `PATH`.

## 2. File system and tarballs

- **Path traversal:** every path built from untrusted data is resolved, then checked to stay inside the intended root. Use `path.relative(root, resolved)` and reject results that start with `..` or are absolute. **`startsWith(root)` alone is wrong**, because `/data/root2` starts with `/data/root`.
- **Tar entries:** reject absolute paths, `..` segments, symlinks and hardlinks whose target leaves the root, device files, FIFOs, and entries whose name contains NUL or control characters.
- **Limits:** cap the number of entries, the size of each entry, and the total size. Check the uncompressed size while streaming (decompression bombs), not from the header.
- **Symlink races (TOCTOU):** don't check a path and then open it later by name. Open with `O_NOFOLLOW` where possible, or extract into a fresh directory nothing else touches.
- **Permissions:** files written by us get explicit modes. Never `chmod 777`.
- **Temp files:** use `mkdtemp` for unique directories. Never use predictable names in a shared `/tmp`.

## 3. Parsing untrusted data

- **Validate with zod at the boundary,** and use `.strict()` on objects so unknown keys are rejected rather than silently kept.
- **Prototype pollution:** never merge untrusted objects into plain objects (`Object.assign`, spread into config, deep merge). Treat keys like `__proto__`, `constructor`, and `prototype` as hostile. Use `Map` or `Object.create(null)` for untrusted keys.
- **ReDoS:** any regular expression run on untrusted input must not have nested or overlapping quantifiers (`(a+)+`, `(a|a)*`, `(.*)*`, `\s*\S*\s*` chains). Bound the input length before matching. Prefer simple, anchored patterns.
- **Size before parse:** check length before `JSON.parse`, decoding, or decompressing.
- **Encodings:** decode once, in one place. Double-decoding, or checking before decoding, creates bypasses.
- **Unicode:** package names and paths may contain look-alike characters, right-to-left overrides, and zero-width characters. Normalise (NFC) and reject control and bidi characters where the value is shown to people.

## 4. Network and HTTP

- **SSRF:** never fetch a URL taken from package metadata as-is. Tarball URLs must match the configured registry host exactly (scheme, host, port). Block redirects to other hosts. Block private, loopback, link-local, and metadata addresses (`169.254.169.254`, `fd00::/8`, `::1`, `127.0.0.0/8`, `10/8`, `172.16/12`, `192.168/16`), including after DNS resolution.
- **Route input:** every Fastify route has a schema for params, query, body, and response.
- **Auth:** admin actions check auth on the server. Never trust a client flag.
- **Rate limits and size limits** on every public endpoint, and request body caps.
- **Header injection:** values placed in headers have CR and LF rejected.
- **CORS:** explicit origins only, never `*` with credentials.
- **Errors:** responses never include stack traces, internal paths, or secrets.

## 5. Output: dashboard, CLI, and logs

- **XSS:** package names, versions, file paths, captured payloads, and README text are rendered as text. No `dangerouslySetInnerHTML`. No Markdown rendering of package content without sanitising it. Links built from package data use only `https:` and are validated.
- **Terminal escape injection:** the CLI and hooks print package data. Strip or escape ANSI and other control characters (`\x1b`, `\x07`, `\r`, and bytes below `0x20` other than `\n` and `\t`) before printing, or a hostile package name can rewrite the terminal or hide output.
- **Log injection:** untrusted strings in logs go into structured fields, never interpolated into the message, and newlines are escaped.
- **Secrets:** honeytokens are shown truncated. Real secrets never appear in logs, errors, or API responses.

## 6. Verdict and detection logic

- **Fail closed:** see `fail-closed.md`.
- **Exhaustive handling:** `switch` on event type or verdict ends with an exhaustive `never` check. Unknown event types are an error, never ignored.
- **Evidence:** every finding cites evidence events that exist in the input.
- **Ordering:** severity comparison uses an explicit rank, not string comparison.
- **Caching:** the cache key includes name, version, integrity hash, and ruleset version. A changed hash never hits an old verdict.
- **Truncation:** if events are capped, hitting the cap is recorded and treated as suspicious, never silently dropped.

## 7. Secrets and configuration

- No secrets in code, fixtures, tests, or committed config. Fake secrets in tests are built at runtime (for example `"ghp_" + "x".repeat(36)`), so secret scanners don't flag the repo.
- Required configuration is validated at startup. A missing value stops startup, rather than falling back to a default that weakens security.

## 8. Dependencies

- Every new dependency: is it needed, maintained, license-compatible (Apache-2.0), free of install scripts, and pinned exactly? Note the reason in the review.

## 9. Concurrency and resources

- Unbounded queues, arrays, maps, retries, or recursion fed by untrusted data are findings.
- Every `await` on external work has a timeout.
- Unhandled promise rejections and floating promises (an `async` call without `await` or `.catch`) are findings.

## Severity

| Severity | Meaning |
|---|---|
| **Critical** | Hostile code escapes the sandbox, a real secret leaks, malware can be labelled SAFE, or remote code execution on the host or server. |
| **High** | A security control is bypassed under realistic conditions, or a fail-open path in a security decision. |
| **Medium** | A bypass that needs unusual conditions, denial of service from untrusted input, or a missing test for a security property. |
| **Low** | Defence-in-depth gaps, unclear error handling, or hardening that has no direct exploit. |
