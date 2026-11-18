# Spec prompts

Prompts to paste into a new Kiro **Spec** session, one per spec. They are kept here so the write-up can show exactly what each spec started from.

How to use one:

1. Start a new chat session and pick **Spec** in the session picker.
2. Paste the prompt.
3. Review each stage before approving it: requirements, then design, then tasks. Push back when something is wrong. Your edits are part of the spec-driven story.
4. Run the tasks one at a time from `tasks.md`. The `post-task-verify` hook runs after each one.

---

## 1. rules-engine (`base/core`)

```
Create a spec named "rules-engine" for the base/core package.

Context: #plan-reference (sections 5.1, 5.3, 5.4, 5.5, 5.6). Follow all steering, especially security.md, structure.md rule 1 (base/core is pure, no I/O), and testing.md.

Scope:
1. Event model: TypeScript types and zod schemas for normalised sandbox events: exec, file_read, file_write, connect, dns, http, exit. Each event has a sequence number, a timestamp passed in as data (no clock), pid and ppid, and type-specific data. Also a ScanInput type that bundles the events, static findings, honeytoken values, network allowlist, and ruleset version.
2. Honeytoken matcher: find any honeytoken value in a string or byte payload, raw or encoded as base64, double base64, hex, or URL-encoded. Return which token matched and how it was encoded.
3. Rules R1 to R10 from plan section 5.5, each as a pure function from ScanInput to findings. Every finding has a rule ID, a severity, a short explanation, and the sequence numbers of the evidence events.
4. Verdict logic: any Critical gives MALICIOUS, any High gives SUSPICIOUS, otherwise SAFE. A scan error gives ERROR, which callers must treat as blocked. The verdict records the ruleset version.
5. Verdict cache key built from package name, version, and integrity hash.

Out of scope: parsing raw syscall logs (that depends on Spike 1, so it gets its own spec), anything that touches Docker, files, the network, or a database, and rules R11 and R12.

Requirements must use EARS format. Properties to cover with fast-check, listed in testing.md:
- the same input always gives the same verdict,
- adding a finding never makes a verdict safer,
- every finding cites evidence events that exist in the input,
- a different integrity hash never gives the same cache key,
- the honeytoken matcher catches every supported encoding.

Include hand-written fixtures: a worm-like event sequence (reads ~/.npmrc, spawns a detached process, sends the npm honeytoken base64-encoded to an unknown host) that must be MALICIOUS, and a benign esbuild-like sequence (downloads a binary from an allowlisted host) that must be SAFE.
```

---

**Status:** the spec was written on 2026-11-18 in `.kiro/specs/rules-engine/`, from this prompt.

---

## 2. trace-normaliser (`base/core`) and sandbox-runner (`base/sandbox`)

Spike 1 is done (`docs/spikes/spike-1-recording.md`). Both specs follow from it:

- **trace-normaliser:** parse gVisor `--strace` text lines into the rules-engine's `Event` model, following the "Contract for the trace producer" in `.kiro/specs/rules-engine/design.md`. Any line it can't parse is an error.
- **sandbox-runner:** fetch, the honeytoken generator, the capture sink, and the per-architecture syscall list. It runs install, then load, then a 60 s observation window, and cleans up the raw logs.

Both are written after the rules-engine spec has been reviewed.
