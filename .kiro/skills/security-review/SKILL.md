---
name: security-review
description: Line-by-line security code review for Sietch. Use before committing or after writing any code that touches untrusted input, child processes, shell commands, Docker, the file system, tarballs, the network, HTTP routes, hooks, the CLI, the dashboard, or verdict logic. Finds injection, path traversal, fail-open fallbacks, ReDoS, SSRF, XSS, terminal escape injection, secret leaks, and resource exhaustion. Reports findings with a PASS or FAIL verdict.
metadata:
  project: sietch
  role: reviewer
---

# Security review

Sietch runs hostile code on purpose. A bug here leaks real credentials, lets hostile code out of the sandbox, or labels malware SAFE. Review as if the author were careless and the input were written by the attacker.

## Ground rules

- **Read the code. Don't skim it.** Read every changed line, and every function a changed line calls when that function handles untrusted data.
- **Untrusted means:** package names, versions, metadata, tarballs and every file in them, file names, READMEs, scripts, recorded traces, network payloads the sandbox captured, MCP tool names and descriptions, HTTP requests, hook stdin, environment variables in hooks, and command-line arguments.
- **No speculation.** Every finding needs a concrete input or sequence that triggers it. If you can't build one, it isn't a finding. Put it under "Questions" instead.
- **Don't fix during the review.** Report first. Fix after the user or the main agent agrees.
- **No finding is too small to report, and no report should invent findings.** If the code is clean, say what you checked.

## Steps

1. **Scope.** Run `git status` and `git diff` (staged and unstaged), or review the files the user names. List the files and what each one touches.
2. **Map the trust boundaries.** For each file, write down where untrusted data enters, where it ends up (a sink), and what validates it in between.
3. **Go through the checklist** in `references/checklist.md`, section by section, for every boundary. Skip sections that don't apply, and say that you skipped them.
4. **Audit fallbacks.** Find every `catch`, `?? default`, `|| default`, optional chain that falls through, `if (!x) return`, empty branch, timeout handler, and "unknown" or "default" case. For each one, answer: **if this path runs, is the result allowed or blocked?** Anything that ends in allow, SAFE, skip, or exit 0 without a stated reason is a finding (see `references/fail-closed.md`).
5. **Check the tests.** Each security property needs a test that fails if the property breaks. Missing tests for a finding's area are a finding.
6. **Report** in the format below.

## Report format

For each finding:

| Field | Content |
|---|---|
| ID | `SR-<n>` |
| Severity | Critical, High, Medium, or Low (see `references/checklist.md`, "Severity") |
| Location | `file:line` |
| Class | For example: command injection, fail-open, path traversal, ReDoS |
| Trigger | The concrete input or sequence that causes it |
| Impact | What the attacker gets |
| Fix | The specific change, and the test that proves it |

Then:

- **Fallback audit table:** each fallback path, where it is, and whether it ends in allow or block.
- **Checked and clean:** what you reviewed and found no problems in.
- **Questions:** things you couldn't confirm.
- **Verdict:** **PASS** only if there are no Critical, High, or Medium findings. Otherwise **FAIL**.
