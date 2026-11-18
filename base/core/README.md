# @sietch/core

The pure heart of Sietch: the event model, the rules engine, and the verdict.

**Rule:** this package does no I/O. It has no file system, network, Docker, database, clock, or random number access. Data goes in, a verdict comes out. That's what makes verdicts deterministic and testable with property-based tests. The rule is enforced in two ways:

- `tsconfig.json` loads no Node.js types, so importing a `node:` module is a type error.
- `biome.json` refuses `process`, `fetch`, timers, `Date`, `crypto`, and `Buffer` in this package.

The only dependency is `zod` (MIT), for strict input validation.

## Public API

| Export | What it does |
|---|---|
| `judge(input: unknown): Verdict` | Validates the scan input and runs every rule. **Never throws.** Any problem gives an `ERROR` verdict. |
| `allowsInstall(verdict)` | `true` only for `SAFE`. Use this, never a comparison of your own. |
| `errorVerdict(reason)` | The verdict for a scan that failed or timed out. It blocks. |
| `verdictCacheKey(identity, rulesetVersion)` | Cache key from name, version, SHA-512 integrity, and ruleset version. Throws `InvalidPackageIdentityError` on bad input. |
| `RULESET_VERSION` | Bumped whenever a rule changes. Verdicts from other versions are never reused. |
| `validateScanInput(input)` | The strict schema on its own. |
| `findHoneytokens`, `compileHoneytokens` | Honeytoken matching (raw, hex, base64 at any alignment, double base64, URL-encoded). |
| Types | `ScanInput`, `Event`, `Verdict`, `Finding`, `Severity`, `RuleId`, `HoneytokenKind` |

## Verdicts

| Kind | When | Install |
|---|---|---|
| `MALICIOUS` | Any Critical finding | Blocked |
| `SUSPICIOUS` | Any High finding, no Critical | Blocked until a person reviews it |
| `SAFE` | No High or Critical finding | Allowed |
| `ERROR` | Invalid input, no `exec` events, or an internal error | Blocked |

Every finding cites the `seq` numbers of the events that caused it. Untrusted values are escaped, capped, and stripped of honeytokens before they appear in a finding.

## Rules

| ID | Severity | What it catches |
|---|---|---|
| R1 | Critical | A honeytoken in outgoing traffic (HTTP or DNS), in any supported encoding, to any host |
| R2 | High | Reading or linking to a credential store (`~/.npmrc`, `~/.ssh`, `~/.aws`, `/proc/*/environ`, `.env`, …) |
| R3 | High | Contacting a host that isn't allowlisted, a raw IP, or the sink on a port it can't record |
| R4 | High | Running a file written outside `node_modules` during the scan, or running Bun or Deno |
| R5 | High | Running a network or DNS tool (`curl`, `wget`, `nc`, `dig`, …) |
| R6 | High, Critical | Changing files outside `node_modules`, temp, and caches. Critical for `.github/workflows` |
| R7 | Critical | npm publish, unpublish, login, or token use (HTTP or command line, abbreviations included) |
| R8 | Critical, High | Creating or changing things on GitHub, `git push`, checking a GitHub token, running `gh` |
| R9 | Critical | Deleting or overwriting 20 or more files outside the package's area |
| R10 | High | A process still running after install and load, or active afterwards |
| R13 | High | The trace or a request body was cut off |

Paths are checked under every name they can be reached by: through symlinks and hard links created earlier in the trace, and through `/proc/<pid>/root`.

## Contract for the trace producer

The trace normaliser and sandbox runner must guarantee the items in `.kiro/specs/rules-engine/design.md` ("Contract for the trace producer"), and in particular:

- pids are process (thread group) IDs, and every exit is reported once,
- paths are absolute and resolved against the working directory,
- the sandbox runner's own processes are not included,
- `bodyTruncated` is set whenever the sink cut a body short,
- the install runs offline, so npm itself sends nothing.

## Known limits

Sietch doesn't claim to catch everything. These gaps are known and accepted for now:

- Code that only runs in a browser, or only when imported by a particular parent package.
- Behaviour delayed past the observation window, or triggered only on a real machine.
- Malware that detects the sandbox and stays quiet.
- Tokens encoded in other ways (base32, XOR, compressed, split across requests). R1 misses them, but R2 and R3 usually still fire.
- Data other than our fake credentials sent to an allowlisted host.
- Tampering with other packages inside `node_modules` (rule R14 is planned).
- Writes into the npm, node-gyp, and general caches (`~/.npm`, `~/.node-gyp`, `~/.cache`) are allowed, because normal installs write there constantly. A package could poison the npm cache for a later install, and it wouldn't be flagged.
- Reading an environment variable leaves no file event, so R2 can't see it. R1 still catches the token when it's sent out in a supported encoding.

**A worked example of what gets through.** Each step below is one of the limits above, and together nothing fires: read a fake token from an environment variable (no event), encode it as base32 (R1 doesn't decode it), and send it as a DNS lookup under an allowlisted wildcard host such as `<data>.objects.githubusercontent.com` (R3 allows it). Keeping the allowlist short, and preferring exact hosts to `*.` wildcards, narrows this path.

Details: `docs/reviews/2026-11-18-rules-engine-blue-team.md` and `docs/reviews/2026-11-18-rules-engine-breach-review.md`.
