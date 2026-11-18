# Breach re-review: rules engine (commit `703eb7d`)

**Date:** 2026-11-18. **Who:** the `sandbox-reviewer` agent in a fresh session (third review overall), using `security-review` and `blue-team`. It was told to invent its own attacks **before** reading the test fixtures or the earlier reviews, so it wasn't anchored on what was already tested. **Verdict: PASS.** There were no Critical, High, or Medium findings, and no new event sequence got a wrong SAFE.

## What it tried

Every attacker goal (steal, exfiltrate, persist, spread, tamper, sabotage), every channel (HTTP and HTTPS to allowlisted hosts, DNS, raw TCP and UDP, staged files), and event-level tricks: ordering, phases, PID games, symlinks, hard links, `/proc` aliases, rename chains, busybox, interpreters running dropped scripts, encodings, host normalisation, caps, and attribution to npm's own process. It also tried to make `judge()` throw, return the wrong kind, run slowly, or leak a honeytoken or unescaped text.

It confirmed that the SR-1 to SR-7 and BT fixes are present and correct.

## Findings (all Low)

| ID | Finding | New? | Action |
|---|---|---|---|
| BT-R2-1 | Writes into `~/.npm`, `~/.cache`, and `~/.node-gyp` are allowed, so a package could poison the npm cache for a later install. | New | Documented in `base/core/README.md` "Known limits". Flagging these writes would hit almost every normal install. |
| BT-R2-2 | The default credential list missed git's own credentials file, keyrings, browser login stores, and crypto wallets. | New | **Fixed:** 12 entries added (`RULESET_VERSION` 1.1.0), with a test. The honeytoken planter (sandbox-runner spec) must also plant fake secrets in these stores. |
| BT-R2-3 | No timing test for `judge()` at the largest valid input (16 honeytokens, about 24 MiB of traffic text). | New | **Measured: 366 ms.** Not a problem. Kept as a permanent test with a 5 s timeout. |
| BT-R2-4 | Raw non-HTTP bytes to the sink on port 80 or 443 might not become an `http` event. | Restates SR-3 | Sandbox-runner contract: the sink must emit an event for all traffic on 53, 80, and 443. |

## Known limits it reproduced (still bounded)

- **Tampering with other packages** in `node_modules` (BT-22) is the highest-impact open gap. It needs the sandbox runner to report each package's own folder, then R14.
- **Interpreters running dropped scripts** (`node ~/.cache/stage2.js`): R4 is silent, but the script's own behaviour is traced by every other rule.
- **Reading an environment variable** leaves no event, so R1 is the only net for environment-variable honeytokens.
- **The weakest point overall is three known limits combined:** an environment-variable read, plus base32 encoding, plus DNS under an allowlisted wildcard host. Each is a known limit, and together nothing fires. It's now written up as a worked example in the README.

## Candidate for later (not built)

A DNS lookup under an allowlisted `*.` wildcard whose first label is unusually long and random-looking is how DNS exfiltration usually looks. Flagging it would narrow the combined path above. The cost is false positives on CDN hostnames with hashes in them, so it needs real traffic samples first. It's parked until the sandbox runner can replay normal packages.
