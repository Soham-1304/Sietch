# Implementation Plan

All work is in `base/core/src/`. Property tests are **required** for this spec (they aren't optional), because `testing.md` lists them as the properties the project depends on. Before committing, run `/security-review` on the changed files.

- [ ] 1. Add zod and the shared building blocks
  - Add `zod@4.6.7` to `base/core` (exact pin, MIT, no install scripts, published 2026-10-12, so it passes the 1-day minimum release age).
  - Create `limits.ts` with every constant from the design's Limits table.
  - Create `text.ts`: `quote(value)` caps at `MAX_QUOTE` and replaces C0 and C1 controls, U+2028, U+2029, U+202A–U+202E, and U+2066–U+2069 with `\u{…}`. `redactToken(value)` gives the first 6 characters plus `…`.
  - Add `InvalidPackageIdentityError` to `errors.ts`.
  - _Requirements: 1.4, 16.4, 16.5, 19.2_

- [ ] 2. Paths and hosts
  - [ ] 2.1 Implement `paths.ts`: `segments`, `normalisePath`, `isInside`, `basename`.
    - Unit tests: `/a/bc` is not inside `/a/b`; `..` above the root stays at `/`; a trailing slash; repeated slashes.
    - _Requirements: 1.3, 6.3, 10.1_
  - [ ] 2.2 Property tests for paths.
    - **Property 10: Path containment works on segments.** **Validates: Requirements 6.3, 10.1**
    - **Property 12: Normalisation is idempotent.** **Validates: Requirements 1.3**
  - [ ] 2.3 Implement `hosts.ts`: `normaliseHost`, `compileAllowlist`, `matchesAllowlist`, `canonicalIp`, `isLoopback`.
    - Unit tests: `registry.npmjs.org.evil.invalid`, `evilnpmjs.org`, `NPMJS.ORG.`, `host:443`, `[::1]:80`, `::ffff:127.0.0.1`, an invalid pattern (`*evil.com`, `a.*.com`, an empty string) rejected.
    - _Requirements: 7.3, 7.4, 7.5_
  - [ ] 2.4 Property test for allowlist matching.
    - **Property 11: Allowlist matching is exact.** **Validates: Requirements 7.4, 7.5**

- [ ] 3. Encoding and the honeytoken matcher
  - [ ] 3.1 Implement `encoding.ts`: `base64Encode` (std and url), `hexEncode`, `percentDecode`. Check them against the RFC 4648 test vectors.
    - _Requirements: 4.2, 4.3_
  - [ ] 3.2 Implement `honeytokens.ts`: `compileHoneytokens` (raw, hex, base64 at 3 offsets × 2 alphabets, double base64) and `findHoneytokens` (candidates after 0, 1, and 2 percent-decodes; whitespace removed for base64; lowercase for hex).
    - Unit tests: a token inside `base64(JSON.stringify({ tokens: [t] }))` at each of the 3 offsets; base64 wrapped at 76; `%`-encoded base64; no false match for a near-identical token with one character changed.
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_
  - [ ] 3.3 Property test for honeytoken detection.
    - **Property 7: Honeytokens are found in every supported encoding.** **Validates: Requirements 4.1–4.4**

- [ ] 4. Schema and validation
  - [ ] 4.1 Implement `schema.ts` with `z.strictObject` schemas for all 7 event types and ScanInput, plus refinements: unique seq, unique honeytoken IDs and values, `nodeModulesDir` inside `projectDir`, `target` present exactly for `rename`, `symlink`, and `hardlink`, `pid` present exactly for process events, well-formed strings, no control characters in paths, and the total body limit.
    - `validateScanInput` returns `{ ok, value }` or `{ ok: false, reason }`. The reason is built only from the issue path and code, never from the value or the zod message.
    - Unit tests for each rejection in Requirement 1, including an unknown key such as `"__proto__"`, an unknown event type, a relative path, and a path with `\u0000`.
    - _Requirements: 1.1–1.8_
  - [ ] 4.2 Property test.
    - **Property 14: Control characters are rejected.** **Validates: Requirements 1.3, 1.8**

- [ ] 5. Test fixtures and generators
  - Create `src/__fixtures__/builders.ts`: a small trace builder (`exec`, `read`, `write`, `exit`, `dns`, `http`, `connect`) that assigns seq numbers and builds honeytokens at run time.
  - Create `src/__fixtures__/arbitraries.ts`: fast-check arbitraries for valid ScanInputs made of benign events (reads and writes inside `nodeModulesDir`, allowlisted DNS and HTTP, processes that exit), plus injectors that add one rule's trigger.
  - Create `worm.ts`, `esbuild-like.ts`, and `shai-hulud-2.ts` as described in the design's Testing strategy.
  - _Requirements: 20.1, 20.2, 20.3_

- [ ] 6. Checkpoint: run `pnpm check`. Everything must pass before the rules are written.

- [ ] 7. Context and programs
  - [ ] 7.1 Implement `context.ts`: `buildContext` sorts by seq, normalises every path and target, computes the allowed write roots and credential roots, compiles the allowlist and honeytokens, and provides `isPackageEvent`.
    - Unit test: the same ScanInput with its events shuffled gives the same sorted context.
    - _Requirements: 3.1, 3.4_
  - [ ] 7.2 Implement `programs.ts`: `programName` (busybox and toybox applets, npm-cli.js), and the network tool, runtime, registry-write, and GitHub program sets.
    - _Requirements: 8.2, 9.1, 9.2, 9.3, 11.2, 12.2, 12.4_

- [ ] 8. Rules
  - Each rule gets its own file in `rules/` with unit tests: one case that fires, one near miss that doesn't fire, and the matching blue-team bypass from the design.
  - [ ] 8.1 R1 honeytoken exfiltration (http fields, dns names with and without dots, case-insensitive raw match for DNS, allowlisted hosts included). _Requirements: 5.1, 5.2, 5.3, 3.3_
  - [ ] 8.2 R2 credential access (reads, symlink and hardlink targets, `/proc/*/environ`, `.env` outside `node_modules`, `extraCredentialPaths`, and npm's own `~/.npmrc` read ignored). _Requirements: 6.1, 6.2, 6.3, 3.2_
  - [ ] 8.3 R3 unexpected destinations (dns, http, and connect; sink and loopback ignored; one finding per destination). _Requirements: 7.1, 7.2, 7.3_
  - [ ] 8.4 R4 new executables (exec of a file written outside `node_modules`; bun, bunx, and deno; esbuild-style exec inside `node_modules` doesn't fire). _Requirements: 8.1, 8.2_
  - [ ] 8.5 R5 network tools (including busybox applets and `openssl s_client`). _Requirements: 9.1, 9.2, 9.3_
  - [ ] 8.6 R6 writes outside the allowed roots (rename sources and targets, `.github/workflows` Critical, `/dev/null` allowed, other `/dev` and `/proc` writes flagged). _Requirements: 10.1, 10.2, 10.3_
  - [ ] 8.7 R7 npm registry writes (HTTP methods and paths; exec with abbreviations such as `npm pu`; the package manager is included). _Requirements: 11.1, 11.2, 3.3_
  - [ ] 8.8 R8 GitHub writes (write methods Critical, `git-upload-pack` excluded, `git push` Critical, `GET /user` High, `gh` High). _Requirements: 12.1–12.4_
  - [ ] 8.9 R9 wiper (19 paths don't fire, 20 do, duplicates counted once). _Requirements: 13.1_
  - [ ] 8.10 R10 lingering processes (no exit, linger activity, PID reuse after exit). _Requirements: 14.1–14.4_
  - [ ] 8.11 R13 truncated trace. _Requirements: 15.1_
  - [ ] 8.12 `rules/index.ts` with the fixed rule order.

- [ ] 9. Verdict and cache key
  - [ ] 9.1 Implement `verdict.ts`: `RULESET_VERSION`, `SEVERITY_RANK`, `kindFromFindings`, `judge` (validate, check for exec events, build the context, run the rules, check the evidence, compute the kind before capping, sort, cap), `errorVerdict`, `allowsInstall`. Wrap everything in try/catch so that any error becomes ERROR.
    - Unit tests: a rule that returns empty or unknown evidence gives ERROR (inject a broken rule through an internal parameter that isn't exported from `index.ts`); no exec events gives ERROR; truncated and empty gives ERROR; 30 R3 destinations give 25 findings and `omittedFindings: 5`.
    - _Requirements: 2.1–2.5, 16.1–16.5, 17.1–17.5, 18.3_
  - [ ] 9.2 Implement `cache-key.ts` with unit tests for every rejected input.
    - _Requirements: 19.1, 19.2, 19.3_
  - [ ] 9.3 Property tests for the verdict.
    - **Property 1: Determinism and order independence.** **Validates: Requirements 18.1, 18.2, 3.4**
    - **Property 2: Never throws.** **Validates: Requirements 2.1, 1.1, 1.8**
    - **Property 3: Evidence integrity.** **Validates: Requirements 16.1, 16.2**
    - **Property 4: Adding a finding never makes the verdict safer.** **Validates: Requirements 17.1–17.3**
    - **Property 5: The verdict matches the severities.** **Validates: Requirements 17.1–17.3, 16.3**
    - **Property 6: Only SAFE allows an install.** **Validates: Requirements 2.5**
    - **Property 8: Honeytokens are never shown in full.** **Validates: Requirements 16.4**
    - **Property 13: Exfiltration always makes it MALICIOUS.** **Validates: Requirements 5.1, 17.1**
  - [ ] 9.4 Property test for the cache key.
    - **Property 9: The cache key is injective.** **Validates: Requirements 19.1, 19.3**

- [ ] 10. Fixtures end to end
  - `worm.ts` is MALICIOUS with R1, R2, R3, R6, and R10. `esbuild-like.ts` is SAFE with zero findings. `shai-hulud-2.ts` is MALICIOUS with R4, R5, and R9.
  - A coverage test checks that every rule ID fires in at least one fixture or unit case.
  - _Requirements: 20.1, 20.2_

- [ ] 11. Public API and docs
  - Export from `index.ts`: `judge`, `errorVerdict`, `allowsInstall`, `verdictCacheKey`, `RULESET_VERSION`, `findHoneytokens`, `compileHoneytokens`, and the types (`ScanInput`, `Event`, `Verdict`, `Finding`, `Severity`, `RuleId`).
  - Update `base/core/README.md` with the API and the trace producer contract.
  - Add the honest limits (BT-4, BT-5, BT-11) to the README's limitations section.

- [ ] 12. Final checkpoint
  - `pnpm check` passes. Run with `FC_NUM_RUNS=5000` once.
  - Run `/security-review` and `/blue-team` on `base/core/src`, and fix every Critical, High, and Medium finding.
  - Add a build-log entry (spec finished, plus any PBT counterexamples), and tick the checklist.
