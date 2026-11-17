---
inclusion: fileMatch
fileMatchPattern: ["**/*.test.ts", "**/*.test.tsx", "base/core/**", "**/__fixtures__/**", "**/vitest.config.*"]
---

# Testing

## Tools

- **Vitest** for all tests.
- **fast-check** for property-based tests (files named `*.prop.test.ts`).

## What must have property-based tests

These are the properties the project depends on. Each one gets a property test in the package that owns it.

| Property | Package |
|---|---|
| The same events and ruleset always produce the same verdict. | `base/core` |
| Adding a finding never makes a verdict safer (SAFE < SUSPICIOUS < MALICIOUS). | `base/core` |
| Every finding references at least one evidence event that exists in the input. | `base/core` |
| A different integrity hash never matches a cached verdict. | `base/core` |
| Honeytoken detection catches every supported encoding: raw, base64, double base64, hex, URL-encoded. | `base/core` |
| Honeytokens are unique per scan. | `base/sandbox` |
| The trace normaliser never throws on arbitrary input. It returns events or a typed parse error. | `base/core` |
| Tarball path validation rejects every escaping path. | `base/sandbox` |
| The install-command parser finds every package in any valid `npm`, `pnpm`, `yarn`, or `npx` command. | `apps/agent-guard` |

## Rules

- **Tests are deterministic.** No real network, no real clock, no real randomness. Inject a `clock` and an `rng`. Use fixed seeds in fast-check, and print the seed on failure.
- **Unit tests never start Docker.** Sandbox integration tests are separate (`*.int.test.ts`) and opt-in.
- Fixtures are small, readable, and hand-written where possible. Recorded traces go in `__fixtures__/` with a comment saying where they came from.
- When a property test finds a counterexample, keep it as a regular unit test so the case stays covered. Log it in `docs/build-log.md` under "PBT findings".
- Test behaviour through public functions, not private internals.
