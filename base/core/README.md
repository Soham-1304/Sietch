# @sietch/core

The pure heart of Sietch: the event model, the rules engine, and the verdict logic.

**Rule:** this package does no I/O. It has no file system, network, Docker, database, clock, or random number access. Data goes in, a verdict comes out. This is what makes the rules engine deterministic and testable with property-based tests. The rule is enforced in two ways:

- `tsconfig.json` loads no Node.js types, so importing a `node:` module is a type error.
- `biome.json` refuses `process`, `fetch`, timers, and `Date` in this package.

## Public API

| Export | What it is |
|---|---|
| `SietchError` | Base class for errors, with a stable `code`. |

More arrives with the `rules-engine` spec (`.kiro/specs/rules-engine/`).
