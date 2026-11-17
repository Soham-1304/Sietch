---
inclusion: always
---

# Project structure

```
.
├── .kiro/                 steering, specs, hooks, agents (committed, never ignored)
├── base/                  THE SKELETON (shared by both apps)
│   ├── core/              event model, rules engine, verdict logic: pure TypeScript
│   ├── sandbox/           sandbox + capture-sink images, runner, honeytoken generator
│   ├── server/            API, worker, queue, database access
│   └── cli/               the `sietch` command
├── apps/
│   ├── registry-gate/     APP 1: Verdaccio plugins, dashboard, compose file
│   └── agent-guard/       APP 2: MCP server, Kiro power, hook scripts
├── demo/                  harmless worm lookalike, benign samples, seed scripts
├── deploy/                production compose, Caddyfile, VM setup script
├── docs/                  plan, checklist, build log, write-up drafts
└── test/                  shared test setup (fast-check seed and run count)
```

Workspace packages are created when their spec starts, not before. Each one has `package.json`, `tsconfig.json`, `vitest.config.ts` (named `core`, `sandbox`, and so on), `README.md`, and `src/`. Copy `base/core` as the template.

## Dependency rules (enforced in review)

These rules keep the base reusable, which is the whole point of the Skeleton Crew entry.

1. **`base/core` is pure.** No file system, network, Docker, database, or clock access. It takes data in and returns data. This makes property-based testing possible.
2. **Only `base/sandbox` talks to Docker.**
3. **Only `base/server` talks to MongoDB and Redis.**
4. **Apps depend on the base. The base never imports from an app.**
5. **The two apps never import from each other.** Shared needs move into the base.
6. Apps talk to the server over its HTTP API, or through `base/core` types. They don't reach into server internals.

## Naming

- Files and folders: `kebab-case`.
- Types and classes: `PascalCase`. Functions and variables: `camelCase`. Constants: `UPPER_SNAKE_CASE`.
- Workspace package names use the placeholder scope `@sietch/` (for example `@sietch/core`). The published npm scope is decided at branding time, so don't hard-code the scope outside `package.json` files.

## Files

- Unit tests sit next to the code: `foo.ts` and `foo.test.ts`.
- Property-based tests use `foo.prop.test.ts`.
- Test fixtures live in `__fixtures__/` folders next to the tests that use them.
- Each package has a short `README.md` describing what it does and its public API.
