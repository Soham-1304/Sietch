---
inclusion: always
---

# Tech stack

One language everywhere: **TypeScript**. Don't introduce Python or another backend language.

| Area | Choice | Notes |
|---|---|---|
| Runtime | Node.js 24 LTS | Pinned in `.nvmrc`. |
| Package manager | pnpm workspaces | pnpm doesn't run dependency install scripts by default, which fits the project. |
| Language settings | TypeScript `strict`, ES modules only | No `any` without a comment explaining why. |
| API server | Fastify | Schemas on every route. |
| Validation | zod | At every trust boundary: HTTP input, queue jobs, package metadata, tarball contents, hook stdin. |
| Queue and cache | BullMQ on Redis | Redis runs in Docker. |
| Database | MongoDB, using the official `mongodb` driver | Atlas free cluster (512 MB) in production. Keep documents small: cap events per scan. |
| Registry | Verdaccio, with Sietch filter and middleware plugins | Filters only hide versions. Tarball blocking must happen in middleware. |
| Sandbox | Docker with the gVisor runtime (`runsc`) | See `security.md` for the required container settings. |
| Dashboard | React, Vite, Tailwind, shadcn/ui | Keep pages few and simple. |
| MCP server | `@modelcontextprotocol/sdk` | stdio transport for the Kiro power. |
| Tests | Vitest and fast-check | See `testing.md`. |
| Lint and format | Biome | One tool for both. |
| Reverse proxy | Caddy | Automatic HTTPS. |

## Dependencies

- **Check current versions before adding a package.** Use Context7 or `npm view <pkg> version`. Don't rely on memory for versions or APIs.
- Prefer the standard library and existing dependencies. Every new dependency needs a reason.
- Pin exact versions (`save-exact=true`).
- Dependencies that need install scripts must be listed explicitly in pnpm's allowlist (`onlyBuiltDependencies`), with a comment explaining why.
- **Our own published packages never have install scripts.**

## Coding conventions

- Named exports only. No default exports.
- Use `async`/`await`, never raw promise chains.
- Errors: throw typed errors (classes extending `SietchError`) inside the base. Map them to HTTP responses only at the API edge.
- No `console.log` in library code. Use the shared logger (pino), and never log secrets or full honeytoken values.
- Inject time, randomness, and I/O into core logic (for example, pass a `clock` and an `rng`) so it stays testable and deterministic.
- Keep functions small and pure where possible, especially in `base/core`.

## Commands

Fill this in when the workspace is scaffolded. Until then, there are no runnable scripts.

| Task | Command |
|---|---|
| Install | `pnpm install` |
| Typecheck | _TBD_ |
| Test (all) | _TBD_ |
| Test (one package) | _TBD_ |
| Lint and format | _TBD_ |
