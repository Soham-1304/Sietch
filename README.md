# Sietch

**A checkpoint for npm packages.** Sietch runs each new package version inside a locked-down sandbox that holds only fake credentials, records what the package does, and blocks it if it tries to steal them. Each version is checked once, and the whole organisation reuses the verdict.

> **Status:** early development for Kiroween 2026 (Skeleton Crew category). Nothing is runnable yet. "Sietch" is a working name.

## Why

In 2025, the Shai-Hulud worm compromised hundreds of npm packages. Its install scripts ran automatically on `npm install`, stole npm, GitHub, and cloud tokens from developer laptops and CI servers, and used the stolen npm tokens to infect more packages. Nothing checked what a package did before it ran next to real secrets.

AI coding agents now run `npm install` on their own, often for packages no person has looked at.

## What it is

One base, two apps:

| Part | Folder | For |
|---|---|---|
| **Base**: detonation engine | `base/` | Sandbox, honeytokens, behaviour recording, deterministic rules, verdict store, API, CLI. |
| **App 1: Registry Gate** | `apps/registry-gate/` | A private npm registry for developers and CI. Unsafe versions are never served. |
| **App 2: Agent Guard** | `apps/agent-guard/` | A Kiro power with an MCP server and hooks. It stops AI agents installing unsafe or made-up packages and MCP servers. |

## How it's built

Built with [Kiro](https://kiro.dev). The `.kiro/` folder holds the steering, specs, hooks, and custom agents used during development.

- Plan: [`docs/plan.md`](docs/plan.md)
- Checklist: [`docs/checklist.md`](docs/checklist.md)
- Build log: [`docs/build-log.md`](docs/build-log.md)

## License

[Apache-2.0](LICENSE)
