# Sietch: Checklist

This is the task tracker. Tick items as they are done. The reasoning behind each item is in `docs/plan.md`; section numbers in brackets point to it, for example (§5.2).

**Deadline:** Fri Dec 4, 2:00 PM PT = **Sat Dec 5, 3:30 AM IST**. Target: submit by Fri Dec 4, evening IST.

**Priorities:** P0 = must ship. P1 = should ship. P2 = only if ahead. When behind, cut from the bottom of the list in §16.

---

## Phase 0: Kiro setup and repo (Tue Nov 17)

- [x] Git repo initialised (`main` branch)
- [x] `LICENSE` (Apache-2.0, official text)
- [x] Steering: `product.md`, `tech.md`, `structure.md`, `security.md` (always on)
- [x] Steering: `testing.md` (loads for test and core files)
- [x] Steering: `plan-reference.md`, `hackathon-rules.md` (manual, `#name` in chat)
- [x] Hook: `host-guard` (blocks unsafe shell commands on the host), tested with 21 cases
- [x] Hook: `secret-guard` (blocks chat messages containing real secrets), tested with 10 cases
- [x] Hook: `post-task-verify` (checks after each spec task)
- [x] Custom agent: `sandbox-reviewer`
- [x] `README.md`, `.gitignore`, `.nvmrc`, `.editorconfig`
- [x] `docs/build-log.md` started
- [ ] **You:** reload Kiro, then check that the steering files, hooks, and agent show up in the Kiro panel
- [ ] **You:** check that `host-guard` really blocks in the IDE: ask Kiro to run `npm publish`. It should be blocked with a reason. (This is Spike 3.)
- [ ] **You:** install Node 24 LTS (`brew install node@24`, or `nvm install 24`). Currently installed: 23.8.0
- [ ] **You:** create a **public** GitHub repo, then push the first commit
- [ ] Repo About section shows "Apache-2.0" (GitHub detects it automatically)

## Phase 0b: Specs and scaffolding (Wed Nov 18)

- [ ] Spec: `rules-engine` (requirements, design, tasks)
- [ ] Spec: `sandbox-runner`
- [ ] pnpm workspace scaffold: `base/core`, `base/sandbox`, `base/server`, `base/cli`, `apps/registry-gate`, `apps/agent-guard`
- [ ] TypeScript, Vitest, fast-check, and Biome configured. Commands filled in `tech.md`
- [ ] Hook: run the rule fixtures whenever a rule file is saved (§13)
- [ ] Hook: typecheck and run related tests whenever a `base/**/*.ts` file is saved (§13)
- [ ] **Spike 1** (§5.2): can we see a detached child process's file reads and network connections from outside the sandbox? Run locally in Docker Desktop first. Confirm on the VM later.
- [ ] **Spike 2** (§6.1): can Verdaccio plugins hide versions, block tarball downloads, and hold a request while a scan runs?
- [ ] **Checkpoint G1:** spike results written in the build log

## Phase 1: Base (Thu Nov 19 – Tue Nov 24)

### Core (`base/core`, pure, P0)
- [ ] Event model types (`exec`, `file_read`, `file_write`, `connect`, `dns`, `http`, `exit`) (§5.1)
- [ ] Trace normaliser (raw syscall log to events, never throws)
- [ ] Honeytoken matcher (raw, base64, double base64, hex, URL-encoded) (§5.4)
- [ ] Rules R1–R10 (§5.5)
- [ ] Verdict logic (MALICIOUS, SUSPICIOUS, SAFE, ERROR treated as blocked)
- [ ] Verdict cache key includes the integrity hash (§5.6)
- [ ] All core property-based tests from `testing.md` passing

### Sandbox (`base/sandbox`, P0)
- [ ] Sandbox Docker image (non-root, read-only root, tmpfs)
- [ ] Honeytoken generator (fresh per scan) and fake home directory (§5.3)
- [ ] Capture sink: fake DNS, HTTP and HTTPS capture, own certificate authority (§5.4)
- [ ] Internal-only sandbox network
- [ ] Safe tarball fetch (scripts off, integrity check) and safe extraction (§5.1)
- [ ] Runner: install, then `require`/`import`, then watch for 60 s after npm exits
- [ ] `sandbox-reviewer` agent review: PASS

### Server and CLI (P0)
- [ ] MongoDB models: `packages`, `scans`, `events`, `verdicts` (§8)
- [ ] Redis: BullMQ queue, verdict cache, pub/sub
- [ ] Worker runs the full pipeline (§5.1)
- [ ] API routes (§9), with zod validation
- [ ] Live event stream (SSE)
- [ ] `sietch scan <pkg@version>`

### Demo packages (P0)
- [ ] Worm lookalike in `demo/`, only fake files and `.invalid` domains (§12.2)
- [ ] Benign package with a legitimate install script

- [ ] **Checkpoint G2 (Nov 24):** `sietch scan` on the worm lookalike returns MALICIOUS with evidence

## Phase 2: App 1, Registry Gate (Wed Nov 25 – Sat Nov 28)

- [ ] Spec: `registry-gate`
- [ ] Verdaccio filter plugin (hide MALICIOUS versions) (§6.1)
- [ ] Verdaccio middleware plugin (block, serve, or hold tarball downloads)
- [ ] Clear npm error message with an evidence link
- [ ] `sietch init` and `sietch check`
- [ ] Spec: `dashboard`
- [ ] Dashboard: live chamber (§10)
- [ ] Dashboard: verdict page
- [ ] Dashboard: packages table
- [ ] Dashboard: try-it page
- [ ] **Checkpoint G3 (Nov 28):** `npm install` through the gate blocks the worm and serves safe packages, and the dashboard shows it live (locally)
- [ ] **Name and branding decided** (npm scope, subdomains)

## Phase 3: App 2, Agent Guard (Sun Nov 29 – Tue Dec 1)

- [ ] Spec: `agent-guard`
- [ ] MCP server: `check_package`, `explain_verdict`, `suggest_safe_version` (§6.2)
- [ ] Install-command parser, with its property-based test
- [ ] Pre Tool Use hook that blocks unsafe installs
- [ ] Kiro power: `plugin.json`, `mcp.json`, skills
- [ ] Agent Guard enabled in our own workspace (and logged in the build log)
- [ ] P1: invented-package check (name doesn't exist, very new, typo of a popular package)
- [ ] P1: `vet_mcp_server` and the `mcp.json` save hook
- [ ] **Checkpoint G4 (Dec 1):** in a real Kiro session, the agent is blocked from an unsafe package and picks a safe one

## Phase 4: Hosting (from Nov 24, all free)

Coding comes first. Start these once the base works locally (Checkpoint G2).

- [ ] MongoDB Atlas free cluster created, with an IP allowlist
- [ ] GCP free trial claimed ($300, 90 days), with a $250 budget alert
- [ ] VM created: `e2-standard-2`, `us-central1`, **no service account**
- [ ] Docker and gVisor installed. Spike 1 confirmed on the VM.
- [ ] Metadata server blocked from Docker networks, firewall set to 80 and 443 only (§11)
- [ ] DuckDNS subdomains, and Caddy serving HTTPS
- [ ] Full stack deployed with Docker Compose
- [ ] Rate limits and size caps on public endpoints
- [ ] Disk snapshot and reset script
- [ ] P1: replay mode on Cloudflare Pages or GitHub Pages

## Phase 5: Ship (Wed Dec 2 – Fri Dec 4)

- [ ] Pre-scan about 200 popular packages (P1)
- [ ] False-positive check on popular packages that have install scripts (P1)
- [ ] GitHub Actions: tests on every push
- [ ] GitHub Actions: npm publish with trusted publishing and provenance
- [ ] npm packages published: `core`, `cli`, `verdaccio-plugin`, `mcp`
- [ ] README final: what it is, try-it steps, self-host steps, "build your own gate", honest limits
- [ ] Video recorded and edited, under 3:00 (§12.3)
- [ ] Video uploaded to YouTube as **public**
- [ ] Kiro write-up drafted from `docs/build-log.md`

## Submission (Devpost) — final check

- [ ] Category: **Skeleton Crew**
- [ ] Public GitHub repo URL
- [ ] License visible in the repo About section
- [ ] `/.kiro` folder committed at the root and **not** in `.gitignore`
- [ ] Two apps in separate folders: `apps/registry-gate/` and `apps/agent-guard/`
- [ ] Working app URL(s), plus admin login in the private Devpost field
- [ ] Text description of features
- [ ] Demo video URL (YouTube, public, under 3 minutes, no copyrighted music)
- [ ] Kiro usage write-up (specs, hooks, steering, custom agent, MCP, powers, PBT)
- [ ] Bonus: **Best Student Project** (LinkedIn, student email, year and degree, school name)
- [ ] Bonus: **Social Blitz** (post starting with `#KiroweenHackathon26`, URL added)
- [ ] Bonus: **Blog** (says it was written for Kiroween 2026, URL added)
- [ ] Submitted before Dec 4, 2:00 PM PT
