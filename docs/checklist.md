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
- [x] **You:** reload Kiro, then check that the steering files, hooks, and agent show up in the Kiro panel
- [x] Fix: hooks couldn't find Node (exit 127). Added the `run-node.sh` launcher
- [x] **Spike 3:** `host-guard` blocks in the IDE. Confirmed: Kiro blocked the command and passed the reason to the agent
- [x] Node 24 LTS installed through nvm (v24.22.3). pnpm 12.21.0 through corepack
- [ ] **You (optional):** make Node 24 your default with `nvm alias default 24`. Otherwise run `nvm use` in this folder
- [x] Public GitHub repo created and pushed: https://github.com/Soham-1304/Sietch
- [x] Skills: `security-review` and `blue-team`. `sandbox-reviewer` loads both
- [x] Security review of the hooks: 3 High, 1 Medium, 2 Low found and fixed. host-guard rebuilt on a strict parser, fail closed
- [x] Hook test suite in the repo: 255 tests, including property tests
- [ ] **You:** run `/security-review` on the hooks in a **new session**, as an independent second review
- [x] Prompt event format confirmed (`prompt` field on stdin, matching what `secret-guard` reads). Probe removed
- [ ] Repo About section shows "Apache-2.0" (GitHub detects it automatically)

## Phase 0b: Specs and scaffolding (Wed Nov 18)

- [x] Spec: `rules-engine` written in `.kiro/specs/rules-engine/` (20 requirements, 14 correctness properties, 12 tasks)
- [x] **You:** review the `rules-engine` requirements and design, then approve or ask for changes (approved Nov 18)
- [x] Implement the `rules-engine` tasks (all 12 done, Nov 18)
- [x] `/security-review` of the rules engine: 2 High, 2 Medium, 2 Low found and fixed (`docs/reviews/`)
- [x] `/blue-team` pass: 11 new threat cards, 1 more bypass fixed (truncated bodies), 2 open items moved to later specs
- [x] Independent review in a new session (`sandbox-reviewer`): no wrong-SAFE verdicts; 1 Medium (SR-7, slow path walk) found and fixed
- [x] Breach re-review (attacks invented without seeing our tests): **PASS**. 4 Low; credential list extended (ruleset 1.1.0), max-size timing test added (366 ms)
- [ ] Spec: `trace-normaliser` (gVisor strace lines to events; possible now that Spike 1 is done)
- [ ] Spec: `sandbox-runner`
- [x] pnpm workspace scaffold with `base/core` as the template package. Other packages are created when their spec starts
- [x] TypeScript 7, Vitest 5, fast-check 4, and Biome 2.6 configured. Commands filled in `tech.md`
- [x] pnpm supply-chain settings: 1-day minimum release age, trust no-downgrade, strict install scripts
- [x] `base/core` purity enforced: no Node types, and restricted globals in Biome
- [x] Hook: `check-on-save` typechecks the package and runs related tests (including rule fixtures) when a `base/` or `apps/` TypeScript file is saved
- [x] Spec prompts written in `docs/spec-prompts.md`
- [x] Colima VM `sietch` with gVisor `release-20261116.0` (no Mac folders shared; Docker Desktop stays the default)
- [x] **Spike 1** (§5.2): **passed.** gVisor `--strace` records a detached child's reads, exec, and connect after the parent exits, and the package can't reach the recorder. Details: `docs/spikes/spike-1-recording.md`
- [ ] Confirm Spike 1 on an x86-64 VM later (different syscall list)
- [ ] **Spike 2** (§6.1): can Verdaccio plugins hide versions, block tarball downloads, and hold a request while a scan runs?
- [ ] **Checkpoint G1:** spike results written in the build log

## Phase 1: Base (Thu Nov 19 – Tue Nov 24)

### Core (`base/core`, pure, P0)
- [x] Event model types (`exec`, `file_read`, `file_write`, `connect`, `dns`, `http`, `exit`) (§5.1)
- [ ] Trace normaliser (raw syscall log to events, never throws)
- [x] Honeytoken matcher (raw, base64 at any alignment, double base64, hex, URL-encoded) (§5.4)
- [x] Rules R1–R10, plus R13 (incomplete trace) (§5.5)
- [x] Verdict logic (MALICIOUS, SUSPICIOUS, SAFE, ERROR treated as blocked)
- [x] Verdict cache key includes the integrity hash and ruleset version (§5.6)
- [x] All core property-based tests from `testing.md` passing (14 properties, 5,000 runs × 3 seeds)

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
