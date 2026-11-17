# Sietch: Build Plan

This is the working plan for building Sietch for Kiroween 2026. It covers what we build, how each part works, what we store, where we host it, how we demo it, and the day-by-day schedule. The name "Sietch" is a working name; branding comes later (see section 17).

---

## 1. Decisions locked

| Decision | Choice |
|---|---|
| Project | Sietch: a checkpoint that detonates npm packages in a sandbox with fake credentials and only lets verified versions through. |
| Category | **Skeleton Crew**: one base and two apps on top of it. |
| Language | **TypeScript everywhere** (Node 24 LTS). We drop FastAPI from the original design, because JavaScript analysis is easiest in Node and one language halves the setup work. |
| Database | **MongoDB** for verdicts and evidence, **Redis** for the job queue and the hot cache. This matches your original MERN plan. |
| Hosting | **One Google Cloud VM paid for by the $300 free-trial credit**, running everything in Docker. **Total spend: $0.** Render, Vercel, and Railway can't run the sandbox (explained in section 11). |
| Distribution | Published **npm packages** (CLI, core library, registry plugin, MCP server) plus Docker images. |
| License | **Apache-2.0.** |
| Team | **Solo.** |
| Eligibility | **No Sietch code exists yet.** Only ideas and text, so the project is eligible. |

## 2. What we build

You described it as "two applications for npm and one for MCP". The rules require **exactly two apps** on one base, so the split is:

| Part | Folder | Who uses it | What it does |
|---|---|---|---|
| **Base** | `base/` | Both apps, and anyone building a new gate | The detonation engine: sandbox, fake credentials, behaviour recording, rules engine, verdict store, API. |
| **App 1: Registry Gate** | `apps/registry-gate/` | Developers and CI pipelines in a company | A private npm registry. Every new package version is checked once, and the verdict is shared with the whole company. Includes the dashboard. |
| **App 2: Agent Guard** | `apps/agent-guard/` | AI coding agents (Kiro first) | An MCP server, a Kiro power, and hooks. It stops the agent installing unsafe or invented packages, and it vets MCP servers before they run. |

The npm packages we publish (section 7) are how people install these parts. They are not separate apps.

**Why these two apps prove the base is flexible.** They serve different users through different entry points. App 1 sits in the npm network path. App 2 sits inside the AI agent's tool loop. Both call the same engine. A short guide in the README, "Build your own gate", shows a third gate (for example PyPI) as an adapter, which supports the Skeleton Crew claim without building a third app.

## 3. The product: "scan once, trust everywhere"

This is how a company would run Sietch.

1. **The security team deploys Sietch** inside its network with one `docker compose up`.
2. **Developers and CI point npm at it** with one command: `npx @<scope>/cli init --url https://sietch.company.internal`. This writes `registry=...` into `.npmrc`.
3. **The first time anyone requests a package version,** Sietch scans it. The install waits up to about 90 seconds while the scan runs.
4. **The verdict is stored against the exact version and its integrity hash.** Every later install of that version, by anyone in the company, is answered from the cache in milliseconds.
5. **Malicious versions are never served.** npm shows a clear error with a link to the evidence page.
6. **Suspicious versions go to review.** A security engineer can approve or block them in the dashboard, giving a reason, and every override is logged.
7. **CI runs `sietch audit`,** which fails the build if the lockfile contains any version without a SAFE verdict.
8. **When rules improve, Sietch re-judges stored recordings without re-running the packages.** If an already-approved version now looks bad, the security team is alerted. We call this a retro-hunt.

**How we answer "why not existing tools?"** (useful for the pitch):

| Tool | What it does | What Sietch adds |
|---|---|---|
| OpenSSF Package Analysis | Detonates packages for research feeds | Sietch sits inline and blocks installs. |
| Socket.dev, Aikido | Commercial SaaS, mainly static and AI analysis | Sietch is self-hosted and open source, and every verdict comes with behaviour evidence. |
| pnpm 10 blocking install scripts | Blocks all scripts until you allowlist a package | Sietch tells you whether a package's scripts are actually safe to allow. |
| All of the above | Built for humans | Sietch also protects AI agents (App 2). |

## 4. Architecture

```
                 developers / CI                       Kiro agent
                       │ npm install                        │ shell tool call
                       ▼                                    ▼
          ┌────────────────────────┐          ┌──────────────────────────┐
          │ App 1: Registry Gate   │          │ App 2: Agent Guard       │
          │ Verdaccio + Sietch     │          │ Pre Tool Use hook        │
          │ plugins                │          │ MCP server, Kiro power   │
          └───────────┬────────────┘          └────────────┬─────────────┘
                      │  check / enqueue (HTTP)            │
                      ▼                                    ▼
          ┌─────────────────────────────────────────────────────────────┐
          │ BASE                                                        │
          │  API (Fastify) ── Redis (BullMQ queue, verdict cache, pubsub)│
          │       │                     │                               │
          │       │               Worker(s)                             │
          │       │          1. fetch tarball + deps (trusted, scripts off)
          │       │          2. static checks                           │
          │       │          3. detonate in gVisor sandbox ─┐           │
          │       │          4. normalise trace → events    │           │
          │       │          5. rules engine → verdict      │           │
          │       ▼                                         ▼           │
          │  MongoDB (packages, scans, events,     Capture sink         │
          │  verdicts, audit)                      (fake DNS/HTTP/HTTPS)│
          └─────────────────────────────────────────────────────────────┘
                      ▲
                      │ REST + live stream (SSE)
          ┌───────────┴────────────┐
          │ Dashboard (React)      │
          └────────────────────────┘
```

## 5. The base in detail

### 5.1 Scan pipeline

Every package version goes through these steps.

| Step | Where it runs | What happens |
|---|---|---|
| 1. Fetch | Trusted fetch container, network to the npm registry only | Download the tarball and its dependencies with `--ignore-scripts`. No package code runs here. Check the integrity hash. |
| 2. Static checks | Worker | Read `package.json` and the file list. Flag install scripts, `child_process`, `eval` of decoded strings, very long base64 or high-entropy strings, and unusually large single JS files. |
| 3. Diff (P1) | Worker | Compare with the previous version: new install scripts, new obfuscated files, new dependencies, a big size jump. |
| 4. Detonate | gVisor sandbox, no real network | Run the install scripts, then `require()` and `import()` the package, then **keep watching for 60 seconds after npm exits**. |
| 5. Normalise | Worker | Turn the raw syscall log into clean events: `exec`, `file_read`, `file_write`, `connect`, `dns`, `http`, `exit`. |
| 6. Judge | Worker (pure function) | The rules engine turns events and static findings into a verdict with evidence. |

The 60-second watch in step 4 matters. In the November 2025 Shai-Hulud 2.0 wave, the payload forked itself into a detached background process so the install looked clean, then did its work afterwards ([Unit 42](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)).

**Tiers keep it fast.** Detonation runs only for versions that have install scripts, raise static flags, or are newer than a policy threshold (for example 14 days). Other versions get the static checks only, which take a few seconds. Companies can switch to "detonate everything".

### 5.2 The sandbox

| Control | Setting |
|---|---|
| Runtime | **gVisor (`runsc`)**: a user-space kernel, so package code never talks to the host kernel directly. |
| Filesystem | Read-only root, a writable tmpfs for the project and fake home, no host mounts. |
| User | Non-root, all capabilities dropped, `no-new-privileges`. |
| Limits | CPU, memory, process count, 3-minute wall clock limit. |
| Network | An internal Docker network whose only member is the capture sink. There is no route to the internet or to the cloud metadata service. |
| Lifetime | One container per scan, destroyed afterwards. |

**Recording behaviour.** We record outside the sandbox's kernel, so malware can't hide from it or tamper with it. This also sees every child process, including runtimes like Bun that Shai-Hulud 2.0 installed (`setup_bun.js`, `bun_environment.js`). The two candidates are gVisor's built-in syscall logging (`runsc --strace`) and gVisor runtime monitoring. Spike 1 picks one (section 15). Running `strace` inside the container is the fallback, but malware can detect it.

### 5.3 Fake credentials (honeytokens)

Each scan gets a fake home directory and environment that look like a real developer laptop or CI runner. **Every token value is unique to that scan**, so any leak can be traced to the exact package.

| Bait | Example format |
|---|---|
| `~/.npmrc` | `//registry.npmjs.org/:_authToken=npm_<random>` |
| `~/.config/gh/hosts.yml`, `GITHUB_TOKEN` | `ghp_<random>` |
| `~/.aws/credentials`, `AWS_ACCESS_KEY_ID` | `AKIA<random>` plus a fake secret |
| `~/.ssh/id_ed25519` | Fake private key |
| Project `.env` | Fake database URL and API keys |
| CI environment variables | `CI=true`, `GITHUB_ACTIONS=true`, fake runner names |

### 5.4 Fake network (capture sink)

- **DNS**: every name resolves to the sink, and every query is logged.
- **HTTP and HTTPS**: the sink accepts every request and records host, path, headers, and body. The sandbox trusts our own certificate authority (through `NODE_EXTRA_CA_CERTS` and the system store), so we can read HTTPS bodies too. If a package pins certificates, we still record the server name it tried to reach.
- **Token matching**: the sink searches every request for our honeytokens, raw and encoded (base64, double base64, hex, URL-encoded).
- **Legitimate downloads**: when `esbuild` or `sharp` fetch their binaries, the request is recorded and the domain is checked against an allowlist. This avoids failing normal packages.

### 5.5 Rules engine

The engine is deterministic: a pure function from (events, static findings, ruleset version) to a verdict. The same input always gives the same output, and no AI is involved in judging.

| ID | Rule | Severity |
|---|---|---|
| R1 | A honeytoken value appears in outgoing network traffic | Critical |
| R2 | During install, reads credential files (`.npmrc`, `.aws`, `.ssh`, `gh`, `.env`) | High |
| R3 | Connects to a host that is not on the allowlist during install | High |
| R4 | Downloads and runs a new binary or runtime (for example Bun or Deno) | High |
| R5 | Starts a shell with network tools (`curl`, `wget`, `nc`) | High |
| R6 | Writes outside its own package folder (home directory, other packages, `.github/workflows`) | High (Critical for workflows) |
| R7 | Calls npm publish or token APIs (worm spreading) | Critical |
| R8 | Calls GitHub APIs that create repos or runners | Critical |
| R9 | Deletes or overwrites many files in the home directory (wiper) | Critical |
| R10 | Leaves a detached process running after install | Medium |
| R11 | Obfuscated code (high entropy, `eval` of decoded data) | Medium |
| R12 | New install script compared with the previous version (P1) | Medium |

**Verdict logic:** any Critical finding gives MALICIOUS. Any High finding gives SUSPICIOUS. Otherwise the verdict is SAFE. If the scan fails, the verdict is ERROR, and ERROR is treated as blocked (fail closed) and retried.

Every finding points to the exact events that triggered it, so the dashboard can show "this rule fired because of these events".

### 5.6 Verdict cache

- The cache key is `name@version` plus the **integrity hash**. If the hash ever changes, the cached verdict no longer applies.
- The verdict also records the **ruleset version**. When rules change, stored events are re-judged without re-running the package (the retro-hunt from section 3).

## 6. The two apps

### 6.1 App 1: Registry Gate (`apps/registry-gate/`)

**What it is:** Verdaccio, an open source npm registry proxy, plus two Sietch plugins, plus the dashboard.

Verdaccio's own docs say a filter plugin only changes the package metadata npm sees. It does not stop anyone downloading a hidden version's tarball ([Verdaccio filter docs](https://www.verdaccio.org/dev/plugin-filter/)). So we need two layers:

| Layer | Plugin type | Job |
|---|---|---|
| Metadata filter | Filter plugin | Removes MALICIOUS versions from the version list npm sees, so npm resolves to a safe version where it can. |
| Tarball guard | Middleware plugin | Intercepts every tarball download. SAFE: serve it. MALICIOUS or SUSPICIOUS: return 403 with a reason and an evidence link. Unknown: start a scan and hold the request until the verdict arrives. |

**Policy modes** (configurable): `hold` (wait for the verdict, the default), `hide` (show only verified versions), and `warn` (serve, but log and alert).

**CLI commands** (in the `@<scope>/cli` package):

| Command | What it does |
|---|---|
| `sietch init --url <gate>` | Points npm at the gate by writing `.npmrc`. |
| `sietch scan <pkg@version>` | Runs a scan on the server and prints the verdict and evidence. A `--local` flag runs it in local Docker. |
| `sietch check <pkg@version>` | A fast verdict lookup. |
| `sietch audit` (P1) | Checks every lockfile entry. Exits non-zero if any lacks a SAFE verdict. Used in CI. |

**Fallback:** if Spike 2 shows the Verdaccio plugins can't do what we need, we write a small proxy in Fastify. It would fetch metadata from upstream, filter it, rewrite tarball URLs to point at us, and guard downloads. That is about 300 to 500 lines.

### 6.2 App 2: Agent Guard (`apps/agent-guard/`)

**What it is:** a Kiro power that keeps AI agents safe from packages and MCP servers.

| Part | What it does |
|---|---|
| **MCP server** (`@<scope>/mcp`) | Exposes `check_package(name, version)`, `explain_verdict(name, version)`, `suggest_safe_version(name)`, and `vet_mcp_server(command)`. |
| **Pre Tool Use hook** | Matches the shell tool. When the agent is about to run `npm install`, `npm i`, `pnpm add`, `yarn add`, or `npx`, the hook extracts the packages and asks Sietch about them. If any is unsafe or doesn't exist, it exits with code 2. Kiro then blocks the command and passes the reason back to the agent, so the agent can choose something else. Kiro's docs say Pre Tool Use hooks can validate and block tool calls ([Kiro hook types](https://kiro.dev/docs/hooks/types/)). Spike 3 confirms exactly how blocking behaves in the IDE. |
| **Invented-package check** (P1) | Flags names that don't exist on npm (a likely LLM hallucination), were created in the last few days, have very few downloads, or are one typo away from a popular package. This catches "slopsquatting", where attackers register package names that LLMs invent. |
| **MCP server vetting** | MCP servers are npm packages that run with your credentials. In September 2025, an unofficial `postmark-mcp` package started quietly BCCing every email it sent to an attacker ([The Hacker News](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html)). Agent Guard detonates an MCP server's package with the base. It also starts the server in the sandbox, lists its tools, and checks tool descriptions for hidden instructions aimed at the agent (tool poisoning). |
| **Config watch hook** | A File Save hook on `.kiro/settings/mcp.json`. When a new MCP server is added, the hook vets it and warns. |
| **Steering in the power** | Tells the agent to check every new dependency and MCP server with Sietch first, and how to read a verdict. |

**How the two apps support each other:** if the developer's npm already points at the Registry Gate, `npx some-mcp-server` is also checked at the network level. App 2 adds the agent-aware layer on top. It blocks earlier, explains why, and steers the agent to an alternative.

**We use this ourselves:** once App 2 works, we enable it in our own Kiro workspace. This gives a strong story for the write-up: Sietch protected the agent that was building Sietch.

## 7. npm packages we publish

The plain name `sietch` is already taken on npm (by an unrelated database library). We publish under an npm org scope, which we pick at branding time.

| Package | Contents | Used by |
|---|---|---|
| `@<scope>/core` | Types, event model, rules engine, verdict logic. Pure TypeScript, no Docker. | Both apps, and anyone building a gate |
| `@<scope>/cli` | The `sietch` command (section 6.1) | Developers and CI |
| `@<scope>/verdaccio-plugin` | The filter and tarball guard plugins | App 1 |
| `@<scope>/mcp` | The MCP server, runnable with `npx` | App 2 and the Kiro power |

The server and worker ship as Docker images on GitHub Container Registry, with a `docker-compose.yml` for self-hosting.

**How we publish safely.** Supply-chain security is the whole pitch, so our own packages must be clean:

- Publish from GitHub Actions with npm **trusted publishing** (OIDC) and **provenance**. No long-lived npm token exists anywhere.
- **None of our packages has install scripts.**
- **Sietch scans its own packages in CI before each release.**

## 8. Data: what we store

### MongoDB (Atlas free tier for the demo, or self-hosted)

| Collection | Key fields | Purpose |
|---|---|---|
| `packages` | `name`, `version`, `integrity`, `publishedAt`, `hasInstallScripts`, `firstSeenAt` | One record per version we have seen. |
| `scans` | `packageId`, `status` (queued / running / done / failed), `tier`, `engineVersion`, `startedAt`, `durationMs`, `rawTraceRef`, `error` | One record per scan run. |
| `events` | `scanId`, `seq`, `t`, `pid`, `ppid`, `type`, `data` | The normalised behaviour timeline, capped at about 5,000 events per scan. Indexed on `scanId, seq`. |
| `verdicts` | `packageId`, `integrity`, `rulesetVersion`, `verdict`, `findings[]` (rule, severity, evidence event IDs, explanation), `decidedBy` (engine or a person), `override` | The decision and its evidence. |
| `policies` | Mode, detonation threshold, network allowlist, package allowlist | Company settings. |
| `audit_log` | `actor`, `action`, `target`, `reason`, `at` | Every manual override and settings change. |
| `users` | Admin accounts and API keys (hashed) | Minimal auth for the dashboard's admin actions. |

### Redis

- The BullMQ `scan` queue.
- The hot verdict cache: `verdict:<name>@<version>:<integrity>`.
- Pub/sub for live scan events, which feeds the dashboard's live view.

### Disk (EBS volume)

- Raw syscall logs, gzipped, one file per scan. Kept so we can re-normalise if the parser improves.
- The tarball cache (Verdaccio storage).

**Privacy note:** we store only package behaviour and our own fake credentials. No user code or real secrets ever enter the system.

## 9. API (base server, Fastify)

| Method and path | Purpose | Auth |
|---|---|---|
| `GET /api/check?name=&version=` | Fast verdict lookup. Starts a scan if the version is unknown. | API key (public demo key, rate limited) |
| `POST /api/scans` | Start a scan explicitly. | API key, rate limited |
| `GET /api/scans/:id` | Scan status. | Public (read-only) |
| `GET /api/scans/:id/events` | The event timeline. | Public |
| `GET /api/scans/:id/stream` | Live events (server-sent events). | Public |
| `GET /api/packages` | Search and filter by verdict. | Public |
| `GET /api/packages/:name/:version` | Verdict, findings, and evidence. | Public |
| `POST /api/verdicts/:id/override` | Approve or block, with a required reason. | Admin |
| `GET /api/stats` | Counts for the overview page. | Public |

Request bodies are validated with schemas (zod or TypeBox) at every entry point.

## 10. Frontend: the dashboard

You said frontend isn't your strength, so the dashboard is small and built from a component library: **React + Vite + TypeScript + Tailwind + shadcn/ui**. Kiro writes most of it from a spec. When we polish it, we can use the frontend design skill available in Kiro (`impeccable`).

| Page | Shows | Priority |
|---|---|---|
| **Live chamber** | Scans running now, with events streaming in as they happen (process started, file read, connection attempted). Honeytoken hits flash red. This is the star of the demo. | P0 |
| **Verdict page** | A verdict banner, each finding with the events that caused it, the process tree, and the network attempts. | P0 |
| **Packages** | A searchable table of every version with a verdict badge. | P0 |
| **Overview** | Totals: scanned, blocked, cache hits, average scan time. | P1 |
| **Review queue** | SUSPICIOUS versions with approve and block buttons (admin only, reason required). | P1 |
| **Try it** | Copy-paste commands so judges can test the hosted gate themselves. | P0 |

Halloween styling can come with branding. The core screens work without it.

## 11. Hosting and deployment (all free)

**The budget is $0.** Every service below is free, or paid for by free credits. Prices are approximate. We check the GCP pricing calculator before creating the VM.

### Why a VM, and not Render

The sandbox needs Docker with the gVisor runtime installed on the host. Render, Vercel, Railway, and similar platforms run your code inside their own containers, and they don't let you install a container runtime. So **the scanning must run on a VM we control.** The simplest setup is to put everything on that one VM.

### Free options for the VM

| Option | What you get free | Good | Bad | Verdict |
|---|---|---|---|---|
| **GCP free trial** | $300 credit for 90 days, for new customers ([Google Cloud](https://docs.cloud.google.com/free/docs/free-cloud-features)) | Normal x86 Linux VMs, reliable, and you can claim it now. An `e2-standard-2` (2 vCPU, 8 GB) costs roughly $50 per month, so it can run about 4 months on the credit; the 90-day expiry ends it first. | Needs a payment method for verification. You are not charged unless you manually upgrade to a paid account. | **Primary.** |
| GCP Always Free `e2-micro` | 1 small VM (2 shared vCPUs, 1 GB RAM) in selected US regions, with no end date | Free forever | 1 GB of RAM can't run the sandbox alongside Verdaccio, the API, and Redis | Not enough on its own. |
| Oracle Cloud Always Free | Arm VM, now **2 OCPU / 12 GB**. Oracle halved this in June 2026 ([details](https://terminalbytes.com/oracle-cloud-free-tier-changes-2026/)). | Free forever, and enough power | Often "out of capacity" at signup. Oracle disabled many free instances during the 2026 change. Arm only. | **Backup** for after the GCP credit runs out. |
| AWS Free plan (new accounts) | $100 credit, plus up to $100 more by completing activities. The account is suspended after 6 months or when the credits run out ([AWS](https://docs.aws.amazon.com/accounts/latest/reference/bcm-lite-free-tier.html)). | Also free | Only for new accounts, and smaller than the GCP credit | Second backup. |

**Plan:**

1. Claim the GCP trial and run one `e2-standard-2` VM in `us-central1`. Most judges are probably in the US.
2. Set a **budget alert at $250** so the credit never runs out by surprise.
3. Claiming on Nov 17 means the credit lasts until about **Feb 15, 2027**, which should cover judging.

**After the credit runs out,** we keep a free **replay mode** online (see "Replay mode" below) and optionally move the live stack to Oracle's free Arm VM.

**Development stays on your Mac** with Docker, which is free. Locally we only run our own harmless test packages, using the normal Docker runtime. Real detonation only happens on the cloud VM. The first deploy happens by Nov 24, so hosting problems show up early.

### Every other piece, free

| Need | Free choice | Notes |
|---|---|---|
| Database | **MongoDB Atlas free cluster** | 512 MB storage, no time limit. We cap stored events per scan so it fits. Raw logs live on the VM disk, not in Atlas. |
| Queue and cache | **Redis in Docker on the VM** | Free. Hosted free Redis plans count every command, and the BullMQ queue polls constantly, so they would run out. |
| Domain and HTTPS | **DuckDNS** free subdomains (up to 5 per account) plus **Caddy** with Let's Encrypt | For example `sietch-app.duckdns.org` and `sietch-registry.duckdns.org`. A custom domain can come with branding later. If you are a student, the GitHub Student Developer Pack includes a free domain. |
| Dashboard hosting | Served by Caddy on the VM | Replay mode also goes on **Cloudflare Pages** or **GitHub Pages**, which are free. |
| CI and releases | **GitHub Actions** (free for public repos) | Also publishes to npm with trusted publishing. |
| Docker images | **GitHub Container Registry** | Free for public images. |
| npm packages | **npm public packages and org scope** | Free for public packages. |
| Kiro | **Hackathon Kiro credits** | Request them from the Resources tab. |
| Video | **OBS Studio** (record), **DaVinci Resolve** or **Shotcut** (edit), **YouTube** (host) | All free. Use no music, or music whose license allows use. |
| Blog and social | dev.to, Hashnode, or Medium, plus X or LinkedIn | Free. |

### Replay mode (P1)

This is a static copy of the dashboard, built with recorded scan data from real runs:

- the worm being caught,
- benign packages passing,
- an agent being blocked.

It is hosted free on Cloudflare Pages or GitHub Pages, with no time limit. If the VM is ever down, or the credit runs out during judging, judges can still see the product working. The banner clearly says it shows recorded scans.

### What runs on the VM (Docker Compose)

| Service | Purpose |
|---|---|
| `caddy` | HTTPS (automatic Let's Encrypt certificates) and routing for the dashboard, API, and registry hostnames. |
| `api` | Base API server. |
| `worker` | Scan worker, which launches sandbox containers. Two workers in parallel. |
| `verdaccio` | Registry Gate with the Sietch plugins. |
| `capture-sink` | Fake DNS and HTTP/HTTPS for sandboxes, on an internal-only network. |
| `redis` | Queue and cache. |
| MongoDB | Atlas free cluster (external). |

The dashboard is static files built by Vite and served by Caddy.

### Hardening the host (GCP)

The VM runs untrusted code on purpose, so we lock it down.

- **No service account on the VM.** Choose "No service account" when creating it. Then there are no Google Cloud credentials on the box to steal.
- **Block the metadata server** (`169.254.169.254`) from all Docker networks with an iptables rule in the `DOCKER-USER` chain. Google's metadata server only asks for a request header, which malware can easily add.
- **Firewall:** only ports 80 and 443 are open to the public. SSH goes through `gcloud compute ssh` with IAP, or port 22 is open only to your IP.
- **Sandbox containers** join only an internal Docker network with no outbound route.
- **A dedicated GCP project** with nothing else in it.
- **A reset script plus a disk snapshot,** so the VM can be rebuilt in minutes if something goes wrong.
- **Rate limits for the public demo:** at most 2 scans running at once, a 50 MB tarball size cap, and per-IP limits.
- **The budget alert** from the plan above.

Note that the GCP free trial doesn't allow certain things, such as GPUs or crypto mining. Nothing in this plan needs them.

## 12. Demo

### 12.1 How judges test it

- **Dashboard:** `https://sietch-app.duckdns.org` (placeholder until branding). Read-only for everyone. Admin login details go in the private Devpost field.
- **Registry:** judges can run `npm install <any-package> --registry https://sietch-registry.duckdns.org` and watch the scan in the live chamber.
- **The demo worm:** `npm install @sietch-demo/<name> --registry https://sietch-registry.duckdns.org` gets blocked, with an evidence link.
- **Agent Guard:** install the power from our GitHub repo into Kiro and ask the agent to add a dependency.
- **Pre-scanned cache:** before submission we pre-scan about 200 popular packages, so judges see instant cache hits.
- **Replay mode:** a permanent static copy of the dashboard on Cloudflare Pages or GitHub Pages, with recorded scans. It works even if the VM is down.

### 12.2 The demo worm (harmless lookalike)

A package that behaves like Shai-Hulud but can't hurt anyone:

- A preinstall script reads `~/.npmrc` and the GitHub and AWS credential files, then forks a detached background process.
- The background process sends the data to a `.invalid` domain. `.invalid` is reserved by RFC 2606 and never resolves, so even on a real machine nothing leaves.
- It tries to write `.github/workflows/<name>.yml` and to call the npm publish API.
- **It is published only to our own registry, never to npmjs.org.** Its README states clearly that it is a test sample.
- A second, benign package with a legitimate install script (one that downloads a binary from an allowlisted host) shows that Sietch doesn't block normal packages.

### 12.3 Video script (target 2:45, limit 3:00)

| Time | Scene |
|---|---|
| 0:00–0:20 | **The problem.** Shai-Hulud 2025: hundreds of npm packages compromised, 25,000+ GitHub repos, secrets stolen within seconds of `npm install`. |
| 0:20–0:35 | **The idea.** A company runs Sietch. Every new package version is detonated once, with fake credentials, before anyone runs it. |
| 0:35–1:15 | **App 1 live.** A developer installs the worm lookalike. In the live chamber: the preinstall starts, credential files are read, a detached process appears, the honeytoken shows up in an outgoing request. Verdict: MALICIOUS. npm prints the block with an evidence link. |
| 1:15–1:30 | **Scan once, trust everywhere.** A colleague installs a verified package. It is served instantly from the cache. |
| 1:30–2:10 | **App 2 live.** In Kiro, we ask the agent to add a library. It tries an invented package name, the hook blocks it, and Agent Guard explains why. The agent picks a verified package instead. Then we add a suspicious MCP server to `mcp.json` and get warned. |
| 2:10–2:35 | **How Kiro built it.** Specs, property-based tests catching a real bug, hooks, steering, and Sietch guarding our own Kiro session. |
| 2:35–2:45 | **Close.** Open source, self-hostable, link to the repo. |

Use self-made or royalty-free audio, and no Dune imagery.

## 13. Kiro usage plan (for the write-up)

Each feature has a real job. We log what happens in `docs/build-log.md` as we go.

| Kiro feature | How we use it |
|---|---|
| **Steering** | Always on: `product.md`, `tech.md`, `structure.md`, `security.md`. Loaded only for test and core files: `testing.md`. Manual (`#name` in chat): `plan-reference.md` and `hackathon-rules.md`, which link to the live docs with `#[[file:...]]`. |
| **Specs** | One spec per component: `sandbox-runner`, `rules-engine`, `verdict-api`, `registry-gate`, `dashboard`, `agent-guard`. Each has requirements in EARS format, a design, and tasks. |
| **Property-based testing** (fast-check) | The same events always give the same verdict. Adding a finding never makes a verdict safer. A different integrity hash never reuses a cached verdict. Honeytoken detection catches every encoding we support. Honeytokens are unique per scan. The event normaliser never crashes on any input. The hook's command parser finds every package in any valid install command. |
| **Hooks** | **In place now:** `host-guard` (Pre Tool Use on shell) blocks unsafe commands on the host, `secret-guard` (Prompt Submit) blocks real secrets pasted into chat, and `post-task-verify` (Post Task Execution) runs checks after each spec task. **Added later:** File Save on rule files runs the fixtures, File Save on `base/**/*.ts` runs typecheck and related tests, Agent Guard's own Pre Tool Use hook, and File Save on `mcp.json` vets new MCP servers. |
| **MCP and powers (during development)** | Context7 for current docs (Verdaccio, BullMQ, MCP SDK, gVisor). The MongoDB power for schema and index design. The Postman power for API test collections. |
| **Our own power** | Agent Guard is a Kiro power: `plugin.json`, `mcp.json`, and skills ([Kiro powers docs](https://kiro.dev/docs/powers/create/)). |
| **Custom agent** | `sandbox-reviewer` (`.kiro/agents/`): a read-only reviewer loaded with the security steering. It reviews every change to the sandbox, network, and hosting code and returns PASS or FAIL. |

## 14. Repository layout

```
sietch/
├── .kiro/
│   ├── steering/          product.md, tech.md, structure.md, security.md, testing.md
│   ├── specs/             one folder per component
│   ├── hooks/             hook definitions (*.json)
│   └── settings/mcp.json
├── base/                  THE SKELETON
│   ├── core/              @<scope>/core: event model, rules, verdicts (pure, fully tested)
│   ├── sandbox/           sandbox and capture-sink Dockerfiles, runner, honeytoken generator
│   ├── server/            API, worker, queue, database access
│   └── cli/               @<scope>/cli
├── apps/
│   ├── registry-gate/     APP 1: Verdaccio plugins, dashboard, compose file
│   └── agent-guard/       APP 2: MCP server, Kiro power, hook scripts
├── demo/                  worm lookalike, benign samples, seed scripts
├── deploy/                production compose, Caddyfile, VM setup script
├── docs/                  overview, ideation, plan, build log, write-up drafts
├── LICENSE
└── README.md              setup, "try it", "build your own gate"
```

This is a pnpm workspace. pnpm also fits the theme, because it doesn't run dependency install scripts by default.

## 15. Schedule

Today is Mon Nov 16. The deadline is Fri Dec 4, 2:00 PM PT, which is **Sat Dec 5, 3:30 AM IST**. We aim to submit by **Fri Dec 4, evening IST**.

### Phase 0: Setup and spikes (Tue Nov 17 – Wed Nov 18)

- Create the repo with LICENSE, README, `.kiro/steering`, and the build log. Make the first commit.
- Claim the GCP free trial, set the $250 budget alert, create the VM (no service account), and install Docker and gVisor. Create the Atlas free cluster and the DuckDNS subdomains.
- **Spike 1 (sandbox):** can we see a detached child process's file reads and connections from outside gVisor? Choose between `runsc --strace` and runtime monitoring.
- **Spike 2 (registry):** can Verdaccio plugins hide versions, block tarballs, and hold a request while a scan runs? If not, switch to the custom proxy.
- **Spike 3 (Kiro hook):** does a Pre Tool Use hook in Kiro IDE block a shell command and show our reason to the agent?

**Checkpoint G1 (Nov 18):** all three spikes are decided and written in the build log.

### Phase 1: Base (Thu Nov 19 – Tue Nov 24)

| Date | Work |
|---|---|
| Nov 19–20 | Sandbox image, honeytoken generator, capture sink, runner. |
| Nov 21 | Raw trace to normalised events. |
| Nov 22 | Rules engine, property-based tests, fixtures (worm lookalike and benign samples). |
| Nov 23 | MongoDB models, Redis queue, worker, API, live stream. |
| Nov 24 | `sietch scan` working end to end. **First deploy to the GCP VM.** |

**Checkpoint G2 (Nov 24):** `sietch scan` on the worm lookalike returns MALICIOUS with evidence, on the GCP VM.

### Phase 2: App 1, Registry Gate (Wed Nov 25 – Sat Nov 28)

| Date | Work |
|---|---|
| Nov 25–26 | Verdaccio plugins (filter, tarball guard, hold mode), clear npm error messages, `sietch init` and `check`. |
| Nov 27–28 | Dashboard: live chamber, verdict page, packages table, try-it page. |

**Checkpoint G3 (Nov 28):** `npm install` through the hosted gate blocks the worm and serves safe packages. The dashboard shows it live. **The name must be final today**, because npm scope, domain, and package names depend on it.

### Phase 3: App 2, Agent Guard (Sun Nov 29 – Tue Dec 1)

| Date | Work |
|---|---|
| Nov 29 | MCP server and tools. |
| Nov 30 | Kiro power, Pre Tool Use hook, invented-package check. Enable it in our own workspace. |
| Dec 1 | MCP server vetting and the `mcp.json` hook. |

**Checkpoint G4 (Dec 1):** in a real Kiro session, the agent is blocked from installing an unsafe package and picks a safe alternative.

### Phase 4: Ship (Wed Dec 2 – Fri Dec 4)

| Date | Work |
|---|---|
| Dec 2 | Harden the host, pre-scan popular packages, measure false positives on popular packages with install scripts, publish npm packages with provenance. |
| Dec 3 | Record and edit the video, upload it to YouTube as public. |
| Dec 4 | Final README, Kiro write-up, blog post, social post with `#KiroweenHackathon26`, submit on Devpost. |

**Checkpoint G5 (Dec 3):** the video is uploaded. Dec 4 is for writing and submitting only.

## 16. Priorities and cut list

The schedule has almost no spare days, so the cut list provides the buffer. If a checkpoint slips, we cut from the bottom up.

| Priority | Items |
|---|---|
| **P0 (must ship)** | Sandbox and honeytokens, capture sink, event normaliser, rules R1–R10, verdict store and cache, API, `sietch scan`, registry gate (block and hold), dashboard (live chamber, verdict page, packages table, try-it page), MCP server with `check_package` and `explain_verdict`, Kiro power, Pre Tool Use hook, demo worm, GCP hosting, published packages, video. |
| **P1 (should ship)** | Static diff against the previous version (R12), invented-package check, MCP server vetting, `sietch audit` for CI, review queue and overrides, overview page, pre-scan, false-positive benchmark, replay mode. |
| **P2 (only if ahead)** | Retro-hunt, platform spoofing (fake Windows or macOS), clock skew, fake cloud metadata endpoint, PyPI adapter, signed verdicts that companies can share, a test run against Datadog's public malicious package dataset. |

If App 2's MCP server vetting is cut, App 2 still has the hook, MCP tools, and power, which is enough for it to count as a distinct app.

## 17. Risks and honest limitations

| Risk | Mitigation |
|---|---|
| gVisor tracing doesn't give us what we need | Spike 1 on day 2. Fallback: `strace` inside the container. |
| Verdaccio plugins can't hold or block | Spike 2. Fallback: a small Fastify proxy. |
| Big dependency trees make first installs slow | Static-only tier for low-risk versions, two workers, pre-scanned popular packages, and every version is scanned only once. |
| False positives on legitimate packages | Network allowlist for known binary hosts, a false-positive benchmark, and a review queue. |
| Malware detects the sandbox and stays quiet | Realistic fake home and CI environment. Static checks still run. We say openly that no sandbox catches everything. |
| Malware that only runs in browsers | Example: the September 2025 `chalk`/`debug` compromise targeted browser crypto wallets. Detonation in Node won't see it, but the static diff can flag new obfuscated code. We state this limitation. |
| The free credit runs out, or the VM gets abused | $250 budget alert, a dedicated GCP project, rate limits, size caps, and replay mode as a permanent free fallback. Oracle's free Arm VM is the backup for the live stack. |
| Too much scope for one person (solo build) | Checkpoints plus the cut list. Kiro specs and hooks carry the repetitive work, and the dashboard is kept to a few component-library pages. |

## 18. Open decisions

1. **Name:** final by **Nov 28**, because the npm scope, the subdomains, and the package names depend on it.
2. **GCP trial:** claim it once the base works locally (around Nov 24), so the 90-day credit covers judging. Coding comes first.

**Settled:** solo, student (GitHub Student Developer Pack already claimed), not registered for Kiroween 2025. Bonus targets: Best Student Project, Social Blitz, Blog, and Best Demo (automatic).

## Sources

- [Unit 42: Shai-Hulud and Shai-Hulud 2.0](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/): preinstall execution, `setup_bun.js` and `bun_environment.js`, detached background process, `.github` workflow persistence, home directory wiper.
- [The Hacker News: malicious postmark-mcp server](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html), September 2025.
- [Verdaccio filter plugin docs](https://www.verdaccio.org/dev/plugin-filter/): filters don't block tarball downloads.
- [Kiro hook types](https://kiro.dev/docs/hooks/types/): Pre Tool Use can validate and block tool calls.
- [Kiro powers: create](https://kiro.dev/docs/powers/create/): `plugin.json`, `mcp.json`, skills.
- [Google Cloud free features and trial](https://docs.cloud.google.com/free/docs/free-cloud-features): $300 credit for 90 days, plus Always Free limits.
- [Oracle free tier 2026 changes](https://terminalbytes.com/oracle-cloud-free-tier-changes-2026/): Arm allocation halved to 2 OCPU / 12 GB.
- [AWS Free Tier for new accounts](https://docs.aws.amazon.com/accounts/latest/reference/bcm-lite-free-tier.html): $100 credit plus up to $100 more.
- [MongoDB Atlas free cluster limits](https://www.mongodb.com/docs/atlas/reference/free-shared-limitations/).

Content from these sources was rephrased for compliance with licensing restrictions.
