# Evasion catalogue

Techniques that real npm malware uses, or that an attacker who knows Sietch would try. They are grouped by the attacker's goal. Each entry lists the defence to look for.

## A. Escape the sandbox or harm the host

| Technique | Defence to look for |
|---|---|
| Kernel exploit from inside the container | gVisor (`runsc`): package syscalls hit gVisor's user-space kernel, not the host kernel. |
| Docker socket, host mounts, `--privileged`, host namespaces | None of these are ever set. `host-guard` blocks them in shell commands. Code review checks the Docker arguments. |
| Reaching the cloud metadata server (`169.254.169.254`) for VM credentials | Internal-only network, an iptables block in `DOCKER-USER`, and no service account attached to the VM. |
| Reaching the internet directly by IP, skipping DNS | No route out. The only peer is the capture sink. Raw IP connections are recorded as `connect` events. |
| Fork bomb, memory or disk exhaustion to take down the worker or host | pids, memory, CPU, and tmpfs size limits, plus a wall-clock kill of the whole container. |
| Huge tarball or decompression bomb that hits the fetcher before the sandbox | Streaming size limits and entry count limits in the trusted fetch step. |
| Path traversal in tar entries during extraction on the host side | Strict entry validation (see the security-review checklist, section 2). |
| Attacking the capture sink (malformed HTTP, huge bodies, slowloris) | The sink is hardened like a public server: body caps, timeouts, and it runs as an unprivileged container. |
| Poisoning the trace output, for example printing fake log lines to stdout | The trace is recorded outside the sandbox. Package stdout is data and is never parsed as trace. |
| Hostile text aimed at an LLM or a person (prompt injection in README or tool descriptions) | Package text is never treated as instructions. Show it as escaped text only. |

## B. Hide from the recording

| Technique | Defence to look for |
|---|---|
| Spawning a different runtime (Bun, Deno, Python, a shell) to avoid Node-level hooks. Shai-Hulud 2.0 installed Bun. | Recording happens at the syscall level, outside the sandbox, so it covers every process. |
| Detaching a background process so the install looks clean. Shai-Hulud 2.0 did this. | Keep watching after npm exits (60 s). Record leftover processes (R10). |
| Killing or detecting the tracer from inside | The tracer lives outside the sandbox and can't be reached. |
| Running code in a `node_modules/.bin` shim, a `prepare` script, or a binding file | All lifecycle scripts run, then `require` and `import`, then the observation window. |
| Exfiltrating through DNS (data encoded in subdomains) | DNS queries are recorded, and query names are scanned for honeytokens. |
| Exfiltrating over a protocol other than HTTP (raw TCP, UDP, ICMP) | `connect` events are recorded for all protocols. Payload capture is only possible for protocols the sink speaks, so this is detection by destination only. |
| Splitting or encoding the token (base64 twice, hex, reversed, XOR, chunked across requests) | The matcher handles the listed encodings. Reversed, XOR, and chunked can be missed. Back them up with R2 (read a credential file) plus R3 (contacted an unknown host). |
| Too many events, so the evidence falls past the event cap | Hitting the cap is recorded and raises the verdict to at least SUSPICIOUS. |

## C. Behave well only in the sandbox

| Technique | Defence to look for |
|---|---|
| Checking CI variables, hostname, username, or home directory contents | A realistic fake developer or CI environment. Values vary per scan. |
| Checking for gVisor or containers (`/proc/1/cgroup`, `dmesg`, `/.dockerenv`, CPU count, uptime) | Accepted limitation in part. Reads of these paths can themselves be a signal (a rule candidate). |
| Waiting (sleep, `setTimeout` for minutes, or a date check) | A time-skew option (P2). Long-sleeping processes left at the end are recorded (R10). Accepted limitation for long delays. |
| Only acting on a specific OS (`process.platform === "win32"`) | Platform spoofing (P2). Static checks flag platform-gated code paths. Accepted limitation for now. |
| Only acting when the install is not in CI, or only in CI | Run in the CI-like profile by default. Consider two profiles for high-risk packages (P2). |
| Only acting when imported by a specific parent package | `require` and `import` are run directly. Accepted limitation for parent-specific triggers. |
| Code that only runs in a browser (the Sept 2025 `chalk`/`debug` wallet stealer) | Not caught by Node detonation. The static diff against the previous version (R11, R12) is the defence. Accepted limitation. |
| Checking network reachability first (fetching a known site) | The sink answers every request. A check that inspects the response content can still tell. Accepted limitation in part. |

## D. Steal in a way the rules miss

| Technique | Defence to look for |
|---|---|
| Reading credentials and writing them into a file in the package (to be published later) | R6 (writes outside the package folder). Writes inside the package after reading a credential file are a rule candidate. |
| Using stolen npm tokens to publish (worm spreading) | R7 (npm publish or token API calls). |
| Creating GitHub repos, workflows, or self-hosted runners. Shai-Hulud did both. | R8 (GitHub API calls), and R6 at Critical for `.github/workflows` writes. |
| Wiping the home directory as a fallback. Shai-Hulud 2.0 did this. | R9 (many deletes or overwrites in home). |
| Exfiltrating to an allowlisted host (for example a GitHub gist, or an npm package) | The honeytoken match (R1) is independent of the allowlist. Allowlisted hosts are checked for honeytokens too. |
| Encoding the token in the User-Agent, URL path, cookie, or header | The matcher scans the whole request: method, URL, headers, and body. |
| Stealing environment variables, not files | Honeytokens are in the environment too, and R1 matches them wherever they go. |

## Real incidents to keep in mind

- **Shai-Hulud (Sept 2025):** a `postinstall` credential stealer that published itself with stolen npm tokens and created public GitHub repos.
- **Shai-Hulud 2.0 (Nov 2025):** moved to `preinstall`, installed Bun, detached a background process, added a self-hosted runner workflow, and wiped the home directory as a fallback.
- **`chalk`/`debug` compromise (Sept 2025):** browser-only wallet-stealing code with no install script.
- **`postmark-mcp` (Sept 2025):** a malicious MCP server that BCC'd every sent email to the attacker. The behaviour only shows when the tool is used.
