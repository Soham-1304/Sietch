# Kiroween 2026: Ideation

This document compares five project candidates: your idea (Sietch), followed by four of mine. All five target the **Skeleton Crew** or **Frankenstein** category. Each one is checked against the rules and given a build plan. A comparison and a recommendation are at the end.

## 0. Time check

Today is **Monday, Nov 16, 2026**. The deadline is **Friday, Dec 4, 2:00 PM PT**, which is **Saturday, Dec 5, 3:30 AM IST**.

That gives us about **18 days**, including the video and the write-up. Every plan below assumes this window and keeps the last 2 to 3 days as buffer.

## 1. Rules that apply to every idea

All five ideas can meet these rules. Each idea section lists only its own extra concerns.

| Rule | How we meet it |
|---|---|
| New project, built from Oct 30 | Fresh repo, first commit now. |
| Public GitHub repo with all code and instructions | One repo with a README that includes setup steps. |
| Open source license visible in About | Add an MIT or Apache-2.0 `LICENSE` file in the first commit. |
| `/.kiro` at the root and never ignored | Commit specs, hooks, and steering from day one. |
| Working app URL | A hosted demo. Credentials, if any, go in the private Devpost field. |
| Video under 3 minutes, public on YouTube, no copyrighted music or trademarks | Use royalty-free or self-made audio. Show no logos or film imagery. |
| Kiro write-up | Keep a build log in `docs/build-log.md` from day one. |

## 2. The two target categories

Costume Contest is out because it depends heavily on frontend work. The four new ideas use a chat window, a phone call, an API, or generated files as their main interface, so they need very little custom frontend.

| Category | Your understanding | What the rules add |
|---|---|---|
| **Skeleton Crew** | Build a base, then build solutions on top of it. | It must be **exactly two distinct apps**, in **two separate folders** in the repo. The base should be "lean enough to be clear but flexible enough to support various use cases", so the two apps should be clearly different, ideally for different audiences. |
| **Frankenstein** | Combine several bases into one app, which streamlines the work. | The rules say "stitch together a chimera of technologies... seemingly incompatible elements". Streamlining counts, but the parts being joined should look as if they don't belong together, such as a phone call and a Kubernetes cluster. |

**The Design criterion still applies in every category.** For these ideas, "design" mostly means conversation design: clear messages, confirmations, and recovery from errors. The few small web pages we need can use a ready-made component library, with Kiro generating them.

---

## 3. Your idea: Sietch, an npm detonation checkpoint

### What it is

Sietch is a private npm registry proxy. When a new package version is requested, Sietch installs it inside a locked-down container. The container holds only fake credentials (honeytokens), and Sietch records every file read, spawned process, and network attempt. A deterministic rules engine then gives a verdict, along with the evidence for it. Packages that pass are cached and served to the whole organisation. Malicious ones are blocked.

### Honest opinion

**This is a good idea.** Of the five ideas, it has the strongest case for real impact.

**Strengths**

- **The problem is real, recent, and backed by numbers.** Shai-Hulud hit npm in two waves in 2025, and CISA issued an alert. Judges don't need convincing that it matters.
- **The demo is dramatic.** On camera, a fake worm reaches for the bait credentials and gets caught. Demos like that score well on Presentation.
- **Deterministic verdicts with evidence suit security work.** They also give us a strong property-based testing story; see the Kiro plan below.
- **Verdicts are cached per version and hash.** Each version is tested once, and the whole organisation reuses the result.

**Weaknesses**

1. **The category and Halloween fit are weak.** As written, Sietch is a single app with an ordinary stack, so it fits neither Skeleton Crew nor Frankenstein without reshaping. The name also comes from Dune, not Halloween. This is the biggest strategic problem. The fix is under "Category fit" below.
2. **Similar tools already exist.** Judges who know security will ask how Sietch differs from these:
   - OpenSSF Package Analysis, which already detonates packages in a gVisor sandbox.
   - Socket.dev and Aikido Safe Chain.
   - Datadog GuardDog.
   - pnpm 10, which skips dependency install scripts unless you allowlist them, and its `minimumReleaseAge` setting.

   Sietch needs a sharp answer to "why this?" My suggestion is under "How to make it win".
3. **A security judge would spot these technical gaps:**
   - **Monitoring has to happen at the OS level, not inside Node.** I recall that the second Shai-Hulud wave installed Bun to avoid Node-level monitoring; verify before using this in the pitch. `strace -f`, seccomp, or eBPF can see every child process.
   - **Install scripts are not the only attack path.** In the Sept 2025 compromise of `chalk` and `debug`, the malicious code was in the package's runtime code. It ran on import, with no install script. The sandbox should also `require()` the package and diff its code against the previous version.
   - **Blocking all network traffic causes false positives.** Legitimate packages such as `esbuild`, `sharp`, and `puppeteer` download binaries during install. Use a fake network instead: a DNS sinkhole plus an HTTP capture server. The sandbox then records where the package tried to connect and classifies those destinations, instead of simply failing.
   - **Malware can detect sandboxes.** Some packages check for CI variables, the OS, or the date, or sleep before acting. Add realistic fake CI variables and time skew. In the write-up, say honestly that no sandbox catches everything.
   - **Docker alone is a weak boundary against real malware.** Use gVisor (`runsc`) if possible. Add dropped capabilities and `no-new-privileges`, and run the hosted demo on a disposable VM.
4. **The scope is heavy for 18 days.** The current plan has a MERN app, FastAPI, Redis, Docker workers, a registry proxy, static analysis, and a live graph. Two backend languages add cost without a clear benefit, since JavaScript code analysis is easiest in Node anyway. **Build on Verdaccio**, an open source npm proxy registry, instead of writing a proxy from scratch.
5. **The first install of a new version has to wait.** Testing takes about 30 to 90 seconds. One option is to serve the last verified version while the new one is tested.
6. **Hosting is harder than usual.** A working URL means hosting a service that runs untrusted code. It needs an isolated VM, rate limits, and an allowlist of what judges can submit. This is doable, but it must be planned from day one.

**Check where the Q1.a/Q1.b text came from.** It looks like it was written for another program. Reusing the idea and the text is probably fine. If any **code** was written before Oct 30, the project is not eligible. Confirm this in the Official Rules before we start.

### How to make it win: protect AI coding agents

AI coding agents, Kiro included, run `npm install` on their own, often for packages no human has read. LLMs also invent package names that don't exist, and attackers then register those names. This attack is called "slopsquatting". Adding agent protection makes Sietch new and directly relevant to Kiro:

- **A Sietch MCP server** with tools such as `check_package(name, version)` and `explain_verdict(...)`. Kiro checks with Sietch before adding a dependency.
- **A Kiro hook that gates installs.** A pre-tool-use hook catches the agent's `npm install` command and blocks it until Sietch approves. Check the exact hook trigger types in the docs when we build.
- **A Kiro power** that bundles the MCP server, the hook, and steering ("never install unverified packages"). Any Kiro user gets protection in one step.

The pitch becomes: "Sietch is the checkpoint between untrusted packages and both your developers and your AI agents."

### Category fit

| Category | Fit | Why |
|---|---|---|
| **Skeleton Crew** | **Best fit** | Turn the core into a reusable base for detonating untrusted code. App 1 is the npm gate. App 2 is a gate for AI-generated code, or for VS Code and Open VSX extensions, which were also hit by malware in late 2025. |
| Frankenstein | Weak | Proxy, container, and rules engine are an ordinary stack, so nothing looks "incompatible". |
| Costume Contest | Out | Too much frontend work. |
| Resurrection | Stretch | Honeypots date from the 1980s and 90s, but that angle is hard to argue. |

**Recommendation:** enter **Skeleton Crew**. If you are solo, keep App 2 small: it reuses the same sandbox and rules engine and only adds a new entry point. Consider a Halloween name such as *Exorcist*, *Crypt*, or *Hex*. If you keep "Sietch", leave all Dune imagery and audio out of the video.

### Kiro usage plan

| Kiro feature | Use |
|---|---|
| Specs | One spec each for the base (sandbox runner and rules engine), the npm gate, and the second gate. |
| Property-based testing | The same trace always gets the same verdict. Adding a malicious behaviour never makes a verdict safer. The cache key changes whenever the hash changes. The `package.json` parser never crashes on arbitrary input. |
| Hooks | When a rule file is saved, run the rules against a set of benign and malicious samples. Also the install-gating hook described above. |
| Steering | Security rules: never mount the host, never use real credentials, and every verdict must cite evidence. |
| MCP and powers | The Sietch MCP server and power. Optionally, the Postman power for API tests. |
| Public dataset | Datadog publishes a dataset of malicious packages on GitHub, which gives us a real test set. It contains live malware, so open it only inside the sandbox and never commit it. |

### Build plan (18 days)

| Days | Work |
|---|---|
| 1–2 | Repo, license, `.kiro`, steering, specs. Verdaccio running locally. |
| 3–6 | Base: sandbox runner (gVisor or Docker, strace, fake network, honeytokens) and a fake worm package. |
| 7–9 | Base: rules engine with property-based tests, version diff, verdict cache. |
| 10–11 | App 1: npm gate on Verdaccio. Minimal verdict and evidence page. |
| 12–13 | App 2: second gate on the same base. |
| 14 | MCP server, install-gating hook, Kiro power. |
| 15–16 | Hosted demo on an isolated VM. Video script and recording. |
| 17–18 | Write-up, social post, blog post, buffer. |

**Cut list if we fall behind:** drop the version diff first, then the web page. The CLI output is enough. Keep the detonation, the verdict, and the agent hook.

---

## 4. Idea A: Séance (Skeleton Crew)

**One line:** a base for apps that live entirely inside chat (Telegram, WhatsApp, SMS) and understand voice notes in Indian languages. Two apps sit on top: a voice ledger for small shops and a medication reminder for elderly parents.

**Problem and audience.** Hundreds of millions of people in India use WhatsApp every day, but many of them find app forms hard to use. Many prefer to speak Hindi, Marathi, or Tamil rather than type. Every team building for these users rebuilds the same plumbing: message channels, speech recognition, conversation state, confirmations, reminders, and handoff to a person.

**The base (`/seance`)**

- **Channel adapters** for Telegram, the WhatsApp Cloud API, and SMS, behind one interface.
- **Voice notes to text** in Indian languages, using Bhashini (the Indian government's language AI platform), Sarvam AI, or Whisper.
- **A deterministic conversation state machine.** The LLM only pulls structured data out of messages, and code decides what happens next.
- **Typed extraction with a confirmation step**, for example: "You said: Ramesh, 2 kg rice, ₹120, due Friday. Correct? Reply 1 or 2."
- **A reminder scheduler** that handles time zones and retries.
- **Handoff to a person**, plus an audit log.

**App 1 (`/bahi`): voice ledger for small shops.** Kirana shops often sell on informal credit ("udhaar") and track it in a paper notebook. With Bahi, the shopkeeper sends a voice note and the ledger updates. Customers get polite reminders with a UPI payment link, and the shopkeeper gets a weekly summary.

**App 2 (`/dawa`): medication reminders for elderly parents.** A caregiver, such as a son working in another city, sets the medicine schedule. The parent gets a voice-note reminder in their own language and replies "1" once the dose is taken. A missed dose alerts the caregiver. The WHO estimates that about half of patients with chronic illness don't take their medicines as prescribed. Dawa only sends reminders and never gives medical advice.

**Demo moment.** The shopkeeper sends a Hindi voice note. The ledger shows the entry, and the customer's phone receives a reminder with a payment link. Then the video cuts to Dawa on the same base: the parent misses a dose and the son's phone buzzes.

**Category fit: Skeleton Crew, strong.** The base is clearly separate from the apps, and the two apps serve different audiences.

**Extra rules notes**

- **Judges should test through Telegram.** It is free, and anyone can message a bot. A WhatsApp Cloud API test number can only message a few registered recipients, so WhatsApp appears only in the video.
- Use synthetic people and data, never real customers.

**Kiro usage**

- **Specs:** one for the base and one for each app.
- **Property-based tests:**
  - A balance always equals the sum of its entries.
  - No ledger entry is saved without confirmation.
  - A webhook delivered twice is counted once. Duplicate deliveries are a real source of bugs in messaging apps.
  - A reminder never fires twice and always fires at the right IST time.
- **Steering:** a conversation style guide (short messages, always confirm money, never give medical advice) and rules for what belongs in the base versus an app.
- **Hooks:** when a state-machine file is saved, replay a set of recorded conversations.
- **MCP:** a Séance MCP server that lets Kiro create a new conversation flow from a plain description. This also shows how flexible the base is.

**Stack.** TypeScript or Python, Postgres, Redis with BullMQ for reminders, the Telegram Bot API, the WhatsApp Cloud API, and Bhashini or Sarvam for speech.

**Build plan**

| Days | Work |
|---|---|
| 1–2 | Repo, `.kiro`, specs, steering. A Telegram adapter that echoes messages. |
| 3–6 | Base: speech to text, state machine, extraction with confirmation, scheduler, property-based tests. |
| 7–10 | App 1: Bahi. |
| 11–13 | App 2: Dawa. |
| 14–15 | WhatsApp adapter, hosting, recorded-conversation tests. |
| 16–18 | Video, write-up, social and blog posts, buffer. |

**Risks.** Speech recognition can struggle with some languages and with noisy shops, which is why the confirmation step is essential. Two apps take real time, so keep each one small.

---

## 5. Idea B: Shroud (Skeleton Crew)

**One line:** a base that hides personal data before it reaches an LLM and puts it back into the answer. Two apps sit on top: a clinic notes summariser and a support-ticket assistant.

**Problem and audience.** Companies want to use LLMs but can't send customer or patient data to outside APIs. In 2023, Samsung banned ChatGPT internally after engineers pasted in confidential code. In India, the DPDP Act adds legal pressure; I believe its rules were notified in late 2025, but verify this. Most PII tools simply delete the data, which makes the LLM's answer less useful.

**The base (`/shroud`)**

- **An OpenAI-compatible proxy.** Any app can use it by changing its API base URL.
- **PII detection** with Microsoft Presidio, plus custom recognisers for Indian data:
  - Aadhaar numbers, validated with the Verhoeff checksum.
  - PAN numbers.
  - UPI IDs.
  - Indian phone numbers.
- **Reversible, consistent placeholders.** "Rahul Mehta" becomes `PERSON_1` everywhere in a session and is restored in the reply. The real values sit in a short-lived vault.
- **A policy file and an audit log** recording what was hidden, when, and by which rule.

**App 1 (`/clinic`): clinic notes summariser.** A doctor pastes or dictates notes and gets back a structured summary and a discharge note. The patient's identity never leaves the server.

**App 2 (`/helpdesk`): support-ticket assistant.** It sorts incoming tickets by type and drafts replies, without customer emails, phone numbers, or account IDs reaching the LLM.

**Demo moment.** A three-panel screen. The left panel shows what the doctor typed. The middle panel shows what the LLM actually received, full of `PERSON_1` and `AADHAAR_1`. The right panel shows the final summary with the real names restored.

**Category fit: Skeleton Crew, strong.** One base serves two clearly different industries.

**Extra rules notes.** Use only synthetic patient and customer data. Presidio is MIT-licensed, which works with our open source license.

**Kiro usage**

- **Property-based tests.** This idea has the strongest testing story of the four new ones:
  - Hiding and then restoring always returns exactly the original text.
  - No recognised PII appears in what the LLM receives.
  - The same person always gets the same placeholder within a session.
  - The Aadhaar validator matches the Verhoeff algorithm for every input.
- **Steering:** privacy rules, and a guide to adding new recognisers.
- **Hooks:** when a recogniser is saved, measure its recall on a synthetic PII dataset.
- **Kiro integration:** a prompt-submit hook that warns when you paste secrets or PII into Kiro's chat. Check whether the hook can block the prompt or only warn.

**Stack.** Python with FastAPI (which you already know), Presidio, spaCy, Redis for the vault, and one minimal web page per app.

**Build plan**

| Days | Work |
|---|---|
| 1–2 | Repo, `.kiro`, specs, steering. A proxy that passes requests through unchanged. |
| 3–7 | Base: detection, Indian recognisers, placeholder vault, restoration, property-based tests. |
| 8–10 | App 1: Clinic. |
| 11–13 | App 2: Helpdesk. |
| 14–15 | Recall benchmark, Kiro hook, hosting. |
| 16–18 | Video, write-up, posts, buffer. |

**Risks**

- **No detector catches 100% of PII.** Publish the measured recall instead of claiming perfection.
- **LLMs sometimes rewrite placeholders,** for example turning `PERSON_1` into "the patient", which breaks restoration. Restoration needs fuzzy matching.
- **The demo is less dramatic than the others.** The three-panel view has to carry it.
- **Similar tools exist:** LLM Guard, Private AI, and Nightfall. Our differences are reversible placeholders, Indian ID formats, and an open source base.

---

## 6. Idea C: Graveyard Shift (Frankenstein)

**One line:** when production breaks at 3 AM, your phone rings and you handle the incident by talking. A voice agent reads your alerts, deploys, and logs, and takes action only after you confirm.

**Problem and audience.** On-call engineers get paged at night, often away from their laptops, and lose the first minutes opening dashboards and gathering context. This affects every team that runs production software.

**What gets stitched together**

| Part | Role |
|---|---|
| Phone network (Twilio Voice with Media Streams) | The interface: an ordinary phone call. |
| Speech to text and text to speech | Turn the conversation into text and back. |
| An LLM agent with an MCP client | Reasons and picks tools. |
| MCP servers for Kubernetes, GitHub, and Grafana/Prometheus | Real infrastructure access, using existing open source servers. |
| Alertmanager webhook | Starts the call. |

A phone call and a Kubernetes cluster really do look incompatible, and joining them makes on-call much faster. That fits both the official definition and yours.

**Safety design.** This is the heart of the product, and judges will look at it closely.

- Every tool is read-only by default.
- Any change (rollback, scaling, restart) needs a spoken PIN plus a push approval on the engineer's phone.
- Every action is logged together with the call transcript.
- After the call, the full incident timeline is posted to Slack or GitHub as a first draft of the postmortem.

**Demo moment.** We deploy a bad version of a demo shop, and the phone rings on camera:

> **Agent:** "Payments p95 latency is 4 seconds. It started 3 minutes after deploy 1.4.2."
> **Engineer:** "What changed?"
> **Agent:** Summarises the diff.
> **Engineer:** "Roll it back."
> **Agent:** "Say your PIN to confirm."

The rollback runs and the graph recovers.

**Category fit: Frankenstein, strong.** The parts are visibly unrelated technologies, and together they make on-call much simpler.

**Extra rules notes**

- **Judges need a way in.** A real phone number costs a few dollars a month, and Twilio trial accounts have restrictions. Add a free **browser-based call** (WebRTC) for judges.
- **The demo cluster must be a sandbox** (kind or k3d), never real infrastructure.

**Kiro usage**

- **Specs:** call flow, safety gate, and tool layer.
- **Property-based tests:**
  - No path through the state machine reaches "run a change" without passing "confirmed".
  - A wrong or missing PIN never runs a change.
  - Every action has a matching log entry.
- **Steering:** safety rules for the agent, and a voice style guide (short sentences, numbers first).
- **MCP:** used both to build the product and inside it, which makes a strong write-up.
- **Hooks:** when a tool definition is saved, check that it declares whether it is read-only or makes changes.

**Stack.** TypeScript or Python, Twilio Voice with Media Streams, Deepgram or AWS Transcribe for speech to text, a text-to-speech service, Claude through Bedrock or the Anthropic API, the MCP SDK, the existing Kubernetes, GitHub, and Grafana MCP servers, and a kind cluster running a demo shop.

**Build plan**

| Days | Work |
|---|---|
| 1–2 | Repo, `.kiro`, specs, steering. Demo cluster with Prometheus and Alertmanager. |
| 3–5 | Phone loop: an alert triggers a call, and a basic conversation works. |
| 6–9 | MCP client, read-only tools, incident summary. |
| 10–12 | Safety gate (PIN plus push approval), actions that make changes, property-based tests. |
| 13–14 | Browser-call fallback, postmortem output, hosting. |
| 15–18 | Video, write-up, posts, buffer. |

**Risks**

- **Voice latency is the hardest part.** A slow agent feels broken, so keep tool calls short and stream the speech.
- **Speech recognition can mishear commands.** The confirmation step protects against this.
- **Similar products are emerging.** PagerDuty, Rootly, and incident.io are adding AI features, but a phone-first agent that can act is still unusual.

---

## 7. Idea D: Phantom Scribe (Frankenstein)

**One line:** record a planning meeting and get Kiro specs, GitHub issues, and full traceability. Any line of code can be traced back to the moment in the meeting where it was decided.

**Problem and audience.** Decisions made in meetings get lost or misremembered. Months later, nobody knows why a feature works the way it does. Meeting tools such as Otter, Fireflies, and Granola produce notes, not anything a developer can build from. The audience is product and engineering teams, especially remote ones.

**What gets stitched together**

| Part | Role |
|---|---|
| Meeting audio with speaker separation | The raw input. |
| LLM extraction | Pulls out decisions, requirements in EARS format, open questions, and owners. |
| Kiro spec format | Writes `.kiro/specs/<feature>/requirements.md`, linking each requirement to an audio timestamp. |
| GitHub issues and PRs | Tasks become issues, and PRs reference requirement IDs. |
| Kiro | Implements from the generated spec. |

**Key features**

- **A trace view.** For any requirement, you can see its audio clip, its issue, and the PRs that implemented it.
- **Reversal detection.** If a later meeting reverses a decision, the affected requirements and issues are flagged.

**Demo moment.** We upload a 2-minute mock planning call. A spec appears in `.kiro/specs/`, issues open on GitHub, and Kiro builds one task. Then we click a line in the resulting PR, and the original audio plays: "Let's cap uploads at 10 MB."

**Category fit: Frankenstein, good.** It joins audio, specs, issue tracking, and code into one flow, which matches your "streamlining" view. The parts look less incompatible than in Graveyard Shift.

**Extra rules notes.** Record a scripted mock meeting, with consent from everyone in it. Don't use real meetings.

**Kiro usage**

This is the most Kiro-native of the four new ideas, because the product's output is Kiro specs.

- **Property-based tests:**
  - Writing an EARS requirement and reading it back gives the same requirement.
  - Every requirement points to a timestamp inside the recording.
  - Requirement IDs stay the same when the same meeting is processed again.
- **MCP:** the GitHub MCP server for issues and PRs.
- **Hooks:** when a PR is created, check that each requirement it references still holds after the latest meeting.

**Stack.** Python or TypeScript, WhisperX or AWS Transcribe for speech to text with speaker separation, Claude for extraction, the GitHub MCP server or API, and a simple trace page.

**Build plan**

| Days | Work |
|---|---|
| 1–2 | Repo, `.kiro`, specs, steering. A scripted mock meeting recording. |
| 3–6 | Transcription, speaker separation, extraction into EARS requirements with timestamps. |
| 7–9 | Spec writer, GitHub issue sync, property-based tests. |
| 10–12 | Trace view, PR linking, reversal detection. |
| 13–14 | Hosting, plus a sample repo built from the spec. |
| 15–18 | Video, write-up, posts, buffer. |

**Risks**

- **Extraction quality depends on the LLM,** so results are not fully deterministic. Make every extracted item editable before it is written.
- **Judges may see it as "another meeting AI"** unless the trace view appears early in the video.

---

## 8. Comparison

Scores are my honest estimates, from 1 (low) to 5 (high).

| | Sietch (yours) | Séance | Shroud | Graveyard Shift | Phantom Scribe |
|---|---|---|---|---|---|
| Category | Skeleton Crew | Skeleton Crew | Skeleton Crew | Frankenstein | Frankenstein |
| Potential Impact | **5** | **5** | 4 | 4 | 3 |
| Technological Implementation (Kiro) | 4 (5 with the agent angle) | 4 | **5** | 4 | **5** |
| Design (conversation or flow) | 3 | 4 | 3 | 4 | 3 |
| Innovation | 3 (4 with the agent angle) | 4 | 3 | **5** | 4 |
| Presentation (demo) | **5** | 4 | 3 | **5** | 4 |
| Frontend needed | Low | **Very low** | Low | **Very low** | Low |
| Scope risk in 18 days | High | Medium | Medium | Medium–High | Medium |
| Hosting risk | High | **Low** | **Low** | Medium | **Low** |

## 9. My recommendation

1. **Graveyard Shift is the best of the new ideas for you.**
   - It needs almost no frontend.
   - It is one app rather than two.
   - It has the most memorable demo: the phone rings on camera.
   - It uses MCP inside the product, which makes for a strong Kiro write-up.
2. **Séance has the strongest real-world impact story.** Its frontend needs are also low, but building two apps takes more time.
3. **Sietch is still a strong option** as a Skeleton Crew entry with the AI-agent angle. It suits you best if you have a teammate, or if you are willing to keep App 2 very small.

Shroud has the best property-based testing story but the weakest demo. Phantom Scribe is the most Kiro-native, but it risks looking like yet another meeting-notes tool.

## 10. Decisions needed from you

1. Are you working solo or in a team?
2. Was any Sietch code written before Oct 30?
3. Which idea do we take forward?
4. Which backend language: Python (FastAPI) or TypeScript (Node)?
5. Are you comfortable paying for a few small services, such as a phone number, speech APIs, and LLM credits? You can request Kiro credits, but these services are billed separately.
6. Which bonus prizes apply to you: student, startup, 2025 participant, or Kiro Crew?
