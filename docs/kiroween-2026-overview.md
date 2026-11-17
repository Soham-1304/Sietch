# Kiroween 2026: Overview

A plain-language summary of the hackathon, what we must submit, and how we will be judged. Use this as the reference while we plan and build.

## 1. Key facts

| Item | Detail |
|---|---|
| Event | Kiroween 2026, Kiro's annual Halloween-themed hackathon |
| Prize pool | $100,000 |
| Build window | October 30 to December 4, 2026 |
| Deadline | **Friday, December 4, 2026, 2:00 PM Pacific Time** |
| Team size | Up to 3 members |
| Eligibility | New projects only. Anything started before October 30 (including Kiroween 2025 projects) is not eligible. |
| Submission platform | Devpost (drafts can be saved any time) |

Useful links and events:
- Official Rules (read before building).
- Kiro Discord, channel `#kiroween-hackathon`. Biweekly office hours.
- Devpost Build Session: November 11, 10:00 AM PT.
- Kiro credits: registered participants can request them (see the Resources tab).

## 2. What we build

A **working software application**, built with Kiro (IDE, CLI, Web and/or Kiro Crew), entered in **one** category:

| Category | Idea | What judges want to see |
|---|---|---|
| **Resurrection** | Revive a dead or obsolete technology | Old tech reimagined with modern capabilities or used to solve future problems |
| **Frankenstein** | Stitch together incompatible technologies | A chimera that is unexpectedly powerful |
| **Skeleton Crew** | A lean, flexible skeleton/template | Two distinct applications built from the same foundation, in **two separate repo folders** |
| **Costume Contest** | Any app with a haunting, polished UI | Unforgettable, spooky design that also supports the app's function |

## 3. Submission checklist

- [ ] Category selected, plus any bonus prizes.
- [ ] **Public GitHub repo** (not GitLab or Bitbucket) containing:
  - [ ] All source code, assets, and setup instructions needed to run the project.
  - [ ] An **open source license** file, detectable by GitHub and shown in the repo's About section.
  - [ ] The **`/.kiro` directory at the repo root** (specs, hooks, steering). **Never add `.kiro` to `.gitignore`**, as this can disqualify us.
  - [ ] Skeleton Crew only: two separate app folders.
- [ ] URL to the working app(s). If a login is needed, put credentials and instructions in the Devpost form (judges only).
- [ ] Text description of features and functionality.
- [ ] **Demo video**:
  - [ ] Under 3 minutes.
  - [ ] Shows the project working on the device it was built for.
  - [ ] Public on YouTube.
  - [ ] No third-party trademarks or copyrighted music/material without permission.
- [ ] **Kiro usage write-up** (see section 4).

## 4. Kiro usage write-up: what to cover

Judges must understand how well we used Kiro. We should cover as many of these as we genuinely use, with specifics:

| Area | Questions to answer |
|---|---|
| Kiro apps (IDE, CLI, Web, Crew) | Which did we use? How did they differ? |
| Custom agents | Which ones? In which app? How did they change the build? |
| Agent hooks | What workflows did we automate? How did that help? |
| Spec-driven development | How did we structure specs? How did it compare to vibe coding? |
| Steering docs | What strategy gave the biggest improvement in Kiro's responses? |
| MCP | What capabilities did it add that would have been hard otherwise? |
| Property-based testing (PBT) | Which requirements used PBT? What did it catch that unit tests missed? |
| Kiro powers | Which powers? Any third-party integrations we would not otherwise have used? |

Tip: keep a running log (decisions, prompts that worked, bugs PBT caught) from day one. It makes the write-up easy and credible.

## 5. Bonus prizes

An eligible project can win **one** Overall or Category prize, but **any number** of bonus prizes.

| Bonus | Requirement | Effort |
|---|---|---|
| Best Startup Project | Confirm we are founders. Provide LinkedIn and startup website. | Depends on team |
| Best Student Project | All members are students. LinkedIn, student email, year/degree, school for each. May need proof of enrollment. | Depends on team |
| Best Ghost of Kiroween Past | Registered for Kiroween 2025 (checked against records). Project itself must be new. | Depends on history |
| Best Kiro Crew App | Public GitHub URL for the Crew app, plus a description of features. | Requires using Kiro Crew |
| Social Blitz Prize | Post on any social platform during the period. Start with `#KiroweenHackathon26`. Share our favorite thing about Kiro and how it changed our development. Add the URL to the submission. | Low |
| Bonus Blog Prize | Public blog post about Kiro and the project on a third-party platform, stating it was written for Kiroween 2026. Add the URL. | Medium |
| Best Demo | No extra steps. Every eligible submission is considered. | None |

The Social Blitz and Blog prizes are cheap to earn and stack with a main prize.

## 6. Judging criteria

| Criterion | What it asks |
|---|---|
| **Potential Impact** | Real problem, real audience? Useful, intuitive, accessible? Would someone actually use it? |
| **Technological Implementation** | How deeply and skillfully do we use Kiro? Thoughtful AI-development strategy? Variety of Kiro features used with impact? Experimentation? |
| **Design** | Complete, coherent, polished product rather than a proof of concept? |
| **Innovation / Idea** | Creative and novel? Unusual technologies or datasets combined in a new way? |
| **Presentation** | Does the video show it working end to end? Is the problem, audience, and "why it matters" clear? Easy to follow, memorable? |

## 7. Rules that can sink us

- Project must be started on or after October 30, 2026.
- `.kiro` must be committed and must not be ignored.
- Repo must be public, on GitHub, with a visible open source license.
- Demo video must be under 3 minutes and public on YouTube, with no copyrighted music.
- Skeleton Crew needs two separate app folders.
- Submit before the deadline: Dec 4, 2026, 2:00 PM PT. Aim to finish a day early.

## 8. Suggested approach (to discuss)

1. **Pick the category and idea first.** The category shapes the repo layout and the demo.
2. **Set up the repo on day one**: license, `.kiro/` folder, README, a steering doc describing the project.
3. **Work spec-first** for the core features, and add property-based tests where requirements have clear invariants.
4. **Add hooks and steering early** (for example, run tests or lint on save) so they have time to show real impact.
5. **Use at least one MCP server or power** that clearly adds capability.
6. **Keep a build log** for the Kiro write-up.
7. **Plan the demo video early** (script under 3 minutes), then record, then submit with buffer.
8. **Do the cheap bonuses**: Social Blitz post and a blog post.

## 9. Open decisions for us

- Which category?
- Solo or team (up to 3)?
- Which bonus prizes apply to us (student, startup, 2025 participant, Kiro Crew)?
- Project idea (to brainstorm next).
- Target platform (web, CLI, mobile), since the demo must run on the device it was built for.
