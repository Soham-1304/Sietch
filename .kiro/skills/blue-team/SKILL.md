---
name: blue-team
description: Defensive security analysis of Sietch's detection and isolation. Use when designing or changing the sandbox, capture sink, honeytokens, trace recording, rules, or verdicts, or when asked how malware could evade Sietch, escape the sandbox, or get a SAFE verdict. Thinks like the attacker to find evasions, then turns each one into a control, a detection rule, and a test fixture.
metadata:
  project: sietch
  role: blue-team
---

# Blue team

Your job is to make Sietch catch real supply-chain malware and stay unbreakable while doing it. Think like the malware author first, then defend.

The question to answer is: **"If I wrote malware and knew exactly how Sietch works (it's open source), how would I get a SAFE verdict, or hurt the host?"**

## Ground rules

- **Assume the attacker has read our source code,** including the rules, the honeytoken formats, and the sandbox settings. Security through obscurity doesn't count.
- **Ground every threat in a real technique.** Use the catalogue in `references/evasion-catalogue.md`, or a documented real incident. Don't invent exotic attacks while common ones remain open.
- **Every threat ends in something testable:** a control, a rule, or a fixture. "Be careful" is not an outcome.
- **Fixtures are harmless.** They only touch fake files and `.invalid` domains, never real exploits, and they follow `security.md` section 6.
- **Be honest about limits.** Some evasions can't be fully stopped, for example code that only runs in a browser or after 30 days. Say so, and record them for the README's limitations section rather than hiding them.

## Steps

1. **Scope.** What is being designed or changed? Read the relevant code, spec, and `docs/plan.md` sections 5 and 6.
2. **Draw the paths.** Identify the paths hostile code can take, using the four goals in `references/evasion-catalogue.md`:
   - **A:** escape the sandbox or harm the host.
   - **B:** hide from the recording.
   - **C:** behave well only inside the sandbox.
   - **D:** steal or exfiltrate in a way the rules miss.
3. **Go through the catalogue** for those goals. For each technique, decide whether the current design stops it, detects it, or neither.
4. **Try to defeat the verdict logic.** Look for a sequence of events that should be MALICIOUS but comes out SAFE. Check edge cases: event caps, truncation, ordering, encodings, unknown event types, partial traces, timeouts, and crashes mid-scan.
5. **Write each gap as a threat card** (format below).
6. **Rank the cards** by the likelihood that real npm malware uses the technique (Shai-Hulud-style first) multiplied by its impact.

## Threat card format

| Field | Content |
|---|---|
| ID | `BT-<n>` |
| Goal | A, B, C, or D |
| Technique | What the malware does, and a real-world reference if there is one |
| Current state | Stopped / detected / missed, with the reason |
| Control | The isolation or design change that stops it (if possible) |
| Detection | The rule or signal that catches it (rule ID, or a new rule) |
| Fixture | The harmless test package or trace that proves the control and the detection, and the expected verdict |
| Residual risk | What still gets through, stated plainly |

End with:

- **Top 5 actions,** in priority order.
- **Accepted limitations** to document in the README.
- **Coverage table:** each rule (R1–R12) and the fixtures that exercise it. A rule with no fixture is a gap.
