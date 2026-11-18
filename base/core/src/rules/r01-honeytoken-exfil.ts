import { findHoneytokens, type HoneytokenMatch } from "../honeytokens.js";
import { redactToken } from "../text.js";
import type { FindingDraft, Rule } from "./types.js";

const ENCODING_LABEL: Record<HoneytokenMatch["encoding"], string> = {
  raw: "as plain text",
  hex: "hex-encoded",
  base64: "base64-encoded",
  "double-base64": "double base64-encoded",
};

const describe = (m: HoneytokenMatch) =>
  ENCODING_LABEL[m.encoding] +
  (m.percentDecoded > 0 ? `, then URL-encoded ${m.percentDecoded === 1 ? "once" : "twice"}` : "");

/** R1: a honeytoken appears in outgoing traffic, to any host (allowlisted ones included). */
export const r01HoneytokenExfil: Rule = {
  id: "R1",
  title: "Fake credential sent out",
  evaluate(ctx) {
    const tokens = new Map(ctx.input.honeytokens.map((t) => [t.id, t]));
    const drafts: FindingDraft[] = [];

    for (const event of ctx.events) {
      const fields: [where: string, text: string, caseInsensitive: boolean][] = [];
      let destination: string;
      if (event.type === "http") {
        destination = `a ${event.method} request to ${ctx.show(event.host)}`;
        fields.push(["host", event.host, true], ["URL path", event.path, false]);
        for (const [name, value] of event.headers)
          fields.push(["header name", name, false], ["headers", value, false]);
        fields.push(["body", event.body, false]);
      } else if (event.type === "dns") {
        destination = `a DNS lookup of ${ctx.show(event.name)}`;
        fields.push(["name", event.name, true], ["name", event.name.replaceAll(".", ""), true]);
      } else {
        continue;
      }

      const seen = new Set<string>();
      for (const [where, text, caseInsensitive] of fields) {
        for (const match of findHoneytokens(ctx.honeytokens, text, { caseInsensitiveRaw: caseInsensitive })) {
          if (seen.has(match.tokenId)) continue;
          seen.add(match.tokenId);
          const token = tokens.get(match.tokenId);
          if (token === undefined) continue;
          drafts.push({
            severity: "Critical",
            explanation: `Sent the ${token.kind} honeytoken (${redactToken(token.value)}) ${describe(match)} in the ${where} of ${destination}.`,
            evidence: [event.seq],
          });
        }
      }
    }
    return drafts;
  },
};
