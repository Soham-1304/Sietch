import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { identityArb, scanInputArb } from "./__fixtures__/arbitraries.js";
import { clone, fakeTokens } from "./__fixtures__/builders.js";
import { percentEncodeAll, refBase64, refHex } from "./__fixtures__/reference-encoders.js";
import { verdictCacheKey } from "./cache-key.js";
import { SEVERITY_RANK, type Severity } from "./rules/types.js";
import type { ScanInput } from "./schema.js";
import { allowsInstall, judge, kindFromFindings, type Verdict } from "./verdict.js";

const KIND_RANK = { SAFE: 0, SUSPICIOUS: 1, MALICIOUS: 2 } as const;
const severity = fc.constantFrom<Severity>("Low", "Medium", "High", "Critical");

describe("verdict: properties", () => {
  // Property 1: Determinism and order independence. Validates: Requirements 18.1, 18.2, 3.4
  it("gives the same verdict for a copy and for any order of the event array", () => {
    fc.assert(
      fc.property(
        scanInputArb.chain((input) =>
          fc.tuple(
            fc.constant(input),
            fc.shuffledSubarray(input.events, {
              minLength: input.events.length,
              maxLength: input.events.length,
            }),
          ),
        ),
        ([input, shuffled]) => {
          const v = judge(input);
          expect(judge(clone(input))).toEqual(v);
          expect(judge({ ...input, events: shuffled })).toEqual(v);
        },
      ),
    );
  });

  // Property 2: Never throws. Validates: Requirements 2.1, 1.1, 1.8
  it("never throws, for any value at all", () => {
    fc.assert(
      fc.property(
        fc.anything({ withMap: true, withSet: true, withBigInt: true, withNullPrototype: true }),
        (value) => {
          expect(["SAFE", "SUSPICIOUS", "MALICIOUS", "ERROR"]).toContain(judge(value).kind);
        },
      ),
    );
  });

  it("never throws when one field of a valid input is replaced with anything", () => {
    fc.assert(
      fc.property(
        scanInputArb,
        fc.nat(),
        fc.constantFrom("seq", "pid", "path", "type", "argv", "body", "op", "target"),
        fc.anything(),
        (input, i, key, value) => {
          const copy = clone(input) as unknown as { events: Record<string, unknown>[] };
          const event = copy.events[i % copy.events.length];
          if (event !== undefined) event[key] = value;
          expect(() => judge(copy)).not.toThrow();
        },
      ),
    );
  });

  // Property 3: Evidence integrity. Validates: Requirements 16.1, 16.2
  it("cites 1 to 20 evidence events per finding, ascending, unique, and present in the input", () => {
    fc.assert(
      fc.property(scanInputArb, (input) => {
        const seqs = new Set(input.events.map((e) => e.seq));
        for (const f of judge(input).findings) {
          expect(f.evidence.length).toBeGreaterThanOrEqual(1);
          expect(f.evidence.length).toBeLessThanOrEqual(20);
          expect([...f.evidence]).toEqual([...new Set(f.evidence)].sort((a, b) => a - b));
          for (const s of f.evidence) expect(seqs.has(s)).toBe(true);
        }
      }),
    );
  });

  // Property 4: Adding a finding never makes the verdict safer. Validates: Requirements 17.1-17.3
  it("adding a finding never lowers the verdict", () => {
    fc.assert(
      fc.property(fc.array(severity.map((s) => ({ severity: s }))), severity, (findings, extra) => {
        const before = KIND_RANK[kindFromFindings(findings)];
        const after = KIND_RANK[kindFromFindings([...findings, { severity: extra }])];
        expect(after).toBeGreaterThanOrEqual(before);
      }),
    );
  });

  // Property 5: The verdict matches the severities. Validates: Requirements 17.1-17.3, 16.3
  it("kind matches the highest severity among the findings", () => {
    fc.assert(
      fc.property(scanInputArb, (input) => {
        const v = judge(input);
        if (v.kind === "ERROR") return;
        const max = Math.max(0, ...v.findings.map((f) => SEVERITY_RANK[f.severity]));
        if (v.omittedFindings === 0) {
          expect(v.kind).toBe(max >= 4 ? "MALICIOUS" : max >= 3 ? "SUSPICIOUS" : "SAFE");
        } else {
          // Hidden findings can only raise the kind.
          expect(KIND_RANK[v.kind]).toBeGreaterThanOrEqual(max >= 4 ? 2 : max >= 3 ? 1 : 0);
        }
        if (v.kind === "SAFE") expect(v.findings.every((f) => SEVERITY_RANK[f.severity] < 3)).toBe(true);
      }),
    );
  });

  // Property 6: Only SAFE allows an install. Validates: Requirements 2.5
  it("allows an install exactly when the verdict is SAFE", () => {
    fc.assert(
      fc.property(scanInputArb, (input) => {
        const v: Verdict = judge(input);
        expect(allowsInstall(v)).toBe(v.kind === "SAFE");
      }),
    );
  });

  // Property 8: Honeytokens are never shown in full. Validates: Requirements 16.4
  it("never includes a honeytoken value anywhere in the verdict, in any letter case", () => {
    fc.assert(
      fc.property(scanInputArb, (input) => {
        const text = JSON.stringify(judge(input)).toLowerCase();
        for (const t of input.honeytokens) expect(text).not.toContain(t.value.toLowerCase());
      }),
    );
  });

  // Property 13: Exfiltration always makes it MALICIOUS. Validates: Requirements 5.1, 17.1
  it("adding one request that carries a honeytoken always gives MALICIOUS", () => {
    const encoders = [
      (s: string) => s,
      (s: string) => refHex(s),
      (s: string) => refBase64(s),
      (s: string) => refBase64(refBase64(s)),
      (s: string) => percentEncodeAll(refBase64(s, true, false)),
    ];
    fc.assert(
      fc.property(
        scanInputArb,
        fc.constantFrom(...encoders),
        fc.constantFrom(fakeTokens.npm(), fakeTokens.github()),
        fc.string({ maxLength: 20 }),
        (input, encode, token, padding) => {
          const seq = Math.max(...input.events.map((e) => e.seq)) + 1;
          const exfil = {
            type: "http" as const,
            seq,
            t: 0,
            phase: "linger" as const,
            method: "POST",
            scheme: "https" as const,
            host: "collector.invalid",
            path: "/",
            headers: [],
            body: encode(`${padding.replace(/[^ -~]/g, "")}${token}`),
            bodyTruncated: false,
          };
          const v = judge({ ...input, events: [...input.events, exfil] } satisfies ScanInput);
          expect(v.kind).toBe("MALICIOUS");
        },
      ),
    );
  });

  // Property 14: Control characters are rejected. Validates: Requirements 1.3, 1.8
  it("returns ERROR when a control character is inserted into any event path", () => {
    fc.assert(
      fc.property(scanInputArb, fc.nat(), fc.integer({ min: 0, max: 0x1f }), (input, i, code) => {
        const withPaths = input.events.filter((e) => "path" in e && e.type !== "http");
        if (withPaths.length === 0) return;
        const victim = withPaths[i % withPaths.length];
        const events = input.events.map((e) =>
          e === victim && "path" in e ? { ...e, path: `${e.path}${String.fromCharCode(code)}x` } : e,
        );
        expect(judge({ ...input, events }).kind).toBe("ERROR");
      }),
    );
  });

  // Property 9: The cache key is injective. Validates: Requirements 19.1, 19.3
  it("gives equal cache keys only for equal identities and ruleset versions", () => {
    fc.assert(
      fc.property(
        identityArb,
        identityArb,
        fc.constantFrom("1", "1:0", "2"),
        fc.constantFrom("1", "1:0", "2"),
        (a, b, ra, rb) => {
          const same =
            a.name === b.name && a.version === b.version && a.integrity === b.integrity && ra === rb;
          expect(verdictCacheKey(a, ra) === verdictCacheKey(b, rb)).toBe(same);
        },
      ),
    );
  });
});
