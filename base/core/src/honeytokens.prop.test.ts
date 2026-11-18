import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { percentEncodeAll, refBase64, refHex, wrapLines } from "./__fixtures__/reference-encoders.js";
import { compileHoneytokens, findHoneytokens } from "./honeytokens.js";

const tokenValue = fc.stringMatching(/^[A-Za-z0-9_]{16,60}$/).map((s) => `tok_${s}`);
const filler = fc.stringMatching(/^[ -~]{0,40}$/); // printable ASCII

type Encode = (s: string) => string;
const encodings: { name: string; outer: (token: string, before: string, after: string) => string }[] = [
  { name: "raw", outer: (t, b, a) => b + t + a },
  { name: "hex lower", outer: (t, b, a) => refHex(b + t + a) },
  { name: "hex upper", outer: (t, b, a) => refHex(b + t + a, true) },
  { name: "base64 std", outer: (t, b, a) => refBase64(b + t + a) },
  { name: "base64 url, no padding", outer: (t, b, a) => refBase64(b + t + a, true, false) },
  { name: "base64 wrapped at 76", outer: (t, b, a) => wrapLines(refBase64(b + t + a)) },
  { name: "double base64", outer: (t, b, a) => refBase64(refBase64(b + t + a)) },
  { name: "double base64, url inner", outer: (t, b, a) => refBase64(refBase64(b + t + a, true, false)) },
];
const percentLayers: Encode[] = [
  (s) => s,
  (s) => percentEncodeAll(s),
  (s) => percentEncodeAll(percentEncodeAll(s)),
];

describe("honeytokens: properties", () => {
  // Property 7: Honeytokens are found in every supported encoding. Validates: Requirements 4.1-4.4
  it("finds the token in every supported encoding, at any position", () => {
    fc.assert(
      fc.property(
        tokenValue,
        filler,
        filler,
        fc.constantFrom(...encodings),
        fc.constantFrom(0, 1, 2),
        filler,
        filler,
        (token, before, after, encoding, layers, outerBefore, outerAfter) => {
          const compiled = compileHoneytokens([{ id: "t", value: token }]);
          const payload = encoding.outer(token, before, after);
          const layer = percentLayers[layers] ?? ((s: string) => s);
          // The encoded payload is itself embedded in other text, e.g. a URL or a JSON field.
          const text = `${outerBefore.replaceAll("%", "")}\n${layer(payload)}\n${outerAfter.replaceAll("%", "")}`;
          const matches = findHoneytokens(compiled, text);
          expect(matches.map((m) => m.tokenId)).toContain("t");
        },
      ),
    );
  });
});
