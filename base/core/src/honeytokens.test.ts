import { describe, expect, it } from "vitest";
import { percentEncodeAll, refBase64, refHex, wrapLines } from "./__fixtures__/reference-encoders.js";
import { compileHoneytokens, findHoneytokens } from "./honeytokens.js";

// Built at run time so the repo never contains a secret-shaped literal.
const npmToken = `npm_${"Q7x".repeat(12)}`;
const ghToken = `ghp_${"Zr4".repeat(12)}`;
const compiled = compileHoneytokens([
  { id: "npm", value: npmToken },
  { id: "gh", value: ghToken },
]);
const find = (text: string) => findHoneytokens(compiled, text);

describe("findHoneytokens", () => {
  it("finds a raw token", () => {
    expect(find(`Authorization: Bearer ${npmToken}`)).toEqual([
      { tokenId: "npm", encoding: "raw", percentDecoded: 0 },
    ]);
  });

  it("finds hex in either case", () => {
    expect(find(refHex(npmToken)).map((m) => m.encoding)).toContain("hex");
    expect(find(refHex(npmToken, true)).map((m) => m.encoding)).toContain("hex");
  });

  it.each([0, 1, 2])("finds a token inside base64 of a JSON blob at offset %i", (pad) => {
    const blob = JSON.stringify({ host: "x".repeat(pad), tokens: [npmToken], other: "y" });
    expect(find(refBase64(blob)).some((m) => m.tokenId === "npm" && m.encoding === "base64")).toBe(true);
    expect(
      find(refBase64(blob, true, false)).some((m) => m.tokenId === "npm" && m.encoding === "base64"),
    ).toBe(true);
  });

  it("finds double base64 (base64 of base64), like Shai-Hulud's exfil", () => {
    const blob = JSON.stringify({ env: { NPM_TOKEN: npmToken } });
    const matches = find(refBase64(refBase64(blob)));
    expect(matches.some((m) => m.tokenId === "npm" && m.encoding === "double-base64")).toBe(true);
  });

  it("finds line-wrapped base64", () => {
    const blob = `${"z".repeat(100)}${ghToken}${"z".repeat(100)}`;
    expect(find(wrapLines(refBase64(blob))).some((m) => m.tokenId === "gh" && m.encoding === "base64")).toBe(
      true,
    );
  });

  it("finds tokens after one or two rounds of percent-encoding", () => {
    const b64 = percentEncodeAll(refBase64(`{"t":"${npmToken}"}`));
    expect(find(`/collect?d=${b64}`)).toContainEqual({
      tokenId: "npm",
      encoding: "base64",
      percentDecoded: 1,
    });
    expect(find(percentEncodeAll(percentEncodeAll(npmToken)))).toContainEqual({
      tokenId: "npm",
      encoding: "raw",
      percentDecoded: 2,
    });
  });

  // Base64 matching ignores up to 2 characters at each end of a token (they depend on the
  // neighbouring bytes), so the changed character is in the middle. Tokens are random, so an
  // accidental match of everything but 2 characters at an end isn't a realistic false positive.
  it("doesn't match a value that differs in the middle", () => {
    const mid = npmToken.length >> 1;
    const near = `${npmToken.slice(0, mid)}#${npmToken.slice(mid + 1)}`;
    expect(find(near)).toEqual([]);
    expect(find(refBase64(near))).toEqual([]);
  });

  it("matches DNS names case-insensitively only when asked", () => {
    const label = `${npmToken.toUpperCase()}.exfil.invalid`;
    expect(findHoneytokens(compiled, label)).toEqual([]);
    expect(findHoneytokens(compiled, label, { caseInsensitiveRaw: true })).toContainEqual({
      tokenId: "npm",
      encoding: "raw",
      percentDecoded: 0,
    });
  });

  it("reports each token and encoding once, in a stable order", () => {
    const text = `${ghToken} ${npmToken} ${npmToken} ${refHex(ghToken)}`;
    expect(find(text)).toEqual([
      { tokenId: "npm", encoding: "raw", percentDecoded: 0 },
      { tokenId: "gh", encoding: "raw", percentDecoded: 0 },
      { tokenId: "gh", encoding: "hex", percentDecoded: 0 },
    ]);
  });

  it("scans a 1 MiB body quickly", () => {
    const body = `${"A".repeat(1024 * 1024 - 64)}${npmToken}`;
    expect(find(body).some((m) => m.encoding === "raw")).toBe(true);
  });

  it("returns nothing when there are no tokens", () => {
    expect(findHoneytokens(compileHoneytokens([]), npmToken)).toEqual([]);
  });
});
