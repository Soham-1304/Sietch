import { describe, expect, it } from "vitest";
import { base64Encode, hexEncode, percentDecode } from "./encoding.js";

describe("base64Encode", () => {
  // RFC 4648 section 10 test vectors.
  it.each([
    ["", ""],
    ["f", "Zg=="],
    ["fo", "Zm8="],
    ["foo", "Zm9v"],
    ["foob", "Zm9vYg=="],
    ["fooba", "Zm9vYmE="],
    ["foobar", "Zm9vYmFy"],
  ])("%j -> %j", (input, expected) => {
    expect(base64Encode(input)).toBe(expected);
  });

  it("uses the URL-safe alphabet", () => {
    expect(base64Encode("\u00fb\u00ff", "std")).toBe("+/8=");
    expect(base64Encode("\u00fb\u00ff", "url")).toBe("-_8=");
  });

  it("refuses non-byte characters", () => {
    expect(() => base64Encode("\u0100")).toThrow(RangeError);
  });
});

describe("hexEncode", () => {
  it("encodes in lowercase", () => {
    expect(hexEncode("Az\u00ff")).toBe("417aff");
  });
});

describe("percentDecode", () => {
  it("decodes valid escapes and keeps the rest", () => {
    expect(percentDecode("a%41%2fb")).toBe("aA/b");
    expect(percentDecode("100%")).toBe("100%");
    expect(percentDecode("%zz%4")).toBe("%zz%4");
    expect(percentDecode("%2541")).toBe("%41"); // one round only
  });
});
