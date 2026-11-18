import { describe, expect, it } from "vitest";
import { hasUnsafeChars, quote, redactToken } from "./text.js";

describe("quote", () => {
  it("keeps ordinary text", () => {
    expect(quote("/home/dev/.npmrc")).toBe("/home/dev/.npmrc");
  });

  it("escapes control characters and bidirectional overrides", () => {
    expect(quote("a\u001b[31mb")).toBe("a\\u{1b}[31mb");
    expect(quote("evil\u202etxt.exe")).toBe("evil\\u{202e}txt.exe");
    expect(quote("line\nbreak\r")).toBe("line\\u{a}break\\u{d}");
    expect(quote("nul\u0000")).toBe("nul\\u{0}");
  });

  it("caps the length and marks the cut", () => {
    const out = quote("x".repeat(500));
    expect(out).toHaveLength(201);
    expect(out.endsWith("…")).toBe(true);
  });

  it("never splits an escape", () => {
    const out = quote(`${"x".repeat(198)}\u001b`);
    expect(out).toBe(`${"x".repeat(198)}…`);
  });
});

describe("hasUnsafeChars", () => {
  it("detects control characters", () => {
    expect(hasUnsafeChars("ok")).toBe(false);
    expect(hasUnsafeChars("a\tb")).toBe(true);
    expect(hasUnsafeChars("a\u0085b")).toBe(true);
  });
});

describe("redactToken", () => {
  it("keeps only the first 6 characters", () => {
    expect(redactToken(`npm_${"a".repeat(36)}`)).toBe("npm_aa…");
  });
});
