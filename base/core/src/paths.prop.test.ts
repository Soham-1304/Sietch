import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { isInside, normalisePath } from "./paths.js";

const segment = fc.constantFrom("a", "b", "ab", "bc", ".", "..", "", "x.y", ".npmrc");
const absPath = fc.array(segment, { maxLength: 6 }).map((parts) => `/${parts.join("/")}`);

/** Independent oracle: string comparison on normalised paths, with a "/" boundary. */
function insideOracle(child: string, root: string): boolean {
  const c = normalisePath(child);
  const r = normalisePath(root);
  if (r === "/") return true;
  return c === r || c.startsWith(`${r}/`);
}

describe("paths: properties", () => {
  // Property 10: Path containment works on segments. Validates: Requirements 6.3, 10.1
  it("isInside agrees with a boundary-aware string oracle", () => {
    fc.assert(
      fc.property(absPath, absPath, (child, root) => {
        expect(isInside(child, root)).toBe(insideOracle(child, root));
      }),
    );
  });

  it("a sibling that shares a string prefix is never inside", () => {
    fc.assert(
      fc.property(absPath, fc.stringMatching(/^[a-z]{1,4}$/), (root, extra) => {
        const r = normalisePath(root);
        if (r === "/") return;
        expect(isInside(`${r}${extra}`, r)).toBe(false);
      }),
    );
  });

  // Property 12: Normalisation is idempotent. Validates: Requirements 1.3
  it("normalisation is idempotent and leaves no dot segments", () => {
    fc.assert(
      fc.property(absPath, (p) => {
        const n = normalisePath(p);
        expect(normalisePath(n)).toBe(n);
        expect(n.startsWith("/")).toBe(true);
        expect(n.split("/").some((s) => s === "." || s === "..")).toBe(false);
        if (n !== "/") expect(n.endsWith("/")).toBe(false);
      }),
    );
  });
});
