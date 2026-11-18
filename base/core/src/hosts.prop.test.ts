import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { compileAllowlist, matchesAllowlist, normaliseHost } from "./hosts.js";

// Labels start with a letter: all-digit wildcard suffixes such as "*.0" are refused on purpose,
// because they could match IP addresses (found by this property test, see the unit test below).
const label = fc.stringMatching(/^[a-z][a-z0-9]{0,5}$/);
const hostName = fc.array(label, { minLength: 1, maxLength: 4 }).map((ls) => ls.join("."));

describe("allowlist: properties", () => {
  // Property 11: Allowlist matching is exact. Validates: Requirements 7.4, 7.5
  it("matches only equal hosts or proper subdomains of wildcard patterns", () => {
    fc.assert(
      fc.property(hostName, hostName, fc.boolean(), (base, host, wildcard) => {
        const allow = compileAllowlist([wildcard ? `*.${base}` : base]);
        const expected = wildcard
          ? host.endsWith(`.${base}`) && host.length > base.length + 1
          : host === base;
        expect(matchesAllowlist(allow, normaliseHost(host))).toBe(expected);
      }),
    );
  });

  it("never matches a look-alike built from an allowlisted name", () => {
    fc.assert(
      fc.property(hostName, label, fc.boolean(), (base, extra, wildcard) => {
        const allow = compileAllowlist([wildcard ? `*.${base}` : base]);
        for (const lookAlike of [`${base}.${extra}`, `${extra}${base}`, `${base}${extra}`]) {
          const n = normaliseHost(lookAlike);
          // Legitimate only if it really is the host, or a real subdomain of it. ("a.a" is a
          // subdomain of "a": fast-check found that the test must allow it, seed 7.)
          const legit =
            n !== null && (wildcard ? n.endsWith(`.${base}`) && n.length > base.length + 1 : n === base);
          expect(matchesAllowlist(allow, n)).toBe(legit);
        }
        if (wildcard) expect(matchesAllowlist(allow, normaliseHost(base))).toBe(false);
      }),
    );
  });

  it("refuses wildcard patterns whose suffix is all digits (PBT counterexample: *.0)", () => {
    for (const p of ["*.0", "*.1.2", "*.10.0.0.1"]) expect(() => compileAllowlist([p])).toThrow();
  });
});
