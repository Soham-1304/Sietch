import { describe, expect, it } from "vitest";
import { canonicalIp, compileAllowlist, isLoopback, matchesAllowlist, normaliseHost } from "./hosts.js";

describe("normaliseHost", () => {
  it.each([
    ["registry.npmjs.org", "registry.npmjs.org"],
    ["NPMJS.ORG.", "npmjs.org"],
    ["host.example:443", "host.example"],
    ["[::1]:80", "::1"],
    ["10.0.0.2", "10.0.0.2"],
    ["::ffff:127.0.0.1", "127.0.0.1"],
  ])("%s -> %s", (raw, expected) => {
    expect(normaliseHost(raw)).toBe(expected);
  });

  it.each([
    "",
    "a..b",
    ".lead",
    "bad host",
    "x:notaport",
    "x:123456",
    "ex\u00e4mple.com",
    "999.1.1.1",
    "010.0.0.1",
    "[::1",
    "a/b",
  ])("rejects %j", (raw) => {
    expect(normaliseHost(raw)).toBeNull();
  });
});

describe("canonicalIp and isLoopback", () => {
  it("canonicalises", () => {
    expect(canonicalIp("192.0.2.10")).toBe("192.0.2.10");
    expect(canonicalIp("::FFFF:10.0.0.2")).toBe("10.0.0.2");
    expect(canonicalIp("2001:DB8::1")).toBe("2001:db8::1");
    expect(canonicalIp("example.com")).toBeNull();
    expect(canonicalIp("1.2.3")).toBeNull();
  });
  it("detects loopback", () => {
    expect(isLoopback("127.0.0.1")).toBe(true);
    expect(isLoopback("127.9.9.9")).toBe(true);
    expect(isLoopback("::1")).toBe(true);
    expect(isLoopback("128.0.0.1")).toBe(false);
  });
});

describe("allowlist", () => {
  const allow = compileAllowlist(["registry.npmjs.org", "*.githubusercontent.com", "10.0.0.9"]);
  const m = (host: string) => matchesAllowlist(allow, normaliseHost(host));

  it("matches exact hosts and proper subdomains", () => {
    expect(m("registry.npmjs.org")).toBe(true);
    expect(m("REGISTRY.NPMJS.ORG.")).toBe(true);
    expect(m("objects.githubusercontent.com")).toBe(true);
    expect(m("a.b.githubusercontent.com")).toBe(true);
    expect(m("10.0.0.9")).toBe(true);
  });

  it("rejects look-alikes", () => {
    expect(m("registry.npmjs.org.evil.invalid")).toBe(false);
    expect(m("evilregistry.npmjs.org")).toBe(false);
    expect(m("githubusercontent.com")).toBe(false); // *.x doesn't match x itself
    expect(m("evilgithubusercontent.com")).toBe(false);
    expect(m("npmjs.org")).toBe(false);
    expect(matchesAllowlist(allow, null)).toBe(false);
  });

  it("never matches IPs against wildcard patterns", () => {
    const ipish = compileAllowlist(["*.example.com"]);
    expect(matchesAllowlist(ipish, "1.example.com")).toBe(true);
    expect(() => compileAllowlist(["*.0.0.1"])).toThrow();
  });

  it.each(["*evil.com", "a.*.com", "", "*.", "*", "bad host", "x.com:443", "*.x.com:80"])(
    "rejects pattern %j",
    (p) => {
      expect(() => compileAllowlist([p])).toThrow();
    },
  );
});
