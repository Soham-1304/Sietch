import { describe, expect, it } from "vitest";
import { clone, fakeTokens, npmInstall } from "./__fixtures__/builders.js";
import { MAX_EVENTS } from "./limits.js";
import { type ScanInput, validateScanInput } from "./schema.js";

const valid = () => npmInstall(() => {}).build();
const mutate = (fn: (input: Record<string, unknown> & ScanInput) => void) => {
  const input = clone(valid()) as Record<string, unknown> & ScanInput;
  fn(input);
  return validateScanInput(input);
};
const reasonOf = (r: ReturnType<typeof validateScanInput>) => (r.ok ? "" : r.reason);

describe("validateScanInput", () => {
  it("accepts a valid input", () => {
    expect(validateScanInput(valid()).ok).toBe(true);
  });

  it.each([
    ["an unknown top-level key", (i: Record<string, unknown>) => (i.extra = 1)],
    [
      "a __proto__ key",
      (i: Record<string, unknown>) =>
        Object.defineProperty(i, "__proto__", { value: { x: 1 }, enumerable: true }),
    ],
    [
      "an unknown event type",
      (i: ScanInput) => i.events.push({ ...(i.events[0] as object), seq: 999, type: "ptrace" } as never),
    ],
    ["an unknown key on an event", (i: ScanInput) => Object.assign(i.events[0] as object, { note: "x" })],
    ["a relative path", (i: ScanInput) => Object.assign(i.events[1] as object, { path: "home/dev/.npmrc" })],
    [
      "a NUL in a path",
      (i: ScanInput) => Object.assign(i.events[1] as object, { path: "/home/dev/\u0000.npmrc" }),
    ],
    [
      "a newline in a path",
      (i: ScanInput) => Object.assign(i.events[1] as object, { path: "/home/dev/\n.npmrc" }),
    ],
    ["a duplicate seq", (i: ScanInput) => Object.assign(i.events[1] as object, { seq: 1 })],
    ["a negative pid", (i: ScanInput) => Object.assign(i.events[0] as object, { pid: -1 })],
    ["a fractional seq", (i: ScanInput) => Object.assign(i.events[0] as object, { seq: 1.5 })],
    [
      "a pid on a dns event",
      (i: ScanInput) =>
        i.events.push({
          type: "dns",
          seq: 500,
          t: 0,
          phase: "install",
          name: "x.invalid",
          qtype: "A",
          pid: 3,
        } as never),
    ],
    [
      "a process event without a pid",
      (i: ScanInput) =>
        i.events.push({ type: "file_read", seq: 501, t: 0, phase: "install", path: "/x" } as never),
    ],
    [
      "a rename without a target",
      (i: ScanInput) =>
        i.events.push({
          type: "file_write",
          seq: 502,
          t: 0,
          phase: "install",
          pid: 5,
          ppid: 1,
          op: "rename",
          path: "/tmp/a",
        }),
    ],
    [
      "a write with a target",
      (i: ScanInput) =>
        i.events.push({
          type: "file_write",
          seq: 503,
          t: 0,
          phase: "install",
          pid: 5,
          ppid: 1,
          op: "write",
          path: "/tmp/a",
          target: "/tmp/b",
        }),
    ],
    [
      "node_modules outside the project",
      (i: ScanInput) => (i.environment.nodeModulesDir = "/other/node_modules"),
    ],
    [
      "node_modules equal to the project (SR-5)",
      (i: ScanInput) => (i.environment.nodeModulesDir = i.environment.projectDir),
    ],
    ["a temp dir that is the root (SR-5)", (i: ScanInput) => (i.environment.tmpDirs = ["/"])],
    ["a temp dir that contains home (SR-5)", (i: ScanInput) => (i.environment.tmpDirs = ["/home"])],
    ["a temp dir that contains the project (SR-5)", (i: ScanInput) => (i.environment.tmpDirs = ["/work"])],
    ["home at the root (SR-5)", (i: ScanInput) => (i.environment.home = "/")],
    [
      "17 honeytokens (SR-4)",
      (i: ScanInput) => {
        i.honeytokens = Array.from({ length: 17 }, (_, n) => ({
          id: `t${n}`,
          kind: "generic" as const,
          value: `tok_${String(n).padStart(20, "0")}`,
        }));
      },
    ],
    [
      "too much traffic text in total (SR-4)",
      (i: ScanInput) => {
        // 15 MiB of bodies (under the 16 MiB body limit) plus about 10 MiB of headers (over 24 MiB in total).
        const bigHeaders: [string, string][] = Array.from({ length: 100 }, (_, h) => [
          `h${h}`,
          "v".repeat(8190),
        ]);
        for (let n = 0; n < 28; n++) {
          i.events.push({
            type: "http",
            seq: 1000 + n,
            t: 0,
            phase: "install",
            method: "POST",
            scheme: "https",
            host: "x.invalid",
            path: "/",
            headers: n < 15 ? [] : bigHeaders,
            body: n < 15 ? "a".repeat(1024 * 1024) : "",
            bodyTruncated: false,
          });
        }
      },
    ],
    ["a short honeytoken", (i: ScanInput) => ((i.honeytokens[0] as { value: string }).value = "short")],
    [
      "a honeytoken with a space",
      (i: ScanInput) => ((i.honeytokens[0] as { value: string }).value = `npm ${"x".repeat(20)}`),
    ],
    [
      "a duplicated honeytoken value",
      (i: ScanInput) => i.honeytokens.push({ id: "dup", kind: "npm", value: fakeTokens.npm() }),
    ],
    ["a bad integrity", (i: ScanInput) => (i.package.integrity = "sha1-abc")],
    ["a bad allowlist pattern", (i: ScanInput) => i.allowlist.push("*evil.com")],
    ["a sink address that isn't an IP", (i: ScanInput) => (i.environment.sinkAddresses = ["sink.local"])],
    [
      "a non-byte http body",
      (i: ScanInput) =>
        i.events.push({
          type: "http",
          seq: 504,
          t: 0,
          phase: "install",
          method: "POST",
          scheme: "https",
          host: "x.invalid",
          path: "/",
          headers: [],
          body: "\u0100",
          bodyTruncated: false,
        }),
    ],
    [
      "a lowercase http method",
      (i: ScanInput) =>
        i.events.push({
          type: "http",
          seq: 505,
          t: 0,
          phase: "install",
          method: "post",
          scheme: "https",
          host: "x.invalid",
          path: "/",
          headers: [],
          body: "",
          bodyTruncated: false,
        }),
    ],
    [
      "a lone surrogate in argv",
      (i: ScanInput) => Object.assign(i.events[0] as object, { argv: ["npm", "\ud800"] }),
    ],
  ])("rejects %s", (_label, fn) => {
    const r = mutate(fn as (i: Record<string, unknown> & ScanInput) => void);
    expect(r.ok).toBe(false);
  });

  it("rejects things that aren't objects", () => {
    for (const v of [null, undefined, 42, "x", [], () => 1]) expect(validateScanInput(v).ok).toBe(false);
  });

  it("refuses a huge event array before parsing it", () => {
    const r = validateScanInput({ events: { length: MAX_EVENTS + 1 } });
    expect(r.ok).toBe(false);
    const big = validateScanInput({ ...valid(), events: new Array(MAX_EVENTS + 1).fill(0) });
    expect(reasonOf(big)).toContain("events: too_big");
  });

  it("names the field without copying the hostile value", () => {
    const hostile = "/home/dev/\u001b]0;pwned\u0007";
    const r = mutate((i) => Object.assign(i.events[1] as object, { path: hostile }));
    expect(reasonOf(r)).toContain("events.1.path");
    expect(reasonOf(r)).not.toContain("pwned");
    expect(reasonOf(r)).not.toContain("\u001b");
  });
});
