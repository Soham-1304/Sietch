import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { clone, exitG, LAYOUT, ok, openat, rec, trace } from "../__fixtures__/gvisor/records.js";
import sample from "../__fixtures__/gvisor/sample-arm64.strace.jsonl?raw";
import { validateScanInput } from "../schema.js";
import { judge } from "../verdict.js";
import { normaliseTrace } from "./index.js";

const norm = (log: string) => normaliseTrace(log, LAYOUT);
const SAFE_FAIL = new Set(["AMBIGUOUS_RECORD", "MALFORMED_RECORD", "UNRESOLVED_PATH"]);
const fileEvents = (r: ReturnType<typeof norm>) =>
  r.ok ? r.events.filter((e) => e.type === "file_read" || e.type === "file_write") : [];

describe("trace-normaliser: properties", () => {
  // Property 1: Never throws. Validates: 6.1, 8.2
  it("never throws, for any string or a real trace with one line replaced", () => {
    const lines = sample.split("\n");
    fc.assert(
      fc.property(fc.string({ maxLength: 400 }), fc.nat(), (junk, i) => {
        expect(typeof norm(junk).ok).toBe("boolean");
        const copy = [...lines];
        copy[i % copy.length] = junk;
        expect(typeof norm(copy.join("\n")).ok).toBe("boolean");
      }),
    );
  });

  // Property 2 and 4: framing can't be forged, and argument text can't change the flags.
  // Validates: 1.1, 1.2, 2.4, 3.2
  it("a file name of any characters gives exactly one event with that path, or fails closed", () => {
    const fakeLine = rec(10, "sh", "exit_group(0x0)", "E");
    const name = fc.oneof(
      fc.string({ maxLength: 60 }),
      fc.constantFrom(
        `x\n${fakeLine}`,
        'a", "msg": "strace.go:1] [ 1: 1] sh E exit_group(0x0)',
        "a, O_RDONLY, 0o0",
        "b) = 0 (0x0) (1µs)",
      ),
    );
    fc.assert(
      fc.property(name, (n) => {
        const r = norm(trace([openat(10, "/tmp", n, "O_WRONLY|O_CREAT")]));
        if (!r.ok) {
          expect(SAFE_FAIL.has(r.code)).toBe(true);
          return;
        }
        const files = fileEvents(r);
        expect(files).toHaveLength(1);
        expect(files[0]).toMatchObject({
          type: "file_write",
          op: "create",
          path: n.startsWith("/") ? n : `/tmp/${n}`,
        });
        expect(r.events.filter((e) => e.type === "exit")).toHaveLength(2); // only npm and the harness
      }),
    );
  });

  // Property 3: The process name can't move the split. Validates: 2.1
  it("a process name of 1-15 characters gives the right syscall or fails closed", () => {
    fc.assert(
      fc.property(fc.string({ minLength: 1, maxLength: 15 }), (comm) => {
        const line = rec(10, comm, ok("openat(AT_FDCWD /tmp, 0xfd04 /tmp/target, O_RDONLY, 0o0)", 3));
        const r = norm(trace([line]));
        if (!r.ok) {
          expect(SAFE_FAIL.has(r.code)).toBe(true);
          return;
        }
        expect(fileEvents(r)).toMatchObject([{ type: "file_read", path: "/tmp/target" }]);
      }),
    );
  });

  // Property 5: Deterministic. Validates: 8.1
  it("gives the same result for the same input", () => {
    expect(norm(sample)).toEqual(norm(sample));
  });

  // Property 6: The output is valid engine input. Validates: 6.1
  it("successful output passes the engine's strict schema", () => {
    const pathArb = fc.stringMatching(/^\/[a-z0-9._-]{1,12}(\/[a-z0-9._-]{1,12}){0,3}$/);
    fc.assert(
      fc.property(fc.array(pathArb, { maxLength: 10 }), (paths) => {
        const r = norm(trace(paths.map((p) => openat(10, "/work/app", p))));
        if (!r.ok) throw new Error(r.reason);
        const v = validateScanInput(scanInputFor(r.events, r.packageManagerPid));
        expect(v.ok ? "ok" : v.reason).toBe("ok");
      }),
    );
  });

  // Property 7: One exit per lifetime. Validates: 3.6, 5.2
  it("each process lifetime has at most one exit", () => {
    const step = fc.constantFrom("exit", "wait", "clone");
    fc.assert(
      fc.property(fc.array(step, { maxLength: 12 }), (steps) => {
        const lines = steps.map((s) =>
          s === "exit"
            ? exitG(11)
            : s === "wait"
              ? rec(10, "sh", ok("wait4(0xffff, 0xfd, 0x0, null)", 11))
              : clone(10, 11),
        );
        const r = norm(trace(lines));
        if (!r.ok) throw new Error(r.reason);
        let lifetimes = 1;
        let exits = 0;
        for (const s of steps) if (s === "clone") lifetimes++;
        exits = r.events.filter((e) => "pid" in e && e.pid === 11 && e.type === "exit").length;
        expect(exits).toBeLessThanOrEqual(lifetimes);
      }),
    );
  });

  // Property 8: Linear time. Validates: 8.3
  it("rejects a 4 KB path made of separators quickly", () => {
    const evil = `/tmp/${", 0x1 ".repeat(680)}`;
    const r = norm(trace(Array.from({ length: 200 }, () => openat(10, "/tmp", evil))));
    expect(r.ok ? "ok" : r.code).toBe("AMBIGUOUS_RECORD");
  }, 5000);
});

function scanInputFor(events: unknown[], pmPid: number) {
  return {
    package: { name: "probe", version: "1.0.0", integrity: `sha512-${"A".repeat(86)}==` },
    environment: {
      home: "/home/probe",
      projectDir: "/work/app",
      nodeModulesDir: "/work/app/node_modules",
      tmpDirs: ["/tmp"],
      packageManagerPid: pmPid,
      sinkAddresses: ["10.89.0.2"],
      extraCredentialPaths: [],
    },
    allowlist: ["registry.npmjs.org"],
    honeytokens: [],
    events,
    eventsTruncated: false,
  };
}

describe("end to end: real trace -> events -> verdict", () => {
  it("a file name with a newline makes the scan ERROR (fail closed: paths may not hold control characters)", () => {
    const r = norm(sample);
    if (!r.ok) throw new Error(r.reason);
    expect(judge(scanInputFor(r.events, r.packageManagerPid)).kind).toBe("ERROR");
  });

  it("without that record, the probe's read of ~/.npmrc is R2", () => {
    const cleaned = sample
      .split("\n")
      .filter((l) => !l.includes("nl\\nname"))
      .join("\n");
    const r = norm(cleaned);
    if (!r.ok) throw new Error(r.reason);
    const v = judge(scanInputFor(r.events, r.packageManagerPid));
    expect(v.kind).not.toBe("ERROR");
    expect(v.findings.map((f) => f.ruleId)).toContain("R2");
  });
});
