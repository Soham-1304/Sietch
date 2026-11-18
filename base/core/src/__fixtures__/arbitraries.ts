// fast-check generators for valid ScanInputs. Events are drawn from a vocabulary that mixes
// benign behaviour with every rule's triggers, so properties are checked over verdicts of all kinds.

import fc from "fast-check";
import type { Event, ScanInput } from "../schema.js";
import {
  fakeTokens,
  HOME,
  integrity,
  NODE_MODULES,
  PM_PID,
  PROJECT,
  SINK,
  TraceBuilder,
} from "./builders.js";
import { refBase64, refHex } from "./reference-encoders.js";

type Draft = Omit<Event, "seq" | "t" | "phase">;

const pid = fc.constantFrom(PM_PID, 201, 202, 203);
const path = fc.constantFrom(
  `${HOME}/.npmrc`,
  `${HOME}/.ssh/id_ed25519`,
  `${HOME}/.bashrc`,
  `${HOME}/.cache/x`,
  `${HOME}/.bun/bin/bun`,
  `${NODE_MODULES}/pkg/index.js`,
  `${NODE_MODULES}/pkg/bin/tool`,
  `${PROJECT}/.github/workflows/x.yml`,
  `${PROJECT}/.env`,
  "/tmp/a",
  "/dev/null",
  "/proc/1/environ",
  "/usr/bin/curl",
  "/usr/bin/git",
  "/usr/local/bin/npm",
  "/bin/sh",
);
const arg = fc.constantFrom("install", "publish", "pu", "push", "s_client", "-y", "x.js", "--version");
const host = fc.constantFrom(
  "registry.npmjs.org",
  "objects.githubusercontent.com",
  "api.github.com",
  "evil.invalid",
  "x.invalid",
);
const httpPath = fc.constantFrom("/", "/pkg", "/-/whoami", "/user", "/user/repos", "/a.git/git-upload-pack");
const method = fc.constantFrom("GET", "POST", "PUT", "DELETE");
const body = fc.constantFrom(
  "",
  "hello",
  `t=${fakeTokens.npm()}`,
  refBase64(JSON.stringify({ k: fakeTokens.github() })),
  refHex(fakeTokens.npm()),
);
const address = fc.constantFrom(SINK, "127.0.0.1", "::1", "192.0.2.10", "::ffff:192.0.2.11");
const op = fc.constantFrom(
  "create",
  "write",
  "truncate",
  "delete",
  "rename",
  "chmod",
  "mkdir",
  "symlink",
  "hardlink",
);

const draft: fc.Arbitrary<Draft> = fc.oneof(
  fc.record({
    type: fc.constant("exec" as const),
    pid,
    ppid: fc.constant(1),
    path,
    argv: fc.array(arg, { maxLength: 3 }),
  }),
  fc.record({ type: fc.constant("file_read" as const), pid, ppid: fc.constant(1), path }),
  fc
    .record({ op, pid, path, target: path })
    .map(({ op: o, pid: p, path: pa, target }) =>
      o === "rename" || o === "symlink" || o === "hardlink"
        ? { type: "file_write" as const, pid: p, ppid: 1, op: o, path: pa, target }
        : { type: "file_write" as const, pid: p, ppid: 1, op: o, path: pa },
    ),
  fc.record({
    type: fc.constant("connect" as const),
    pid,
    ppid: fc.constant(1),
    protocol: fc.constant("tcp" as const),
    address,
    port: fc.constant(443),
  }),
  fc.record({
    type: fc.constant("exit" as const),
    pid,
    ppid: fc.constant(1),
    code: fc.constant(0),
    signal: fc.constant(null),
  }),
  fc.record({ type: fc.constant("dns" as const), name: host, qtype: fc.constant("A") }),
  fc.record({
    type: fc.constant("http" as const),
    method,
    scheme: fc.constant("https" as const),
    host,
    path: httpPath,
    headers: fc.constantFrom<[string, string][]>(
      [],
      [["authorization", `Bearer ${fakeTokens.npm()}`]],
      [["x", "y"]],
    ),
    body,
    bodyTruncated: fc.constant(false),
  }),
) as fc.Arbitrary<Draft>;

const phase = fc.constantFrom("install" as const, "load" as const, "linger" as const);

/** Valid ScanInputs, always starting with the package manager's exec so there is an exec event. */
export const scanInputArb: fc.Arbitrary<ScanInput> = fc
  .record({
    events: fc.array(fc.tuple(draft, phase), { maxLength: 40 }),
    truncated: fc.boolean(),
    seqGap: fc.integer({ min: 1, max: 5 }),
  })
  .map(({ events, truncated, seqGap }) => {
    const t = new TraceBuilder();
    t.exec(PM_PID, 1, "/usr/local/bin/npm", ["npm", "install"]);
    for (const [d, p] of events) t.inPhase(p).add(d as never);
    const input = t.build({ eventsTruncated: truncated });
    // Spread seq numbers out so they aren't just 1..n.
    return { ...input, events: input.events.map((e) => ({ ...e, seq: e.seq * seqGap })) };
  });

export const identityArb = fc.record({
  name: fc.stringMatching(/^[a-z@/:.-]{1,12}$/),
  version: fc.stringMatching(/^[0-9a-z.:-]{1,8}$/),
  integrity: fc.constantFrom("A", "B", "C").map((c) => integrity(c)),
});
