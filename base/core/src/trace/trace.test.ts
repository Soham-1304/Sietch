import { describe, expect, it } from "vitest";
import { clone, err, execve, exitG, LAYOUT, ok, openat, rec, trace } from "../__fixtures__/gvisor/records.js";
import sample from "../__fixtures__/gvisor/sample-arm64.strace.jsonl?raw";
import { parseRfc3339 } from "./frame.js";
import { normaliseTrace } from "./index.js";

const norm = (log: string) => normaliseTrace(log, LAYOUT);
const events = (log: string) => {
  const r = norm(log);
  if (!r.ok) throw new Error(`expected ok, got ${r.code}: ${r.reason}`);
  return r.events;
};
const codeOf = (log: string) => {
  const r = norm(log);
  return r.ok ? "ok" : r.code;
};

describe("framing", () => {
  it.each([
    ["a non-JSON line", "not json"],
    ["a JSON array", "[1,2]"],
    ["a record without msg", JSON.stringify({ time: "2026-11-18T00:00:00Z" })],
    ["an empty line in the middle", `${clone(1, 10)}\n\n${clone(1, 20)}`],
  ])("rejects %s", (_l, log) => {
    expect(codeOf(log)).toBe("UNFRAMED_RECORD");
  });

  it("rejects a huge log before parsing", () => {
    expect(codeOf("x".repeat(64 * 1024 * 1024 + 1))).toBe("TRACE_TOO_LARGE");
  });

  it("ignores gVisor's own (non-strace) messages", () => {
    const other = JSON.stringify({ msg: "boot.go:12] Starting", time: "2026-11-18T00:00:00Z" });
    expect(events(`${other}\n${trace()}`)).toHaveLength(4);
  });

  it("parses RFC 3339 times without Date", () => {
    expect(parseRfc3339("1970-01-01T00:00:00Z")).toBe(0);
    expect(parseRfc3339("2026-11-18T22:27:18.062642508+05:30")).toBeCloseTo(1795021038062.6426, 3); // matches Node's Date.parse;
    expect(parseRfc3339("2026-13-01T00:00:00Z")).toBeNull();
  });
});

describe("record parsing", () => {
  it("can't be fooled by a process name containing a marker", () => {
    // comm "x X openat(" sits before the real " X execve(" marker: two possible splits.
    const log = trace([rec(10, "x X openat(", ok('execve(0xfd01 /bin/sh, 0xfd02 ["sh"], 0xfd03 [])'))]);
    expect(codeOf(log)).toBe("AMBIGUOUS_RECORD");
  });

  it("rejects a syscall outside the traced list", () => {
    expect(codeOf(trace([rec(10, "sh", ok("ptrace(0x0)"))]))).toBe("UNEXPECTED_SYSCALL");
  });

  it("reads the result from the end, whatever the arguments contain", () => {
    const evil = "/tmp/a) = 0 (0x0) (1µs)";
    const e = events(trace([openat(10, "/tmp", evil, "O_WRONLY|O_CREAT")]));
    expect(e.find((x) => x.type === "file_write")).toMatchObject({ op: "create", path: evil });
  });
});

describe("syscalls", () => {
  const one = (line: string) =>
    events(trace([line])).filter((e) => "pid" in e && e.pid === 10 && e.type !== "exec" && e.type !== "exit");

  it("openat: read, write, create, truncate, and relative paths", () => {
    expect(one(openat(10, "/work/app", "/home/probe/.npmrc"))).toMatchObject([
      { type: "file_read", path: "/home/probe/.npmrc" },
    ]);
    expect(one(openat(10, "/work/app", "pkg/x.js", "O_RDWR"))).toMatchObject([
      { type: "file_write", op: "write", path: "/work/app/pkg/x.js" },
    ]);
    expect(one(openat(10, "/", "/tmp/a", "O_WRONLY|O_CREAT|O_TRUNC|0x20000"))).toMatchObject([
      { op: "truncate" },
    ]);
    expect(one(openat(10, "/", "/tmp/a", "0x41"))).toMatchObject([{ op: "create" }]);
  });

  it("skips failed calls", () => {
    expect(one(rec(10, "node", err("openat(AT_FDCWD /, 0xfd04 /nope, O_RDONLY, 0o0)")))).toEqual([]);
  });

  it("rename, link, symlink, chmod, delete, mkdir", () => {
    expect(
      one(rec(10, "mv", ok("renameat(AT_FDCWD /tmp, 0xfd1 a.txt, 0xffffffffffffff9c, 0xfd2 b.txt)"))),
    ).toMatchObject([{ op: "rename", path: "/tmp/a.txt", target: "/tmp/b.txt" }]);
    expect(
      one(rec(10, "ln", ok("linkat(AT_FDCWD /tmp, 0xfd1 a, 0xffffffffffffff9c, 0xfd2 b, 0x0)"))),
    ).toMatchObject([{ op: "hardlink", path: "/tmp/b", target: "/tmp/a" }]);
    expect(
      one(rec(10, "ln", ok("symlinkat(0xfd1 ../home/probe/.npmrc, AT_FDCWD /tmp, 0xfd2 link)"))),
    ).toMatchObject([{ op: "symlink", path: "/tmp/link", target: "/home/probe/.npmrc" }]);
    expect(one(rec(10, "chmod", ok("fchmodat(AT_FDCWD /tmp, 0xfd1 a, 0o700)")))).toMatchObject([
      { op: "chmod", path: "/tmp/a" },
    ]);
    expect(one(rec(10, "rm", ok("unlinkat(AT_FDCWD /tmp, 0xfd1 a, 0x0)")))).toMatchObject([
      { op: "delete", path: "/tmp/a" },
    ]);
    expect(one(rec(10, "mkdir", ok("mkdirat(AT_FDCWD /tmp, 0xfd1 d/, 0x1ff)")))).toMatchObject([
      { op: "mkdir", path: "/tmp/d/" },
    ]);
  });

  it("refuses a rename into a directory fd it can't resolve", () => {
    expect(codeOf(trace([rec(10, "mv", ok("renameat(AT_FDCWD /tmp, 0xfd1 a, 0x5, 0xfd2 b)"))]))).toBe(
      "UNRESOLVED_PATH",
    );
  });

  it.each([
    ["a cwd containing the separator", openat(10, "/tmp/a, 0x1 /etc", "x")],
    [
      "a symlink target containing ', AT_FDCWD '",
      rec(10, "ln", ok("symlinkat(0xfd1 x, AT_FDCWD /y, 0x1 z, AT_FDCWD /tmp, 0xfd2 link)")),
    ],
  ])("fails closed on %s", (_l, line) => {
    expect(codeOf(trace([line]))).toBe("AMBIGUOUS_RECORD");
  });

  it("a fake list inside an execve path can't change the split: the real argv wins", () => {
    const e = events(
      trace([
        clone(10, 11),
        rec(11, "sh", ok('execve(0xfd01 /a, 0x1 ["x"], 0x2 [], 0xfd02 ["real"], 0xfd03 [])')),
        exitG(11),
      ]),
    );
    expect(e.find((x) => "pid" in x && x.pid === 11 && x.type === "exec")).toMatchObject({
      path: '/a, 0x1 ["x"], 0x2 []',
      argv: ["real"],
    });
  });

  it("execve: argv decoded, envp dropped, long argv capped and flagged", () => {
    const e = events(
      trace([clone(10, 11), execve(11, "/usr/bin/curl", ["curl", 'a"b\\c', "-d"]), exitG(11)]),
    );
    expect(e.find((x) => "pid" in x && x.pid === 11 && x.type === "exec")).toMatchObject({
      path: "/usr/bin/curl",
      argv: ["curl", 'a"b\\c', "-d"],
    });
    expect(JSON.stringify(e)).not.toContain("HOME=/home/probe");
    const long = events(
      trace([
        clone(10, 11),
        execve(
          11,
          "/bin/true",
          Array.from({ length: 300 }, (_, i) => `${i}`),
        ),
        exitG(11),
      ]),
    );
    expect(long.find((x) => "pid" in x && x.pid === 11 && x.type === "exec")).toMatchObject({
      argvTruncated: true,
    });
  });

  it("connect: IPv4, IPv6, failed calls kept, AF_UNIX ignored", () => {
    const c = (s: string) => rec(10, "node", err(`connect(0x13 socket:[2], 0xfd {${s}}, 0x10)`, 101));
    expect(one(c("Family: AF_INET, Addr: 192.0.2.10, Port: 443"))).toMatchObject([
      { type: "connect", address: "192.0.2.10", port: 443 },
    ]);
    expect(one(c("Family: AF_INET6, Addr: 2001:db8::1, Port: 80"))).toMatchObject([
      { address: "2001:db8::1" },
    ]);
    expect(one(c('Family: AF_UNIX, Addr: "/tmp/{Family: AF_INET, Addr: 1.2.3.4, Port: 1}"'))).toEqual([]);
  });

  it("sendmsg with a destination becomes a connect to an unrecorded address", () => {
    const s = rec(
      10,
      "node",
      err(
        'sendmsg(0x13 socket:[4], 0xfd {name=0xfd9, namelen=16, iovecs=0xfd {base=0x1, len=5, "hello"}, control={0x0 }, flags=0}, 0x0)',
        101,
      ),
    );
    expect(one(s)).toMatchObject([{ type: "connect", address: null, protocol: "udp" }]);
  });
});

describe("processes and phases", () => {
  it("assigns install, load, and linger, and drops the runner's own processes", () => {
    const log = [
      trace([openat(10, "/", "/a")], [openat(20, "/", "/b")]),
      clone(1, 30),
      openat(30, "/", "/runner-timer"),
    ].join("\n");
    const e = events(log);
    expect(e.find((x) => "path" in x && x.path === "/a")?.phase).toBe("install");
    expect(e.find((x) => "path" in x && x.path === "/b")?.phase).toBe("load");
    expect(JSON.stringify(e)).not.toContain("/runner-timer");
    expect(norm(log)).toMatchObject({ ok: true, packageManagerPid: 10 });
  });

  it("a detached child keeps running into the linger phase", () => {
    const log = [trace([clone(10, 11)]), openat(11, "/", "/late")].join("\n");
    expect(events(log).find((x) => "path" in x && x.path === "/late")).toMatchObject({
      pid: 11,
      ppid: 10,
      phase: "linger",
    });
  });

  it("a child killed by a signal exits when its parent reaps it with wait4", () => {
    const e = events(
      trace([clone(10, 11), rec(10, "sh", ok("wait4(0xffffffffffffffff, 0xfd, 0x0, null)", 11))]),
    );
    expect(e.filter((x) => "pid" in x && x.pid === 11 && x.type === "exit")).toHaveLength(1);
  });

  it("emits one exit per lifetime, and a reused pid starts a new one", () => {
    const e = events(
      trace([
        clone(10, 11),
        exitG(11),
        rec(10, "sh", ok("wait4(0xffff, 0xfd, 0x0, null)", 11)),
        clone(10, 11),
        exitG(11),
      ]),
    );
    expect(e.filter((x) => "pid" in x && x.pid === 11 && x.type === "exit")).toHaveLength(2);
  });

  it("threads don't become processes", () => {
    const thread = rec(
      10,
      "node",
      ok("clone(CLONE_VM|CLONE_THREAD|CLONE_SETTLS, 0xfd, 0xfd, 0xfd, 0xfd)", 12),
    );
    expect(norm(trace([thread, openat(12, "/", "/t")]))).toMatchObject({ ok: true });
  });

  it("resolves a relative exec through chdir", () => {
    const e = events(
      trace([
        clone(10, 11),
        rec(11, "sh", ok("chdir(0xfd /tmp/sub)")),
        execve(11, "./rel.sh", ["./rel.sh"]),
        exitG(11),
      ]),
    );
    expect(e.find((x) => "pid" in x && x.pid === 11 && x.type === "exec")).toMatchObject({
      path: "/tmp/sub/./rel.sh",
    });
  });

  it("TN-1: text in an execve path can't change the working directory", () => {
    const e = events(
      trace([
        clone(10, 11),
        rec(11, "sh", ok("chdir(0xfd /tmp)")),
        execve(11, "/opt/AT_FDCWD /evil", ["x"]),
        execve(11, "mal", ["mal"]),
        exitG(11),
      ]),
    );
    expect(
      e
        .filter((x) => "pid" in x && x.pid === 11 && x.type === "exec")
        .map((x) => ("path" in x ? x.path : "")),
    ).toEqual(["/opt/AT_FDCWD /evil", "/tmp/mal"]);
  });

  it("fails when the install or load step is missing", () => {
    expect(codeOf(clone(1, 10))).toBe("MISSING_PHASE");
  });
});

describe("the real gVisor trace", () => {
  const r = normaliseTrace(sample, LAYOUT);

  it("normalises without error", () => {
    expect(r.ok ? "ok" : `${r.code} ${r.reason}`).toBe("ok");
  });

  // The probe ran as init's first child (install) and `node -e 0` as its second (load).
  it("keeps hostile names exactly, as single events", () => {
    const paths = r.ok ? r.events.flatMap((e) => ("path" in e ? [e.path] : [])) : [];
    expect(paths).toContain("/tmp/nl\nname");
    expect(paths).toContain('/tmp/quo"te');
    expect(paths).toContain("/tmp/back\\slash");
  });
});
