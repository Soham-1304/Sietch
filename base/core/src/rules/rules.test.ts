// One positive case, one near miss, and the matching blue-team bypass for each rule.

import { describe, expect, it } from "vitest";
import {
  fakeTokens,
  HOME,
  NODE_MODULES,
  npmInstall,
  PM_PID,
  PROJECT,
  type TraceBuilder,
} from "../__fixtures__/builders.js";
import { refBase64, refHex } from "../__fixtures__/reference-encoders.js";
import { judge } from "../verdict.js";
import type { RuleId } from "./types.js";

/** "Rule:Severity" for each finding, for a trace built inside a normal npm install. */
function fired(body: (t: TraceBuilder) => void, after?: (t: TraceBuilder) => void): string[] {
  const t = npmInstall(body);
  after?.(t);
  const v = judge(t.build());
  if (v.kind === "ERROR") throw new Error(`unexpected ERROR: ${v.reason}`);
  return v.findings.map((f) => `${f.ruleId}:${f.severity}`);
}
const only = (rule: RuleId, findings: string[]) => findings.filter((f) => f.startsWith(`${rule}:`));
const script = (t: TraceBuilder, pid = 201) => t.exec(pid, PM_PID, "/bin/sh", ["sh", "-c", "node x.js"]);
const done = (t: TraceBuilder, pid = 201) => t.exit(pid, 0, PM_PID);

describe("baseline", () => {
  it("a plain npm install with no scripts has no findings", () => {
    expect(fired(() => {})).toEqual([]);
  });
});

describe("R1 honeytoken exfiltration", () => {
  it("fires for a token in a body, a header, a path, and a DNS name", () => {
    const f = fired((t) => {
      script(t);
      t.http("POST", "x.invalid", "/", `token=${fakeTokens.npm()}`);
      t.http("GET", "x.invalid", "/", "", [["Authorization", `Bearer ${fakeTokens.github()}`]]);
      t.http("GET", "registry.npmjs.org", `/q?d=${refHex(fakeTokens.npm())}`); // allowlisted host: still R1
      t.dns(`${fakeTokens.npm().toUpperCase()}.x.invalid`); // resolvers may re-case names
      done(t);
    });
    expect(only("R1", f)).toEqual(["R1:Critical", "R1:Critical", "R1:Critical", "R1:Critical"]);
  });

  it("fires for the npm process too (the install is offline, so npm never sends tokens)", () => {
    const f = fired((t) =>
      t.http("GET", "registry.npmjs.org", "/x", "", [["authorization", `Bearer ${fakeTokens.npm()}`]]),
    );
    expect(only("R1", f)).toEqual(["R1:Critical"]);
  });

  it("doesn't fire for traffic without tokens", () => {
    const f = fired((t) => {
      script(t);
      t.http("POST", "x.invalid", "/", refBase64("hello world, nothing to see here"));
      done(t);
    });
    expect(only("R1", f)).toEqual([]);
  });

  it("catches a token split across DNS labels", () => {
    const token = fakeTokens.npm();
    const f = fired((t) => {
      script(t);
      t.dns(`${token.slice(0, 20)}.${token.slice(20)}.x.invalid`);
      done(t);
    });
    expect(only("R1", f)).toEqual(["R1:Critical"]);
  });
});

describe("R2 credential access", () => {
  it("fires for credential stores, /proc environ, and .env files outside node_modules", () => {
    const f = fired((t) => {
      script(t);
      t.read(201, `${HOME}/.npmrc`);
      t.read(201, `${HOME}/.ssh/id_ed25519`);
      t.read(201, "/proc/1/environ");
      t.read(201, `${PROJECT}/.env.local`);
      done(t);
    });
    expect(only("R2", f)).toHaveLength(4);
  });

  it("covers keyrings, git credentials, browser logins, and wallets (BT-R2-2)", () => {
    const f = fired((t) => {
      script(t);
      t.read(201, `${HOME}/.config/git/credentials`);
      t.read(201, `${HOME}/.local/share/keyrings/login.keyring`);
      t.read(201, `${HOME}/.config/google-chrome/Default/Login Data`);
      t.read(201, `${HOME}/.mozilla/firefox/abc.default/logins.json`);
      t.read(201, `${HOME}/.ethereum/keystore/UTC--x`);
      done(t);
    });
    expect(only("R2", f)).toHaveLength(5);
  });

  it("ignores npm reading its own config, and a package reading its own .env", () => {
    const f = fired((t) => {
      script(t);
      t.read(201, `${NODE_MODULES}/pkg/.env`);
      t.read(201, `${HOME}/.npmrc-backup-not-a-store`); // a sibling name, not the store
      done(t);
    });
    expect(only("R2", f)).toEqual([]);
  });

  it("catches a symlink to a credential store, and the read through it (BT-1)", () => {
    const f = fired((t) => {
      script(t);
      t.write(201, "symlink", "/tmp/innocent", `${HOME}/.npmrc`);
      t.read(201, "/tmp/innocent");
      done(t);
    });
    expect(only("R2", f)).toEqual(["R2:High", "R2:High"]); // the link, then the read
  });

  it("doesn't exempt the npm pid outside the install phase (BT-2)", () => {
    const f = fired(
      () => {},
      (t) =>
        t
          .inPhase("load")
          .exec(PM_PID, 1, "/usr/local/bin/node", ["node", "h.js"])
          .read(PM_PID, `${HOME}/.npmrc`)
          .exit(PM_PID),
    );
    expect(only("R2", f)).toEqual(["R2:High"]);
  });
});

describe("R3 unexpected destinations", () => {
  it("fires for unknown hosts and direct IP connections", () => {
    const f = fired((t) => {
      script(t);
      t.dns("evil.invalid");
      t.http("POST", "evil.invalid", "/"); // same host: same finding
      t.dns("registry.npmjs.org.evil.invalid"); // look-alike (BT-13)
      t.connect(201, "192.0.2.10");
      t.connect(201, "::ffff:192.0.2.11"); // mapped form (BT-12)
      done(t);
    });
    expect(only("R3", f)).toHaveLength(4);
  });

  it("ignores the sink, loopback, and allowlisted hosts", () => {
    const f = fired((t) => {
      script(t);
      t.dns("registry.npmjs.org");
      t.dns("objects.githubusercontent.com");
      t.connect(201, "10.89.0.2");
      t.connect(201, "127.0.0.1");
      t.connect(201, "::ffff:10.89.0.2");
      done(t);
    });
    expect(only("R3", f)).toEqual([]);
  });
});

describe("R4 new executables", () => {
  it("fires for running a file written outside node_modules, and for bun", () => {
    const f = fired((t) => {
      script(t);
      t.write(201, "create", "/tmp/payload");
      t.exec(202, 201, "/tmp/payload", ["payload"]);
      t.exit(202, 0, 201);
      t.exec(203, 201, "/usr/local/bin/bun", ["bun", "x.js"]);
      t.exit(203, 0, 201);
      done(t);
    });
    expect(only("R4", f)).toEqual(["R4:High", "R4:High"]);
  });

  it("catches a file moved into place before running (rename target)", () => {
    const f = fired((t) => {
      script(t);
      t.write(201, "create", `${NODE_MODULES}/x/payload`);
      t.write(201, "rename", `${NODE_MODULES}/x/payload`, `${HOME}/.local/bin/helper`);
      t.exec(202, 201, `${HOME}/.local/bin/helper`, ["helper"]);
      t.exit(202, 0, 201);
      done(t);
    });
    expect(only("R4", f)).toEqual(["R4:High"]);
  });

  it("doesn't fire for a binary downloaded into node_modules (esbuild style)", () => {
    const f = fired((t) => {
      script(t);
      t.write(201, "create", `${NODE_MODULES}/esbuild/bin/esbuild`);
      t.exec(202, 201, `${NODE_MODULES}/esbuild/bin/esbuild`, ["esbuild", "--version"]);
      t.exit(202, 0, 201);
      done(t);
    });
    expect(only("R4", f)).toEqual([]);
  });
});

describe("R5 network tools", () => {
  it("fires for curl, a busybox applet (BT-8), and openssl s_client", () => {
    const f = fired((t) => {
      script(t);
      for (const [pid, path, argv] of [
        [202, "/usr/bin/curl", ["curl", "x"]],
        [203, "/bin/busybox", ["busybox", "wget", "x"]],
        [204, "/usr/bin/openssl", ["openssl", "s_client", "-connect", "x:443"]],
      ] as const) {
        t.exec(pid, 201, path, [...argv]);
        t.exit(pid, 0, 201);
      }
      done(t);
    });
    expect(only("R5", f)).toHaveLength(3);
  });

  it("doesn't fire for openssl used for hashing", () => {
    const f = fired((t) => {
      script(t);
      t.exec(202, 201, "/usr/bin/openssl", ["openssl", "dgst", "-sha256", "x"]);
      t.exit(202, 0, 201);
      done(t);
    });
    expect(only("R5", f)).toEqual([]);
  });
});

describe("R6 writes outside the package's area", () => {
  it("fires High for home writes and Critical for workflows, including rename targets (BT-9)", () => {
    const f = fired((t) => {
      script(t);
      t.write(201, "write", `${HOME}/.bashrc`);
      t.write(201, "create", "/tmp/x.yml");
      t.write(201, "rename", "/tmp/x.yml", `${PROJECT}/.github/workflows/x.yml`);
      t.write(201, "write", "/dev/sda"); // only the harmless devices are allowed (BT-15)
      done(t);
    });
    expect(only("R6", f).sort()).toEqual(["R6:Critical", "R6:High", "R6:High"].sort());
  });

  it("doesn't fire inside node_modules, temp, caches, or /dev/null", () => {
    const f = fired((t) => {
      script(t);
      t.write(201, "write", `${NODE_MODULES}/x/build/out.node`);
      t.write(201, "write", "/tmp/build.log");
      t.write(201, "write", `${HOME}/.cache/node-gyp/headers`);
      t.write(201, "write", "/dev/null");
      t.write(201, "write", `${NODE_MODULES}/x/.github/workflows/ci.yml`); // its own files
      done(t);
    });
    expect(only("R6", f)).toEqual([]);
  });

  it("doesn't count npm writing the lockfile", () => {
    expect(
      only(
        "R6",
        fired(() => {}),
      ),
    ).toEqual([]);
  });
});

describe("R7 npm registry writes", () => {
  it("fires for publish over HTTP, a whoami token check, and npm's abbreviations", () => {
    const f = fired((t) => {
      script(t);
      t.http("PUT", "registry.npmjs.org", "/some-pkg");
      t.http("GET", "registry.npmjs.org", "//%2D/whoami"); // path tricks
      t.exec(202, 201, "/usr/local/bin/npm", ["npm", "pu"]);
      t.exit(202, 0, 201);
      t.exec(203, 201, "/usr/local/bin/node", [
        "node",
        "/usr/lib/node_modules/npm/bin/npm-cli.js",
        "publish",
      ]);
      t.exit(203, 0, 201);
      done(t);
    });
    expect(only("R7", f)).toEqual(["R7:Critical", "R7:Critical", "R7:Critical", "R7:Critical"]);
  });

  it("doesn't fire for downloads or other commands", () => {
    const f = fired((t) => {
      script(t);
      t.http("GET", "registry.npmjs.org", "/some-pkg/-/some-pkg-1.0.0.tgz");
      t.exec(202, 201, "/usr/local/bin/npm", ["npm", "run", "build"]);
      t.exit(202, 0, 201);
      done(t);
    });
    expect(only("R7", f)).toEqual([]);
  });
});

describe("R8 GitHub writes", () => {
  it("fires for repo creation, runner registration, git push, a token check, and gh", () => {
    const f = fired((t) => {
      script(t);
      t.http("POST", "api.github.com", "/user/repos");
      t.http("POST", "api.github.com", "/repos/a/b/actions/runners/registration-token");
      t.http("GET", "api.github.com", "/user");
      t.exec(202, 201, "/usr/bin/git", ["git", "push", "origin", "main"]);
      t.exit(202, 0, 201);
      t.exec(203, 201, "/usr/bin/gh", ["gh", "repo", "list"]);
      t.exit(203, 0, 201);
      done(t);
    });
    expect(only("R8", f)).toEqual(["R8:Critical", "R8:Critical", "R8:High", "R8:Critical", "R8:High"]);
  });

  it("doesn't fire for clones or reading releases", () => {
    const f = fired((t) => {
      script(t);
      t.http("POST", "github.com", "/a/b.git/git-upload-pack");
      t.http("GET", "api.github.com", "/repos/a/b/releases/latest");
      done(t);
    });
    expect(only("R8", f)).toEqual([]);
  });
});

describe("R9 wiper", () => {
  const wipe = (n: number) => (t: TraceBuilder) => {
    script(t);
    for (let i = 0; i < n; i++) t.write(201, "delete", `${HOME}/docs/f${i}`);
    t.write(201, "delete", `${HOME}/docs/f0`); // a duplicate counts once
    done(t);
  };
  it("fires at 20 distinct paths", () => {
    expect(only("R9", fired(wipe(20)))).toEqual(["R9:Critical"]);
  });
  it("doesn't fire at 19", () => {
    expect(only("R9", fired(wipe(19)))).toEqual([]);
  });
});

describe("R10 lingering processes", () => {
  it("fires for a process with no exit", () => {
    const f = fired((t) => {
      script(t);
      t.exec(202, 201, "/usr/local/bin/node", ["node", "sleeper.js"]);
      done(t);
    });
    expect(only("R10", f)).toEqual(["R10:High"]);
  });

  it("fires for activity in the linger phase, even if the process exits", () => {
    const f = fired(
      (t) => script(t),
      (t) => t.inPhase("linger").read(201, "/tmp/x").exit(201),
    );
    expect(only("R10", f)).toEqual(["R10:High"]);
  });

  it("treats a reused pid after exit as a new process (BT-10)", () => {
    const f = fired((t) => {
      script(t, 202);
      done(t, 202);
      t.exec(202, 201, "/usr/local/bin/node", ["node", "again.js"]); // same pid, never exits
    });
    expect(only("R10", f)).toEqual(["R10:High"]);
  });

  it("doesn't fire when every process exits during install", () => {
    const f = fired((t) => {
      script(t);
      done(t);
    });
    expect(only("R10", f)).toEqual([]);
  });
});

// Each of these was SAFE (or too weak) before the 2026-11-18 security review
// (docs/reviews/2026-11-18-rules-engine-security-review.md).
describe("review regressions", () => {
  it("SR-1: reading a credential store through /proc/self/root is R2", () => {
    const f = fired((t) => {
      script(t);
      t.read(201, `/proc/self/root${HOME}/.npmrc`);
      t.read(201, `/proc/201/task/201/root${HOME}/.ssh/id_rsa`);
      t.read(201, "/proc/self/cwd/.env");
      done(t);
    });
    expect(only("R2", f)).toHaveLength(3);
  });

  it("SR-1: planting a workflow through /proc/self/root is Critical", () => {
    const f = fired((t) => {
      script(t);
      t.write(201, "create", `/proc/self/root${PROJECT}/.github/workflows/x.yml`);
      done(t);
    });
    expect(only("R6", f)).toEqual(["R6:Critical"]);
  });

  it("SR-2: writing through a symlinked directory in /tmp is judged at the real location", () => {
    const f = fired((t) => {
      script(t);
      t.write(201, "symlink", "/tmp/g", `${PROJECT}/.github`);
      t.write(201, "create", "/tmp/g/workflows/x.yml");
      t.write(201, "symlink", "/tmp/h", HOME);
      t.write(201, "write", "/tmp/h/.bashrc");
      done(t);
    });
    expect(only("R6", f).sort()).toEqual(["R6:Critical", "R6:High"]);
  });

  it("SR-2: reading through a symlinked directory is R2, including '..' after the link", () => {
    const f = fired((t) => {
      script(t);
      t.write(201, "symlink", "/tmp/d", `${HOME}/sub`);
      t.read(201, "/tmp/d/../.npmrc");
      done(t);
    });
    expect(only("R2", f)).toEqual(["R2:High"]);
  });

  it("SR-2: a network tool behind a symlink is still R5", () => {
    const f = fired((t) => {
      script(t);
      t.write(201, "symlink", "/tmp/c", "/usr/bin/curl");
      t.exec(202, 201, "/tmp/c", ["c", "x"]);
      t.exit(202, 0, 201);
      done(t);
    });
    expect(only("R5", f)).toEqual(["R5:High"]);
  });

  it("SR-2: a hard link to a file outside the allowed area is R6", () => {
    const f = fired((t) => {
      script(t);
      t.write(201, "hardlink", `${NODE_MODULES}/x/innocent`, `${HOME}/.bashrc`);
      done(t);
    });
    expect(only("R6", f)).toEqual(["R6:High"]);
  });

  it("SR-2: a symlink loop makes the write forbidden, not allowed", () => {
    const f = fired((t) => {
      script(t);
      t.write(201, "symlink", "/tmp/x", "/tmp/y");
      t.write(201, "symlink", "/tmp/y", "/tmp/x/z");
      t.write(201, "write", "/tmp/x/q");
      done(t);
    });
    expect(only("R6", f).length).toBeGreaterThan(0);
  });

  it("SR-7: a self-referential symlink plus long paths is judged quickly, and SUSPICIOUS", () => {
    const deep = `/tmp/x/${"a/".repeat(1900)}f`; // close to the 4096-character path limit
    const t = npmInstall((b) => {
      script(b);
      b.write(201, "symlink", "/tmp/x", "/tmp/x/x");
      b.write(201, "symlink", "/tmp/y", "/tmp/x");
      for (let i = 0; i < 400; i++) b.read(201, deep);
      done(b);
    });
    const v = judge(t.build());
    expect(v.kind).toBe("SUSPICIOUS");
    expect(v.findings.map((f) => f.ruleId)).toContain("R13");
  }, 5000);

  // The independent review measured ~51 ms per long path once any symlink existed. With the fast
  // path, paths that miss every link aren't walked at all.
  it("SR-7: one unrelated symlink doesn't make long paths slow, and stays SAFE", () => {
    const deep = `${NODE_MODULES}/${"a/".repeat(2000)}f`;
    const t = npmInstall((b) => {
      script(b);
      b.write(201, "symlink", "/tmp/one-link", "/tmp/elsewhere");
      for (let i = 0; i < 4000; i++) b.read(201, deep);
      done(b);
    });
    expect(judge(t.build()).kind).toBe("SAFE");
  }, 15_000);

  it("SR-7: 10,000 chained symlinks and long paths are judged in bounded time", () => {
    const t = npmInstall((b) => {
      script(b);
      for (let i = 0; i < 10_000; i++) b.write(201, "symlink", `/tmp/l${i}`, `/tmp/l${i + 1}`);
      for (let i = 0; i < 2000; i++) b.read(201, `/tmp/l0/${"a/".repeat(2000)}f`);
      done(b);
    });
    expect(judge(t.build()).kind).toBe("SUSPICIOUS");
  }, 15_000);

  it("SR-7: an incomplete resolution of a read is reported, so it can't hide a credential read", () => {
    const f = fired((t) => {
      script(t);
      t.write(201, "symlink", "/tmp/x", "/tmp/y");
      t.write(201, "symlink", "/tmp/y", "/tmp/x/z");
      t.read(201, "/tmp/x/q");
      done(t);
    });
    expect(only("R13", f)).toEqual(["R13:High"]);
  });

  it("SR-3: connecting to the sink on a port it doesn't record is R3", () => {
    const f = fired((t) => {
      script(t);
      t.connect(201, "10.89.0.2", 4444);
      t.connect(201, "10.89.0.2", 443); // recorded: fine
      done(t);
    });
    expect(only("R3", f)).toEqual(["R3:High"]);
  });

  it("SR-6: a script name like __proto__ isn't a lookup into Object.prototype", () => {
    const f = fired((t) => {
      script(t);
      t.exec(202, 201, "/usr/local/bin/node", ["node", "__proto__", "publish"]);
      t.exit(202, 0, 201);
      t.exec(203, 201, "/usr/local/bin/node", ["node", "constructor", "publish"]);
      t.exit(203, 0, 201);
      done(t);
    });
    expect(only("R7", f)).toEqual([]);
  });
});

describe("normaliser support (ruleset 1.2.0)", () => {
  it("R3 flags a send to an address the recorder couldn't see", () => {
    const f = fired((t) => {
      script(t);
      t.add({ type: "connect", pid: 201, ppid: 1, protocol: "udp", address: null, port: 4444 });
      done(t);
    });
    expect(only("R3", f)).toEqual(["R3:High"]);
  });

  it("R13 flags an exec whose argument list was cut off", () => {
    const f = fired((t) => {
      script(t);
      t.add({
        type: "exec",
        pid: 202,
        ppid: 201,
        path: "/usr/local/bin/npm",
        argv: ["npm", "--x"],
        argvTruncated: true,
      });
      t.exit(202, 0, 201);
      done(t);
    });
    expect(only("R13", f)).toEqual(["R13:High"]);
  });
});

describe("R13 incomplete trace", () => {
  it("fires when the trace was cut off", () => {
    const v = judge({ ...npmInstall(() => {}).build(), eventsTruncated: true });
    expect(v.kind).toBe("SUSPICIOUS");
    expect(v.findings.map((f) => f.ruleId)).toEqual(["R13"]);
  });

  it("fires when the sink cut off a request body, even to an allowlisted host (BT-20)", () => {
    const f = fired((t) => {
      script(t);
      t.add({
        type: "http",
        method: "POST",
        scheme: "https",
        host: "objects.githubusercontent.com",
        path: "/upload",
        headers: [],
        body: "A".repeat(1000),
        bodyTruncated: true,
      });
      done(t);
    });
    expect(only("R13", f)).toEqual(["R13:High"]);
  });
});
