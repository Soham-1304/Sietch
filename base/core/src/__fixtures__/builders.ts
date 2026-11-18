// A small builder for hand-written traces. Honeytoken values are built at run time, so the
// repository never contains a secret-shaped literal. None of these values is a real credential.

import type { Event, ScanInput } from "../schema.js";

type Phase = "install" | "load" | "linger";
type Draft = Event extends infer E ? (E extends Event ? Omit<E, "seq" | "t" | "phase"> : never) : never;

export const HOME = "/home/dev";
export const PROJECT = "/work/app";
export const NODE_MODULES = "/work/app/node_modules";
export const PM_PID = 100;
export const SINK = "10.89.0.2";

/** Deep copy for plain JSON data (base/core has no structuredClone: no DOM or Node types). */
export const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

/** A valid integrity string built from a seed character. */
export const integrity = (c = "A") => `sha512-${c.repeat(86)}==`;

export const fakeTokens = {
  npm: () => `npm_${"Fk3".repeat(12)}`,
  github: () => `ghp_${"Hn7".repeat(12)}`,
  aws: () => `AKIA${"Q".repeat(16)}`,
};

export class TraceBuilder {
  private readonly events: Event[] = [];
  private nextSeq = 1;
  private phase: Phase = "install";

  inPhase(phase: Phase): this {
    this.phase = phase;
    return this;
  }

  add(draft: Draft): this {
    const seq = this.nextSeq++;
    this.events.push({ ...draft, seq, t: seq * 10, phase: this.phase } as Event);
    return this;
  }

  exec(pid: number, ppid: number, path: string, argv: string[]): this {
    return this.add({ type: "exec", pid, ppid, path, argv });
  }
  read(pid: number, path: string, ppid = 1): this {
    return this.add({ type: "file_read", pid, ppid, path });
  }
  write(
    pid: number,
    op: typeof import("../schema.js").FILE_WRITE_OPS[number],
    path: string,
    target?: string,
    ppid = 1,
  ): this {
    return this.add(
      target === undefined
        ? { type: "file_write", pid, ppid, op, path }
        : { type: "file_write", pid, ppid, op, path, target },
    );
  }
  connect(pid: number, address: string, port = 443, ppid = 1): this {
    return this.add({ type: "connect", pid, ppid, protocol: "tcp", address, port });
  }
  exit(pid: number, code = 0, ppid = 1): this {
    return this.add({ type: "exit", pid, ppid, code, signal: null });
  }
  dns(name: string): this {
    return this.add({ type: "dns", name, qtype: "A" });
  }
  http(method: string, host: string, path: string, body = "", headers: [string, string][] = []): this {
    return this.add({
      type: "http",
      method,
      scheme: "https",
      host,
      path,
      headers,
      body,
      bodyTruncated: false,
    });
  }

  /** The npm process starting and exiting around everything added in between. */
  build(overrides: Partial<ScanInput> = {}): ScanInput {
    return {
      package: { name: "fixture-pkg", version: "1.0.0", integrity: integrity() },
      environment: {
        home: HOME,
        projectDir: PROJECT,
        nodeModulesDir: NODE_MODULES,
        tmpDirs: ["/tmp"],
        packageManagerPid: PM_PID,
        sinkAddresses: [SINK],
        extraCredentialPaths: [],
      },
      allowlist: ["registry.npmjs.org", "*.githubusercontent.com"],
      honeytokens: [
        { id: "npm", kind: "npm", value: fakeTokens.npm() },
        { id: "gh", kind: "github", value: fakeTokens.github() },
      ],
      events: [...this.events],
      eventsTruncated: false,
      ...overrides,
    };
  }
}

/** A trace with npm starting, then `body` adding events, then npm exiting. */
export function npmInstall(body: (t: TraceBuilder) => void): TraceBuilder {
  const t = new TraceBuilder();
  t.exec(PM_PID, 1, "/usr/local/bin/npm", ["npm", "install", "--ignore-scripts=false"]);
  t.read(PM_PID, `${HOME}/.npmrc`);
  t.read(PM_PID, `${PROJECT}/package.json`);
  t.write(PM_PID, "write", `${PROJECT}/package-lock.json`);
  body(t);
  t.inPhase("install").exit(PM_PID);
  return t;
}
