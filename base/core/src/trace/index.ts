// normaliseTrace: gVisor JSON strace log -> rules-engine events. Pure, never throws.
// Design: .kiro/specs/trace-normaliser/design.md.

import { MAX_EVENTS } from "../limits.js";
import { joinPath } from "../paths.js";
import type { Event, ProcessEvent } from "../schema.js";
import { type NormaliseErrorCode, TraceFailure } from "./errors.js";
import { frameLog } from "./frame.js";
import { parseRecord } from "./record.js";
import { actionOf, cwdOf } from "./syscalls.js";

export type { NormaliseErrorCode } from "./errors.js";

export interface RunnerLayout {
  /** The container's init process (the runner's entrypoint), normally 1. */
  readonly initPid: number;
  /** Exactly the --strace-syscalls list the sandbox used. */
  readonly tracedSyscalls: readonly string[];
}

export type NormaliseResult =
  | {
      readonly ok: true;
      readonly events: Event[];
      readonly packageManagerPid: number;
      readonly eventsTruncated: boolean;
    }
  | { readonly ok: false; readonly code: NormaliseErrorCode; readonly reason: string };

type Role = "install" | "load" | "runner" | "unknown";
/** A process event without the fields normaliseTrace fills in (distributes over the union). */
type Body = ProcessEvent extends infer E
  ? E extends ProcessEvent
    ? Omit<E, "seq" | "t" | "phase" | "pid" | "ppid">
    : never
  : never;
type Phase = Event["phase"];

interface Proc {
  role: Role;
  ppid: number;
  cwd: string | null;
  exited: boolean;
}

export function normaliseTrace(log: string, layout: RunnerLayout): NormaliseResult {
  try {
    return run(log, layout);
  } catch (error) {
    if (error instanceof TraceFailure) return { ok: false, code: error.code, reason: error.message };
    return {
      ok: false,
      code: "INTERNAL",
      reason: `internal error (${error instanceof Error ? error.name : "unknown"})`,
    };
  }
}

function run(log: string, layout: RunnerLayout): NormaliseResult {
  const traced = new Set(layout.tracedSyscalls);
  const records = frameLog(log);
  const procs = new Map<number, Proc>();
  const proc = (pid: number): Proc => {
    let p = procs.get(pid);
    if (p === undefined) {
      // Never seen created: the init process is the runner's; anything else is kept (fail closed).
      p = { role: pid === layout.initPid ? "runner" : "unknown", ppid: 0, cwd: null, exited: false };
      procs.set(pid, p);
    }
    return p;
  };

  let initChildren = 0;
  let installPid: number | null = null;
  let loadPid: number | null = null;
  let installDone = false;
  let loadDone = false;
  const phase = (): Phase => (!installDone ? "install" : !loadDone ? "load" : "linger");

  const events: Event[] = [];
  let truncated = false;
  const firstTime = records[0]?.timeMs ?? 0;

  for (const rec of records) {
    const r = parseRecord(rec.body, rec.line);
    if (!traced.has(r.syscall)) throw new TraceFailure("UNEXPECTED_SYSCALL", rec.line);
    const self = proc(r.tgid);
    const cwd = cwdOf(r);
    if (cwd !== null) self.cwd = cwd; // gVisor prints the real working directory with AT_FDCWD
    const action = actionOf(r, rec.line);
    const t = Math.max(0, rec.timeMs - firstTime); // t is informational; rules order by seq
    const emit = (pid: number, event: Body) => {
      const p = proc(pid);
      if (p.role === "runner") return;
      if (events.length >= MAX_EVENTS) {
        truncated = true;
        return;
      }
      events.push({ ...event, seq: events.length + 1, t, phase: phase(), pid, ppid: p.ppid } as Event);
    };

    switch (action.kind) {
      case "clone": {
        if (action.thread) break;
        let role: Role = self.role === "runner" ? "runner" : self.role;
        if (r.tgid === layout.initPid) {
          initChildren++;
          role = initChildren === 1 ? "install" : initChildren === 2 ? "load" : "runner";
          if (role === "install") installPid = action.child;
          if (role === "load") loadPid = action.child;
        }
        // A new lifetime, even if the pid was used before (PID reuse).
        procs.set(action.child, { role, ppid: r.tgid, cwd: self.cwd, exited: false });
        break;
      }
      case "exit": {
        const p = proc(action.pid);
        if (p.exited) break;
        emit(action.pid, { type: "exit", code: action.code, signal: null });
        p.exited = true;
        if (action.pid === installPid) installDone = true;
        if (action.pid === loadPid) loadDone = true;
        break;
      }
      case "chdir":
        // fchdir and unknown starting points make the directory unknown until gVisor prints it again.
        if (action.path === null) self.cwd = null;
        else if (action.path.startsWith("/")) self.cwd = action.path;
        else self.cwd = self.cwd === null ? null : joinPath(self.cwd, action.path);
        break;
      case "exec": {
        let path = action.path;
        if (action.relative) {
          if (self.cwd === null) throw new TraceFailure("UNRESOLVED_PATH", rec.line);
          path = `${self.cwd.replace(/\/+$/, "")}/${path}`;
        }
        emit(r.tgid, {
          type: "exec",
          path,
          argv: action.argv,
          ...(action.argvTruncated ? { argvTruncated: true } : {}),
        });
        break;
      }
      case "read":
        emit(r.tgid, { type: "file_read", path: action.path });
        break;
      case "write":
        emit(
          r.tgid,
          action.target === undefined
            ? { type: "file_write", op: action.op, path: action.path }
            : { type: "file_write", op: action.op, path: action.path, target: action.target },
        );
        break;
      case "connect":
        emit(r.tgid, {
          type: "connect",
          protocol: action.protocol,
          address: action.address,
          port: action.port,
        });
        break;
      case "none":
        break;
      default: {
        const unreachable: never = action;
        throw new TraceFailure("INTERNAL", rec.line + (unreachable === undefined ? 0 : 0));
      }
    }
  }

  if (installPid === null || loadPid === null) throw new TraceFailure("MISSING_PHASE", 0);
  return { ok: true, events, packageManagerPid: installPid, eventsTruncated: truncated };
}
