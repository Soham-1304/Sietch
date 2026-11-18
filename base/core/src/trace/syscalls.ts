// Stage 3: per-syscall argument parsers. Attacker strings (paths, link targets, directory names)
// are printed unquoted, so every split on a fixed separator must be the only possible one.

import { MAX_ARG, MAX_ARGV } from "../limits.js";
import { joinPath, segments } from "../paths.js";
import type { FILE_WRITE_OPS } from "../schema.js";
import { TraceFailure } from "./errors.js";
import type { ParsedRecord } from "./record.js";

export type Action =
  | { kind: "exec"; path: string; relative: boolean; argv: string[]; argvTruncated: boolean }
  | { kind: "chdir"; path: string | null }
  | { kind: "read"; path: string }
  | { kind: "write"; op: (typeof FILE_WRITE_OPS)[number]; path: string; target?: string }
  | { kind: "connect"; address: string | null; port: number; protocol: "tcp" | "udp" }
  | { kind: "clone"; child: number; thread: boolean }
  | { kind: "exit"; pid: number; code: number | null }
  | { kind: "none" };

const AT_FDCWD_HEX = "0xffffffffffffff9c";
const fail = (code: "AMBIGUOUS_RECORD" | "MALFORMED_RECORD" | "UNRESOLVED_PATH", line: number): never => {
  throw new TraceFailure(code, line);
};

const isHex = (s: string) => /^0x[0-9a-f]{1,16}$/.test(s);

/** Start indices of every ", 0x<hex> " in text (the separator gVisor puts before a string argument). */
function stringSeparators(text: string): { start: number; end: number }[] {
  const out: { start: number; end: number }[] = [];
  let at = text.indexOf(", 0x");
  while (at >= 0) {
    let i = at + 4;
    while (i < text.length && /[0-9a-f]/.test(text[i] ?? "")) i++;
    if (i > at + 4 && text[i] === " ") out.push({ start: at, end: i + 1 });
    at = text.indexOf(", 0x", at + 1);
  }
  return out;
}

/** Remove a trailing ", <token>" where token matches `ok`. */
function stripTail(text: string, ok: (t: string) => boolean, line: number): { head: string; token: string } {
  const at = text.lastIndexOf(", ");
  if (at < 0) return fail("MALFORMED_RECORD", line);
  const token = text.slice(at + 2);
  if (!ok(token)) return fail("MALFORMED_RECORD", line);
  return { head: text.slice(0, at), token };
}

/** "<DIRFD> <CWD>" before the first string separator, resolved to a directory or null. */
function dirOf(prefix: string): string | null {
  if (prefix.startsWith("AT_FDCWD ")) {
    const cwd = prefix.slice(9);
    return cwd.startsWith("/") ? cwd : null;
  }
  return null; // another dirfd: only absolute paths can be used
}

function absolute(path: string, dir: string | null, line: number): string {
  if (path.startsWith("/")) return path;
  if (dir === null) return fail("UNRESOLVED_PATH", line);
  return `${dir.replace(/\/+$/, "")}/${path}`;
}

/** "<DIRFD> <CWD>, 0x<a> <PATH>" with exactly one separator. */
function dirAndPath(text: string, line: number): string {
  const seps = stringSeparators(text);
  if (seps.length !== 1) return fail("AMBIGUOUS_RECORD", line);
  const sep = seps[0] as { start: number; end: number };
  return absolute(text.slice(sep.end), dirOf(text.slice(0, sep.start)), line);
}

/** Two paths: "<DIRFD> <CWD>, 0x<a> OLD, 0x<newdirfd>, 0x<a> NEW". */
function twoPaths(text: string, line: number): { from: string; to: string } {
  const seps = stringSeparators(text);
  if (seps.length !== 2) return fail("AMBIGUOUS_RECORD", line);
  const [s1, s2] = seps as [{ start: number; end: number }, { start: number; end: number }];
  const middle = text.slice(s1.end, s2.start); // "OLD, 0x<newdirfd>"
  const nd = middle.lastIndexOf(", 0x");
  if (nd < 0 || !isHex(middle.slice(nd + 2))) return fail("MALFORMED_RECORD", line);
  const dir = dirOf(text.slice(0, s1.start));
  const from = absolute(middle.slice(0, nd), dir, line);
  const newDirFd = middle.slice(nd + 2);
  const to = absolute(text.slice(s2.end), newDirFd === AT_FDCWD_HEX ? dir : null, line);
  return { from, to };
}

const isOctalMode = (t: string) => /^0o[0-7]{1,7}$/.test(t);
const isFlagToken = (t: string) => t.length <= 256 && /^[A-Z0-9_|x]+$/.test(t);

function openFlags(token: string): { write: boolean; creat: boolean; trunc: boolean } {
  let bits = 0;
  const names = new Set<string>();
  for (const part of token.split("|")) {
    if (isHex(part)) bits |= Number.parseInt(part.slice(2), 16);
    else names.add(part);
  }
  const write = names.has("O_WRONLY") || names.has("O_RDWR") || (bits & 3) !== 0;
  return {
    write,
    creat: names.has("O_CREAT") || (bits & 0x40) !== 0,
    trunc: names.has("O_TRUNC") || (bits & 0x200) !== 0,
  };
}

const ESCAPES: Record<string, string> = {
  n: "\n",
  t: "\t",
  r: "\r",
  a: "\x07",
  b: "\b",
  f: "\f",
  v: "\v",
  "\\": "\\",
  '"': '"',
  "'": "'",
};

/** Parse a Go-quoted string starting at text[i] === '"'. Returns the value and the index after it. */
function quoted(text: string, i: number): { value: string; end: number } | null {
  if (text[i] !== '"') return null;
  let out = "";
  let j = i + 1;
  while (j < text.length) {
    const c = text[j] as string;
    if (c === '"') return { value: out, end: j + 1 };
    if (c !== "\\") {
      out += c;
      j++;
      continue;
    }
    const e = text[j + 1];
    if (e === undefined) return null;
    if (e in ESCAPES) {
      out += ESCAPES[e];
      j += 2;
    } else if (e === "x" && /^[0-9a-fA-F]{2}$/.test(text.slice(j + 2, j + 4))) {
      out += String.fromCharCode(Number.parseInt(text.slice(j + 2, j + 4), 16));
      j += 4;
    } else if (/^[0-7]{3}$/.test(text.slice(j + 1, j + 4))) {
      out += String.fromCharCode(Number.parseInt(text.slice(j + 1, j + 4), 8) & 0xff);
      j += 4;
    } else if (
      (e === "u" || e === "U") &&
      /^[0-9a-fA-F]+$/.test(text.slice(j + 2, j + (e === "u" ? 6 : 10)))
    ) {
      const n = e === "u" ? 4 : 8;
      const cp = Number.parseInt(text.slice(j + 2, j + 2 + n), 16);
      if (cp > 0x10ffff) return null;
      out += String.fromCodePoint(cp);
      j += 2 + n;
    } else return null;
  }
  return null;
}

/** Parse `[` "a", "b" `]` starting at text[i] === '['. Returns the strings and the index after "]". */
function quotedList(text: string, i: number): { values: string[]; end: number } | null {
  if (text[i] !== "[") return null;
  const values: string[] = [];
  let j = i + 1;
  if (text[j] === "]") return { values, end: j + 1 };
  for (;;) {
    const q = quoted(text, j);
    if (q === null) return null;
    values.push(q.value);
    j = q.end;
    if (text[j] === "]") return { values, end: j + 1 };
    if (text.slice(j, j + 2) !== ", ") return null;
    j += 2;
  }
}

/** "0x<a> PATH, 0x<a> [ARGV], 0x<a> [ENVP]" (envp discarded: it holds honeytokens). */
function execArgs(text: string, line: number): { path: string; argv: string[] } {
  const m = /^0x[0-9a-f]+ /.exec(text);
  if (m === null) return fail("MALFORMED_RECORD", line);
  const candidates = stringSeparators(text).filter((s) => text[s.end] === "[");
  if (candidates.length > 4) return fail("AMBIGUOUS_RECORD", line);
  const valid: { path: string; argv: string[] }[] = [];
  for (const c of candidates) {
    const argv = quotedList(text, c.end);
    if (argv === null) continue;
    const rest = text.slice(argv.end);
    const envSep = /^, 0x[0-9a-f]+ /.exec(rest);
    if (envSep === null) continue;
    const env = quotedList(rest, envSep[0].length);
    if (env === null || env.end !== rest.length) continue;
    valid.push({ path: text.slice(m[0].length, c.start), argv: argv.values });
  }
  if (valid.length !== 1) return fail("AMBIGUOUS_RECORD", line);
  return valid[0] as { path: string; argv: string[] };
}

function capArgv(argv: string[]): { argv: string[]; truncated: boolean } {
  let truncated = argv.length > MAX_ARGV;
  const out = argv.slice(0, MAX_ARGV).map((a) => {
    if (a.length <= MAX_ARG) return a;
    truncated = true;
    return a.slice(0, MAX_ARG);
  });
  return { argv: out, truncated };
}

const FAMILY = /^\{Family: (AF_INET6?), Addr: ([0-9a-fA-F:.]{1,64}), Port: (\d{1,5})\}/;

/** Turn one parsed record into an action. Unsuccessful calls produce nothing, except connect. */
/** Working directory gVisor printed with AT_FDCWD in this record, if any. */
export function cwdOf(r: ParsedRecord): string | null {
  if (r.kind !== "X" || r.ret === null || r.ret < 0) return null;
  const at = r.args.indexOf("AT_FDCWD ");
  if (at < 0) return null;
  const seps = stringSeparators(r.args.slice(at));
  if (seps.length === 0) return null;
  const cwd = r.args.slice(at + 9, at + (seps[0] as { start: number }).start);
  return cwd.startsWith("/") && countOf(r.args, "AT_FDCWD ") === 1 ? cwd : null;
}

export function actionOf(r: ParsedRecord, line: number): Action {
  const ok = r.ret !== null && r.ret >= 0;
  const a = r.args;
  switch (r.syscall) {
    case "exit_group": {
      if (r.kind !== "E" || !isHex(a)) return { kind: "none" };
      return { kind: "exit", pid: r.tgid, code: Number.parseInt(a.slice(2), 16) & 0xff };
    }
    case "wait4": {
      if (r.kind !== "X" || r.ret === null || r.ret <= 0) return { kind: "none" };
      return { kind: "exit", pid: r.ret, code: null };
    }
    case "clone":
    case "clone3": {
      if (r.kind !== "X" || r.ret === null || r.ret <= 0) return { kind: "none" };
      const flags = r.syscall === "clone" ? (a.split(", ")[0] ?? "") : a;
      const thread =
        flags.includes("CLONE_THREAD") ||
        (isHex(flags) && (Number.parseInt(flags.slice(2), 16) & 0x10000) !== 0);
      return { kind: "clone", child: r.ret, thread };
    }
    case "waitid":
    case "kill":
    case "tgkill":
      return { kind: "none" };
  }
  if (r.kind !== "X") return { kind: "none" };

  switch (r.syscall) {
    case "connect": {
      const brace = a.indexOf("{Family: ");
      if (brace < 0) return fail("MALFORMED_RECORD", line);
      if (a.startsWith("{Family: AF_UNIX", brace) || !a.startsWith("{Family: AF_INET", brace))
        return { kind: "none" };
      const m = FAMILY.exec(a.slice(brace));
      if (m === null) return fail("MALFORMED_RECORD", line);
      return { kind: "connect", address: m[2] ?? null, port: Number(m[3]), protocol: "tcp" };
    }
    case "sendmsg": {
      const m = /\{name=0x[0-9a-f]+, namelen=(\d{1,5}),/.exec(a.slice(0, 200));
      if (m === null) return fail("MALFORMED_RECORD", line);
      return Number(m[1]) > 0
        ? { kind: "connect", address: null, port: 0, protocol: "udp" }
        : { kind: "none" };
    }
    case "sendto": {
      const { token } = stripTail(a, isHex, line); // addrlen
      return Number.parseInt(token.slice(2), 16) > 0
        ? { kind: "connect", address: null, port: 0, protocol: "udp" }
        : { kind: "none" };
    }
  }
  if (!ok) return { kind: "none" };

  switch (r.syscall) {
    case "execve": {
      const { path, argv } = execArgs(a, line);
      const capped = capArgv(argv);
      return {
        kind: "exec",
        path,
        relative: !path.startsWith("/"),
        argv: capped.argv,
        argvTruncated: capped.truncated,
      };
    }
    case "execveat": {
      const flags = stripTail(a, isHex, line);
      const first = stringSeparators(flags.head)[0];
      if (first === undefined) return fail("MALFORMED_RECORD", line);
      const inner = execArgs(flags.head.slice(first.start + 2), line);
      const capped = capArgv(inner.argv);
      const dir = dirOf(flags.head.slice(0, first.start));
      return {
        kind: "exec",
        path: absolute(inner.path, dir, line),
        relative: false,
        argv: capped.argv,
        argvTruncated: capped.truncated,
      };
    }
    case "openat": {
      const mode = stripTail(a, isOctalMode, line);
      const flags = stripTail(mode.head, isFlagToken, line);
      const path = dirAndPath(flags.head, line);
      const f = openFlags(flags.token);
      if (!f.write) return { kind: "read", path };
      return { kind: "write", op: f.trunc ? "truncate" : f.creat ? "create" : "write", path };
    }
    case "chdir": {
      const m = /^0x[0-9a-f]+ /.exec(a);
      if (m === null) return fail("MALFORMED_RECORD", line);
      return { kind: "chdir", path: a.slice(m[0].length) };
    }
    case "fchdir":
      return { kind: "chdir", path: null };
    case "mkdirat":
      return { kind: "write", op: "mkdir", path: dirAndPath(stripTail(a, isHex, line).head, line) };
    case "unlinkat":
      return { kind: "write", op: "delete", path: dirAndPath(stripTail(a, isHex, line).head, line) };
    case "fchmodat":
      return { kind: "write", op: "chmod", path: dirAndPath(stripTail(a, isOctalMode, line).head, line) };
    case "renameat": {
      const p = twoPaths(a, line);
      return { kind: "write", op: "rename", path: p.from, target: p.to };
    }
    case "renameat2": {
      const p = twoPaths(stripTail(a, isHex, line).head, line);
      return { kind: "write", op: "rename", path: p.from, target: p.to };
    }
    case "linkat": {
      const p = twoPaths(stripTail(a, isHex, line).head, line);
      return { kind: "write", op: "hardlink", path: p.to, target: p.from };
    }
    case "symlinkat": {
      // "0x<a> TARGET, AT_FDCWD <CWD>, 0x<a> LINKPATH"
      const lead = /^0x[0-9a-f]+ /.exec(a);
      const markers = countOf(a, ", AT_FDCWD ");
      if (lead === null || markers !== 1) return fail("AMBIGUOUS_RECORD", line);
      const mk = a.indexOf(", AT_FDCWD ");
      const target = a.slice(lead[0].length, mk);
      const rest = a.slice(mk + 2);
      const link = dirAndPath(rest, line);
      const linkDir = `/${segments(link).slice(0, -1).join("/")}`;
      const resolved = target.startsWith("/") ? target : joinPath(linkDir, target);
      return { kind: "write", op: "symlink", path: link, target: resolved };
    }
  }
  return { kind: "none" };
}

function countOf(text: string, needle: string): number {
  let n = 0;
  let at = text.indexOf(needle);
  while (at >= 0) {
    n++;
    at = text.indexOf(needle, at + 1);
  }
  return n;
}
