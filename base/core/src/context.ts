// The read-only view every rule works from: events sorted by seq, attribution (package manager or
// package), every name each recorded path can be reached by, and the compiled allowlist and
// honeytokens.

import { type CompiledHoneytokens, compileHoneytokens } from "./honeytokens.js";
import { type CompiledAllowlist, canonicalIp, compileAllowlist } from "./hosts.js";
import { basename, isInside, joinPath, normalisePath, segments } from "./paths.js";
import type { Event, ScanInput } from "./schema.js";
import { quote, redactToken } from "./text.js";
import { LinkTable, type PathViews } from "./views.js";

/** Home-relative credential stores (Requirement 6.3). */
export const HOME_CREDENTIAL_ENTRIES = [
  ".npmrc",
  ".yarnrc",
  ".yarnrc.yml",
  ".config/gh",
  ".git-credentials",
  ".netrc",
  ".aws",
  ".ssh",
  ".docker/config.json",
  ".kube",
  ".config/gcloud",
  ".azure",
  ".gnupg",
  ".pypirc",
  ".bash_history",
  ".zsh_history",
] as const;

/** Home-relative directories a package may write to (caches). */
export const HOME_WRITE_ROOTS = [".npm", ".cache", ".node-gyp"] as const;
export const HARMLESS_DEVICES = ["/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"] as const;

const DOT_ENV = /^\.env(\..+)?$/;

export interface EventViews {
  readonly path?: PathViews;
  readonly target?: PathViews;
}

export interface RuleContext {
  readonly input: ScanInput;
  /** Sorted by seq. Paths and link targets are lexically normalised (for display and grouping). */
  readonly events: readonly Event[];
  readonly seqs: ReadonlySet<number>;
  readonly lastSeq: number;
  readonly home: string;
  readonly nodeModulesDir: string;
  readonly sinkAddresses: ReadonlySet<string>;
  readonly allowlist: CompiledAllowlist;
  readonly honeytokens: CompiledHoneytokens;
  /** Events not made by the package manager during install. dns and http are always package events. */
  isPackageEvent(event: Event): boolean;
  /** Every name the event's path (and link target) could refer to, given links created before it. */
  viewsOf(event: Event): EventViews;
  /** True if any view is a credential store. */
  touchesCredentials(views: PathViews | undefined): boolean;
  /** True only if every view is inside the allowed write area, and the views are complete. */
  isAllowedWrite(views: PathViews | undefined): boolean;
  /** Show an untrusted value: honeytokens redacted, unsafe characters escaped, length capped. */
  show(value: string): string;
}

function normaliseEvent(event: Event): Event {
  switch (event.type) {
    case "exec":
    case "file_read":
      return { ...event, path: normalisePath(event.path) };
    case "file_write":
      return event.target === undefined
        ? { ...event, path: normalisePath(event.path) }
        : { ...event, path: normalisePath(event.path), target: normalisePath(event.target) };
    case "connect":
    case "exit":
    case "dns":
    case "http":
      return event;
    default: {
      const unreachable: never = event;
      throw new TypeError(`unknown event type ${String((unreachable as { type?: unknown }).type)}`);
    }
  }
}

export function buildContext(input: ScanInput): RuleContext {
  const raw = [...input.events].sort((a, b) => a.seq - b.seq);
  const events = raw.map(normaliseEvent);
  const env = input.environment;
  const home = normalisePath(env.home);
  const projectDir = normalisePath(env.projectDir);
  const nodeModulesDir = normalisePath(env.nodeModulesDir);
  const pmPid = env.packageManagerPid;

  const credentialRoots = [
    ...HOME_CREDENTIAL_ENTRIES.map((e) => joinPath(home, e)),
    ...env.extraCredentialPaths.map(normalisePath),
  ];
  const writeRoots = [
    nodeModulesDir,
    ...env.tmpDirs.map(normalisePath),
    ...HOME_WRITE_ROOTS.map((e) => joinPath(home, e)),
    "/dev/pts",
  ];
  const harmless = new Set<string>(HARMLESS_DEVICES);

  const sinkAddresses = new Set<string>();
  for (const a of env.sinkAddresses) {
    const ip = canonicalIp(a);
    if (ip === null) throw new TypeError("sink address is not an IP"); // validation guarantees this
    sinkAddresses.add(ip);
  }

  // Views are computed in seq order, so each event only sees links created before it.
  const links = new LinkTable(home, projectDir);
  const views = new Map<number, EventViews>();
  for (const event of raw) {
    if (event.type === "exec" || event.type === "file_read") {
      views.set(event.seq, { path: links.views(event.path) });
    } else if (event.type === "file_write") {
      const pathViews = links.views(event.path);
      const targetViews = event.target === undefined ? undefined : links.views(event.target);
      views.set(
        event.seq,
        targetViews === undefined ? { path: pathViews } : { path: pathViews, target: targetViews },
      );
      if ((event.op === "symlink" || event.op === "hardlink") && event.target !== undefined) {
        const target = normalisePath(event.target);
        for (const name of pathViews.all) links.add(name, target);
      }
    }
  }

  const isCredentialPath = (path: string) => {
    if (credentialRoots.some((root) => isInside(path, root))) return true;
    const segs = segments(path);
    const last = segs[segs.length - 1] ?? "";
    if (segs[0] === "proc" && segs.length >= 3 && (last === "environ" || last === "mem")) return true;
    return DOT_ENV.test(basename(path)) && !isInside(path, nodeModulesDir);
  };
  const isAllowedPath = (path: string) =>
    harmless.has(path) || writeRoots.some((root) => isInside(path, root));
  const tokenValues = [...input.honeytokens].map((t) => t.value).sort((a, b) => b.length - a.length);

  return {
    input,
    events,
    seqs: new Set(events.map((e) => e.seq)),
    lastSeq: events[events.length - 1]?.seq ?? 0,
    home,
    nodeModulesDir,
    sinkAddresses,
    allowlist: compileAllowlist(input.allowlist),
    honeytokens: compileHoneytokens(input.honeytokens),
    isPackageEvent: (event) => !("pid" in event && event.pid === pmPid && event.phase === "install"),
    viewsOf: (event) => views.get(event.seq) ?? {},
    touchesCredentials: (v) => v?.all.some(isCredentialPath) === true,
    // Missing or incomplete views are never allowed (fail closed).
    isAllowedWrite: (v) => v?.complete === true && v.all.every(isAllowedPath),
    show: (value) => quote(redactTokens(value, tokenValues)),
  };
}

/**
 * Replace every occurrence of each token, in any letter case, with its redacted form. Longest
 * tokens go first, so a token that contains another is redacted whole. The redacted form ends
 * in "…", which no token contains, so a replacement can never join pieces into a new full token.
 */
export function redactTokens(value: string, tokenValues: readonly string[]): string {
  let out = value;
  for (const token of tokenValues) {
    const needle = token.toLowerCase();
    let at = out.toLowerCase().indexOf(needle);
    while (at >= 0) {
      const replacement = redactToken(out.slice(at, at + token.length));
      out = out.slice(0, at) + replacement + out.slice(at + token.length);
      at = out.toLowerCase().indexOf(needle, at + replacement.length);
    }
  }
  return out;
}
