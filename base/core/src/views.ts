// Every name a path can be reached by (security review SR-1 and SR-2).
//
// A recorded path such as "/tmp/g/workflows/x.yml" may really be "/work/app/.github/workflows/x.yml"
// if the package made /tmp/g a symlink earlier. "/tmp/d/../.npmrc" with /tmp/d -> /home/dev/sub is
// "/home/dev/.npmrc", because the kernel resolves the link before applying "..". And
// "/proc/self/root/home/dev/.npmrc" is "/home/dev/.npmrc".
//
// So paths are walked one raw segment at a time, as the kernel does: a link is expanded when its
// name is reached, and ".." applies to the expanded result. Both the link and the literal name are
// kept as views, because a link recorded earlier may have been removed since. Extra views can only
// add findings, never remove them, which is the fail-closed direction.
//
// The walk has a work budget. If it runs out (a link loop, or deliberate depth), the result is
// marked incomplete and the rules treat the path as forbidden.

import { MAX_SYMLINK_HOPS } from "./limits.js";
import { segments } from "./paths.js";

export interface PathViews {
  /** Lexically normalised path first, then every other view, without duplicates. */
  readonly all: readonly string[];
  /** False when the walk ran out of budget, so some views may be missing. */
  readonly complete: boolean;
}

const MAX_VIEWS = 16;
const MAX_LINKS = 10_000;

interface State {
  readonly done: readonly string[];
  readonly rest: readonly string[];
  readonly hops: number;
}

export class LinkTable {
  private readonly links = new Map<string, string[][]>();
  private total = 0;
  private overflowed = false;
  private readonly homeSegs: string[];
  private readonly projectSegs: string[];

  constructor(home: string, projectDir: string) {
    this.homeSegs = segments(home);
    this.projectSegs = segments(projectDir);
  }

  /** Record that `linkPath` (absolute, normalised) is another name for `targetPath`. */
  add(linkPath: string, targetPath: string): void {
    if (this.total >= MAX_LINKS) {
      this.overflowed = true;
      return;
    }
    const target = segments(targetPath);
    const key = keyOf(segments(linkPath));
    const existing = this.links.get(key) ?? [];
    if (existing.some((t) => keyOf(t) === keyOf(target))) return;
    existing.push(target);
    this.links.set(key, existing);
    this.total++;
  }

  /** Targets recorded for exactly this link path. */
  targetsAt(linkPath: string): readonly string[][] {
    return this.links.get(keyOf(segments(linkPath))) ?? [];
  }

  /** All views of a raw (not normalised) absolute path, given the links recorded so far. */
  views(rawPath: string): PathViews {
    const raw = rawPath.split("/").filter((s) => s !== "");
    const lexical = `/${segments(rawPath).join("/")}`;
    const hasProc = raw[0] === "proc";
    if (this.links.size === 0 && !hasProc && !this.overflowed) return { all: [lexical], complete: true };

    const out = new Set<string>([lexical]);
    let complete = !this.overflowed;
    const budget = Math.min(50_000, 64 + 4 * (raw.length + 1) * (MAX_SYMLINK_HOPS + 1));
    let work = 0;
    const stack: State[] = [{ done: [], rest: raw, hops: 0 }];

    while (stack.length > 0) {
      const state = stack.pop();
      if (state === undefined) break;
      if (++work > budget || out.size > MAX_VIEWS) {
        complete = false;
        break;
      }
      const [seg, ...rest] = state.rest;
      if (seg === undefined) {
        out.add(`/${state.done.join("/")}`);
        continue;
      }
      if (seg === ".") {
        stack.push({ done: state.done, rest, hops: state.hops });
        continue;
      }
      if (seg === "..") {
        stack.push({ done: state.done.slice(0, -1), rest, hops: state.hops });
        continue;
      }
      const done = [...state.done, seg];
      stack.push({ done, rest, hops: state.hops }); // the literal name

      for (const alias of this.procAlias(done)) stack.push({ done: alias, rest, hops: state.hops });

      const targets = this.links.get(keyOf(done));
      if (targets !== undefined) {
        if (state.hops >= MAX_SYMLINK_HOPS) {
          complete = false;
          continue;
        }
        for (const target of targets)
          stack.push({ done: [], rest: [...target, ...rest], hops: state.hops + 1 });
      }
    }
    return { all: [...out], complete };
  }

  /** /proc/<p>/root and /proc/<p>/task/<t>/root are "/". /proc/<p>/cwd is likely home or the project. */
  private procAlias(done: readonly string[]): string[][] {
    if (done[0] !== "proc") return [];
    const last = done[done.length - 1];
    const isRoot = (done.length === 3 || (done.length === 5 && done[2] === "task")) && last === "root";
    const isCwd = (done.length === 3 || (done.length === 5 && done[2] === "task")) && last === "cwd";
    if (isRoot) return [[]];
    if (isCwd) return [this.homeSegs, this.projectSegs];
    return [];
  }
}

const keyOf = (segs: readonly string[]) => `/${segs.join("/")}`;
