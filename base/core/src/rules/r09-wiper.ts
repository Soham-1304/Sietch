import { WIPER_THRESHOLD } from "../limits.js";
import type { FindingDraft, Rule } from "./types.js";

/** R9: deleting, truncating, or moving away many files outside the package's area. */
export const r09Wiper: Rule = {
  id: "R9",
  title: "Wiped files",
  evaluate(ctx) {
    const hit = new Map<string, number>();
    for (const event of ctx.events) {
      if (!ctx.isPackageEvent(event) || event.type !== "file_write") continue;
      if (event.op !== "delete" && event.op !== "truncate" && event.op !== "rename") continue;
      if (ctx.isAllowedWrite(ctx.viewsOf(event).path) || hit.has(event.path)) continue;
      hit.set(event.path, event.seq);
    }
    if (hit.size < WIPER_THRESHOLD) return [];
    const [example] = hit.keys();
    const draft: FindingDraft = {
      severity: "Critical",
      explanation: `Deleted, truncated, or moved away ${hit.size} files outside its own area, for example ${ctx.show(example ?? "")}. This is how a wiper behaves.`,
      evidence: [...hit.values()],
    };
    return [draft];
  },
};
