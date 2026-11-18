import { Grouper, type Rule } from "./types.js";

/**
 * R13: part of the behaviour wasn't seen. Either the trace hit the event limit, or the capture
 * sink cut off a request body, so a honeytoken could be in the part R1 never saw (blue-team BT-20).
 */
export const r13TruncatedTrace: Rule = {
  id: "R13",
  title: "Part of the trace is missing",
  evaluate(ctx) {
    const g = new Grouper();
    if (ctx.input.eventsTruncated) {
      g.add(
        "events",
        "High",
        "The trace reached the event limit and was cut off, so anything the package did afterwards wasn't seen.",
        ctx.lastSeq,
      );
    }
    for (const event of ctx.events) {
      if (event.type === "http" && event.bodyTruncated) {
        g.add(
          `body:${event.host}`,
          "High",
          `A ${event.method} request to ${ctx.show(event.host)} had a body larger than the capture limit, so part of what was sent wasn't checked.`,
          event.seq,
        );
      }
    }
    return g.drafts();
  },
};
