import { describe, expect, it } from "vitest";
import { SietchError } from "./errors.js";

class TraceParseError extends SietchError {}

describe("SietchError", () => {
  it("keeps the code, the message, and the cause", () => {
    const cause = new Error("bad line");
    const error = new SietchError("TRACE_PARSE_FAILED", "Could not parse trace", { cause });

    expect(error.code).toBe("TRACE_PARSE_FAILED");
    expect(error.message).toBe("Could not parse trace");
    expect(error.cause).toBe(cause);
    expect(error).toBeInstanceOf(Error);
  });

  it("uses the subclass name, so logs show which error it was", () => {
    const error = new TraceParseError("TRACE_PARSE_FAILED", "Could not parse trace");

    expect(error.name).toBe("TraceParseError");
    expect(error).toBeInstanceOf(SietchError);
  });
});
