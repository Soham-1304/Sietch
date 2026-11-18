import { describe, expect, it } from "vitest";
import { basename, isInside, joinPath, normalisePath, segments } from "./paths.js";

describe("paths", () => {
  it("normalises dots, repeated slashes, and trailing slashes", () => {
    expect(normalisePath("/a//b/./c/")).toBe("/a/b/c");
    expect(normalisePath("/a/b/../c")).toBe("/a/c");
    expect(normalisePath("/")).toBe("/");
  });

  it("never goes above the root", () => {
    expect(normalisePath("/../../etc/passwd")).toBe("/etc/passwd");
    expect(segments("/a/../../b")).toEqual(["b"]);
  });

  it("compares whole segments, not string prefixes", () => {
    expect(isInside("/a/bc", "/a/b")).toBe(false);
    expect(isInside("/a/b", "/a/b")).toBe(true);
    expect(isInside("/a/b/c", "/a/b")).toBe(true);
    expect(isInside("/a/b/../x", "/a/b")).toBe(false);
    expect(isInside("/anything", "/")).toBe(true);
  });

  it("takes basenames of absolute and relative strings", () => {
    expect(basename("/usr/bin/curl")).toBe("curl");
    expect(basename("wget")).toBe("wget");
    expect(basename("/")).toBe("");
    expect(basename("/x/y/")).toBe("y");
  });

  it("joins paths", () => {
    expect(joinPath("/home/dev", ".config/gh")).toBe("/home/dev/.config/gh");
  });
});
