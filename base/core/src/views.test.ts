import { describe, expect, it } from "vitest";
import { LinkTable } from "./views.js";

const table = () => new LinkTable("/home/dev", "/work/app");

describe("LinkTable", () => {
  it("returns just the path when there are no links", () => {
    expect(table().views("/tmp/a")).toEqual({ all: ["/tmp/a"], complete: true });
  });

  it("resolves a symlinked directory prefix", () => {
    const t = table();
    t.add("/tmp/g", "/work/app/.github");
    expect(t.views("/tmp/g/workflows/x.yml").all).toEqual([
      "/tmp/g/workflows/x.yml",
      "/work/app/.github/workflows/x.yml",
    ]);
  });

  it("follows chains of links", () => {
    const t = table();
    t.add("/tmp/a", "/tmp/b");
    t.add("/tmp/b", "/home/dev");
    expect(t.views("/tmp/a/.bashrc").all).toContain("/home/dev/.bashrc");
  });

  it("canonicalises /proc root and task root aliases", () => {
    expect(table().views("/proc/self/root/home/dev/.npmrc").all).toContain("/home/dev/.npmrc");
    expect(table().views("/proc/12/task/13/root/etc/passwd").all).toContain("/etc/passwd");
  });

  it("adds home and project views for /proc cwd", () => {
    const all = table().views("/proc/self/cwd/.env").all;
    expect(all).toContain("/home/dev/.env");
    expect(all).toContain("/work/app/.env");
  });

  it("keeps every target a link has pointed to", () => {
    const t = table();
    t.add("/tmp/l", "/tmp/harmless");
    t.add("/tmp/l", "/home/dev/.ssh");
    expect(t.views("/tmp/l/id_rsa").all).toContain("/home/dev/.ssh/id_rsa");
  });

  it("reports an incomplete resolution for a link loop", () => {
    const t = table();
    t.add("/tmp/x", "/tmp/y");
    t.add("/tmp/y", "/tmp/x/z");
    const v = t.views("/tmp/x/q");
    expect(v.complete).toBe(false);
  });

  it("applies .. after expanding a link, as the kernel does", () => {
    const t = table();
    t.add("/tmp/d", "/home/dev/sub");
    const all = t.views("/tmp/d/../.npmrc").all;
    expect(all).toContain("/tmp/.npmrc"); // the lexical reading
    expect(all).toContain("/home/dev/.npmrc"); // what the kernel actually opens
  });

  it("is complete and fast for a long ordinary path", () => {
    const t = table();
    t.add("/x", "/y");
    const deep = `/work/app/node_modules/${"a/".repeat(200)}index.js`;
    expect(t.views(deep)).toEqual({ all: [deep], complete: true });
  });

  it("returns the raw path's lexical form first", () => {
    expect(table().views("/a/./b/../c").all[0]).toBe("/a/c");
  });
});
