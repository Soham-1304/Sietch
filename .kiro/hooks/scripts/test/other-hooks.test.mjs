import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { fake, REPO, runHook, SCRIPTS } from "./helpers.mjs";

const prompt = (text) => ({
  session_id: "sess_test",
  hook_event_name: "UserPromptSubmit",
  cwd: REPO,
  prompt: text,
});

describe("secret-guard", () => {
  it.each([
    ["GitHub token", `here is my token ${fake.gh()} please use it`],
    ["npm token", `npm token ${fake.npm()}`],
    ["AWS access key", `aws ${fake.aws()}`],
    ["private key", `${fake.privateKey()}\nabc`],
    ["database URL", `connect to mongodb+srv://soham:${"hunter2real"}@cluster0.abc.mongodb.net`],
    ["token whose text contains EXAMPLE", `ghp_EXAMPLE${"a".repeat(29)}`],
    ["second match after a placeholder", `AKIAIOSFODNN7EXAMPLE and AKIA${"Z".repeat(16)}`],
  ])("blocks a %s", (_label, text) => {
    const r = runHook("secret-guard.mjs", prompt(text));
    expect(r.status).toBe(2);
    expect(r.stderr).toContain("was not sent");
  });

  it("never echoes the secret back", () => {
    const token = fake.gh();
    const r = runHook("secret-guard.mjs", prompt(`token ${token}`));
    expect(r.stderr).not.toContain(token);
  });

  it.each([
    "lets proceed with the plan",
    "honeytokens look like npm_<random> and ghp_<random>",
    "docs example AKIAIOSFODNN7EXAMPLE",
    "connect to mongodb+srv://soham:<password>@cluster0.abc.mongodb.net",
    // biome-ignore lint/suspicious/noTemplateCurlyInString: a literal ${VAR} placeholder is the test input.
    "connect to postgres://app:${DB_PASSWORD}@localhost/db",
  ])("allows: %s", (text) => {
    expect(runHook("secret-guard.mjs", prompt(text)).status).toBe(0);
  });

  it("finds the text under any field name", () => {
    const r = runHook("secret-guard.mjs", {
      hook_event_name: "UserPromptSubmit",
      message: { content: `x ${fake.npm()}` },
    });
    expect(r.status).toBe(2);
  });

  it("reads the older USER_PROMPT variable", () => {
    const r = runHook("secret-guard.mjs", null, { rawInput: "", env: { USER_PROMPT: `token ${fake.gh()}` } });
    expect(r.status).toBe(2);
  });

  it("scans raw text when the event isn't JSON", () => {
    expect(runHook("secret-guard.mjs", null, { rawInput: `not json ${fake.gh()}` }).status).toBe(2);
  });

  it("blocks when there is no message at all (fail closed)", () => {
    const r = runHook("secret-guard.mjs", null, { rawInput: "" });
    expect(r.status).toBe(2);
    expect(r.stderr).toContain("couldn't find your message");
  });

  it("handles a huge message quickly (no catastrophic regex backtracking)", () => {
    const start = Date.now();
    const r = runHook("secret-guard.mjs", prompt(`mongodb://${"a".repeat(200_000)}:${"b".repeat(200_000)}`));
    expect(r.status).toBe(0);
    expect(Date.now() - start).toBeLessThan(5000);
  });
});

describe("check-on-save", () => {
  const event = (file) => ({ session_id: "s", hook_event_name: "PostFileSave", cwd: REPO, file_path: file });

  it("passes a clean file and really runs its tests", () => {
    const r = runHook("check-on-save.mjs", event(join(REPO, "base/core/src/errors.ts")));
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("passed");
  });

  it("reports a type error", () => {
    const file = join(REPO, "base/core/src/zz-check-on-save-probe.ts");
    writeFileSync(file, 'export const broken: number = "not a number";\n');
    try {
      const r = runHook("check-on-save.mjs", event(file));
      expect(r.status).toBe(1);
      expect(r.stderr).toContain("TS2322");
    } finally {
      rmSync(file, { force: true });
    }
  });

  it("ignores files outside base/ and apps/", () => {
    expect(runHook("check-on-save.mjs", event(join(REPO, "docs/plan.md"))).status).toBe(0);
  });

  it.each([
    ["empty input", ""],
    ["invalid JSON", "{"],
    ["no file path", JSON.stringify({ hook_event_name: "PostFileSave" })],
    ["the wrong event", JSON.stringify({ hook_event_name: "PreToolUse", file_path: "/x.ts" })],
    [
      "a file outside the project",
      JSON.stringify({ hook_event_name: "PostFileSave", file_path: "/etc/x.ts" }),
    ],
    [
      "a look-alike sibling folder",
      JSON.stringify({ hook_event_name: "PostFileSave", file_path: `${REPO}2/base/x.ts` }),
    ],
  ])("reports, rather than passes, on %s", (_label, rawInput) => {
    expect(runHook("check-on-save.mjs", null, { rawInput }).status).toBe(1);
  });
});

describe("run-node.sh", () => {
  const dir = mkdtempSync(join(tmpdir(), "run-node-"));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));
  const launcher = join(SCRIPTS, "run-node.sh");
  const probe = join(dir, "probe.mjs");
  writeFileSync(probe, "process.stdout.write(process.execPath + ' ' + process.argv.slice(2).join(','));\n");

  const run = (args, env, cwd = REPO) =>
    spawnSync("/bin/sh", [launcher, ...args], { cwd, encoding: "utf8", env, input: "" });

  it("finds node with an empty PATH and passes arguments through", () => {
    const r = run(["closed", probe, "a", "b c"], { HOME: process.env.HOME, PATH: "" });
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/^\/\S+node a,b c$/);
  });

  it("never runs a 'node' found through a relative PATH entry", () => {
    const fakeNode = join(dir, "node");
    writeFileSync(fakeNode, "#!/bin/sh\necho FAKE-NODE-RAN\n", { mode: 0o755 });
    const r = run(["closed", probe], { HOME: process.env.HOME, PATH: "." }, dir);
    expect(r.stdout).not.toContain("FAKE-NODE-RAN");
    expect(r.status).toBe(0);
  });

  it("ignores a malicious .nvmrc", () => {
    writeFileSync(join(dir, ".nvmrc"), "../../../../tmp/evil\n");
    const r = run(["closed", probe], { HOME: process.env.HOME, PATH: "" }, dir);
    expect(r.status).toBe(0);
    expect(r.stdout).not.toContain("evil");
  });

  it("blocks (exit 2) in closed mode when node can't be found", () => {
    const r = run(
      ["closed", probe],
      { HOME: "/nonexistent", NVM_DIR: "/nonexistent", PATH: "/nonexistent" },
      dir,
    );
    // Only meaningful on machines without a system node in /usr/local/bin or /opt/homebrew.
    if (r.stdout.includes("node")) return;
    expect(r.status).toBe(2);
  });

  it("rejects bad usage", () => {
    expect(run(["sideways", probe], { PATH: "" }).status).toBe(2);
    expect(run([], { PATH: "" }).status).toBe(2);
  });
});
