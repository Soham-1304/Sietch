import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const SCRIPTS = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const REPO = resolve(SCRIPTS, "../../..");

/** Run a hook script as Kiro would: from the repo root, with the event on stdin. */
export function runHook(script, event, { env = {}, rawInput, args = [], cwd = REPO } = {}) {
  const input = rawInput !== undefined ? rawInput : JSON.stringify(event);
  const result = spawnSync(process.execPath, [join(SCRIPTS, script), ...args], {
    cwd,
    input,
    encoding: "utf8",
    env: { PATH: process.env.PATH, HOME: process.env.HOME, ...env },
    timeout: 30_000,
  });
  return { status: result.status, stderr: result.stderr, stdout: result.stdout };
}

export const shellEvent = (command, cwd = null) => ({
  session_id: "sess_test",
  hook_event_name: "PreToolUse",
  cwd: REPO,
  tool_name: "execute_bash",
  tool_input: { command, cwd },
});

// Secret-shaped values are built at run time so the repo itself never contains one.
export const fake = {
  gh: () => `ghp_${"Ab1".repeat(12)}`,
  npm: () => `npm_${"Zx9".repeat(12)}`,
  aws: () => `AKIA${"Q".repeat(16)}`,
  privateKey: () => `-----BEGIN OPENSSH ${"PRIVATE"} KEY-----`,
};
