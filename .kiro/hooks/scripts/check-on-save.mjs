#!/usr/bin/env node
// Kiro PostFileSave hook for TypeScript files under base/ and apps/.
// Typechecks the saved file's package and runs the tests related to that file.
//
// Exit 0: checks passed, or the file is outside base/ and apps/ (not this hook's job).
// Exit 1: checks failed, or the hook couldn't run them. stderr goes to the agent.
// A PostFileSave hook can't block the save, so "couldn't check" is reported as a failure rather
// than passed silently.

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { HookInputError, readEvent, safeText } from "./lib/hook-io.mjs";

const root = process.cwd();
const TIMEOUT_MS = 110_000;

function fail(message) {
  process.stderr.write(`check-on-save: ${safeText(message)}\n`);
  process.exit(1);
}

const isInside = (child, parent) => {
  const rel = relative(parent, child);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
};

function savedFilePath() {
  let event;
  try {
    event = readEvent();
  } catch (error) {
    if (error instanceof HookInputError) fail(`${error.message}, so the saved file wasn't checked.`);
    throw error;
  }
  if (event.hook_event_name !== "PostFileSave")
    fail("expected a PostFileSave event, so nothing was checked.");
  if (typeof event.file_path !== "string" || event.file_path.length === 0)
    fail("the event has no file path, so nothing was checked.");
  return event.file_path;
}

function findPackageDir(file) {
  let dir = dirname(file);
  while (isInside(dir, root) && dir !== root) {
    if (existsSync(join(dir, "package.json"))) return dir;
    dir = dirname(dir);
  }
  return null;
}

function run(label, args, cwd) {
  const result = spawnSync(process.execPath, args, {
    cwd,
    encoding: "utf8",
    timeout: TIMEOUT_MS,
    maxBuffer: 16 * 1024 * 1024,
  });
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`.trim();
  if (result.error)
    return { label, ok: false, output: `couldn't run: ${result.error.code ?? result.error.message}` };
  if (result.signal)
    return {
      label,
      ok: false,
      output: `stopped by ${result.signal} (timeout is ${TIMEOUT_MS / 1000} s)\n${output}`,
    };
  return { label, ok: result.status === 0, output };
}

const raw = savedFilePath();
const file = isAbsolute(raw) ? resolve(raw) : resolve(root, raw);
if (!isInside(file, root)) fail("the saved file is outside the project, so it wasn't checked.");
const rel = relative(root, file).split(sep).join("/");

// Not this hook's job: other folders, dependencies, and build output.
if (!/^(base|apps)\/.+\.tsx?$/.test(rel) || rel.includes("/node_modules/") || rel.includes("/dist/"))
  process.exit(0);

const pkgDir = findPackageDir(file);
if (!pkgDir) fail(`${rel} isn't inside a workspace package (no package.json found), so it wasn't checked.`);

const tsc = join(root, "node_modules/typescript/bin/tsc");
const vitest = join(root, "node_modules/vitest/vitest.mjs");
if (!existsSync(tsc) || !existsSync(vitest))
  fail("TypeScript or Vitest isn't installed. Run `pnpm install`, then save the file again.");
if (!existsSync(join(pkgDir, "tsconfig.json")))
  fail(`${relative(root, pkgDir)} has no tsconfig.json, so it can't be typechecked.`);

const results = [
  run(`typecheck ${relative(root, pkgDir)}`, [tsc, "--noEmit", "-p", "tsconfig.json"], pkgDir),
  // `file` is absolute (it starts with "/"), so it can't be read as an option. Don't add "--":
  // vitest then ignores the file and exits 0 without running anything.
  run(`tests related to ${rel}`, [vitest, "related", "--run", "--passWithNoTests", file], root),
];
const related = results[1];
if (related.ok && /No changed files found/.test(related.output)) {
  fail(`vitest didn't receive ${rel}, so no tests ran. This is a bug in check-on-save.`);
}

const failed = results.filter((r) => !r.ok);
if (failed.length > 0) {
  const detail = failed.map((r) => `--- ${r.label}: FAILED ---\n${r.output.slice(-4000)}`).join("\n\n");
  fail(`found problems after saving ${rel}. Fix them before moving on.\n\n${detail}`);
}
process.stdout.write(`check-on-save: ${results.map((r) => r.label).join(", ")}: passed.\n`);
process.exit(0);
