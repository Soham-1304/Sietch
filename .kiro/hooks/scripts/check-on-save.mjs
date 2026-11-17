#!/usr/bin/env node
// Kiro PostFileSave hook for TypeScript files under base/ and apps/.
// Runs the package's typecheck and the tests related to the saved file, using the repo's own tools.
//
// Exit 0: checks passed (stdout goes into the agent's context).
// Exit 1: checks failed. stderr goes to the agent, which should fix the failure before moving on.
//
// The file path comes from the {{filePath}} argument, falling back to the hook event on stdin.
// Node and pnpm may not be on PATH in hook environments, so tools are run through process.execPath.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";

const root = process.cwd();

function savedFilePath() {
  const arg = process.argv[2];
  if (arg && !arg.includes("{{")) return arg;
  try {
    const event = JSON.parse(readFileSync(0, "utf8"));
    const input = event.tool_input ?? {};
    return String(event.file_path ?? event.filePath ?? input.path ?? input.file_path ?? "");
  } catch {
    return "";
  }
}

function findPackageDir(file) {
  let dir = dirname(file);
  while (dir.startsWith(root) && dir !== root) {
    if (existsSync(join(dir, "package.json"))) return dir;
    dir = dirname(dir);
  }
  return null;
}

function run(label, args, cwd) {
  const result = spawnSync(process.execPath, args, { cwd, encoding: "utf8", timeout: 110_000 });
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`.trim();
  return { label, ok: result.status === 0, output };
}

const raw = savedFilePath();
if (!raw) process.exit(0);
const file = isAbsolute(raw) ? raw : resolve(root, raw);
const rel = relative(root, file);

if (!/^(base|apps)\/.+\.tsx?$/.test(rel) || rel.includes("node_modules/") || rel.includes("/dist/")) {
  process.exit(0);
}

const pkgDir = findPackageDir(file);
if (!pkgDir) process.exit(0);

const tsc = join(root, "node_modules/typescript/bin/tsc");
const vitest = join(root, "node_modules/vitest/vitest.mjs");
const results = [];

if (existsSync(join(pkgDir, "tsconfig.json")) && existsSync(tsc)) {
  results.push(run(`typecheck ${relative(root, pkgDir)}`, [tsc, "--noEmit", "-p", "tsconfig.json"], pkgDir));
}
if (existsSync(vitest)) {
  results.push(run(`tests related to ${rel}`, [vitest, "related", file, "--run", "--passWithNoTests"], root));
}

const failed = results.filter((r) => !r.ok);
if (failed.length > 0) {
  const detail = failed.map((r) => `--- ${r.label}: FAILED ---\n${r.output.slice(-4000)}`).join("\n\n");
  process.stderr.write(
    `check-on-save found problems after saving ${rel}. Fix them before moving on.\n\n${detail}\n`,
  );
  process.exit(1);
}

process.stdout.write(`check-on-save: ${results.map((r) => r.label).join(", ")}: passed.\n`);
process.exit(0);
