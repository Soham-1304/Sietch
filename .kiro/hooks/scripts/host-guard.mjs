#!/usr/bin/env node
// Kiro Pre Tool Use hook for shell commands. Fails closed.
//
// Exit 0: allow. Exit 2: block, and stderr is returned to the agent.
// Every unexpected condition (bad event, missing command, parse failure, internal error) blocks.
// The policy itself is in lib/host-policy.mjs. Known gaps are listed in .kiro/hooks/README.md.

import { existsSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { HookInputError, readEvent, safeText } from "./lib/hook-io.mjs";
import { analyse, Blocked, makeContext } from "./lib/host-policy.mjs";

function deny(rule, reason) {
  process.stderr.write(`Blocked by host-guard [${rule}]: ${safeText(reason)}\n`);
  process.exit(2);
}

function main() {
  const repoRoot = process.cwd();
  if (!existsSync(join(repoRoot, ".kiro", "hooks"))) {
    deny(
      "bad-environment",
      "host-guard isn't running from the project root, so it can't apply the project's rules.",
    );
  }

  let event;
  try {
    event = readEvent();
  } catch (error) {
    if (error instanceof HookInputError)
      deny("bad-event", `${error.message}, so host-guard can't check the command.`);
    throw error;
  }
  if (event.hook_event_name !== "PreToolUse") deny("bad-event", "host-guard expected a PreToolUse event.");
  const input = event.tool_input;
  if (input === null || typeof input !== "object" || typeof input.command !== "string") {
    deny("bad-event", "the tool call has no command string, so host-guard can't check it.");
  }

  let cwd = repoRoot;
  if (input.cwd !== undefined && input.cwd !== null) {
    if (typeof input.cwd !== "string" || input.cwd.length === 0)
      deny("bad-event", "the tool call's working directory isn't a path.");
    cwd = isAbsolute(input.cwd) ? resolve(input.cwd) : resolve(repoRoot, input.cwd);
  }

  const ctx = makeContext({ repoRoot, cwd, home: process.env.HOME, platform: process.platform });
  try {
    analyse(input.command, ctx);
  } catch (error) {
    if (error instanceof Blocked) deny(error.rule, error.message);
    deny(
      "internal-error",
      `host-guard hit an internal error (${error instanceof Error ? error.name : "unknown"}), so it's blocking to be safe.`,
    );
  }
  process.exit(0);
}

try {
  main();
} catch {
  deny("internal-error", "host-guard failed unexpectedly, so it's blocking to be safe.");
}
