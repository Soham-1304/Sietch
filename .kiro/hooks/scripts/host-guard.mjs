#!/usr/bin/env node
// Kiro Pre Tool Use hook for shell commands.
// Blocks commands that break .kiro/steering/security.md on the developer's machine.
//
// Contract (Kiro hooks v1): JSON event on stdin, with the command in tool_input.command.
// Exit 0 allows the command. Exit 2 blocks it, and stderr is returned to the agent.
// If the event can't be read, the command is allowed: this is a guard rail for development,
// not a security boundary. The sandbox is the security boundary.

import { readFileSync } from "node:fs";

/** @returns {string} the shell command from the hook event, or "" */
function readCommand() {
  let raw = "";
  try {
    raw = readFileSync(0, "utf8");
  } catch {
    return "";
  }
  try {
    const event = JSON.parse(raw);
    const input = event.tool_input ?? event.toolArgs ?? {};
    if (typeof input === "string") return input;
    return String(input.command ?? input.cmd ?? "");
  } catch {
    return "";
  }
}

const runsInsideDocker = (c) => /\bdocker\s+(run|exec|compose)\b/.test(c);

/** Each rule: id, test(command) => boolean, reason shown to the agent. */
const RULES = [
  {
    id: "no-local-publish",
    test: (c) => /\b(npm|pnpm|yarn)\s+(publish|unpublish)\b/.test(c) && !/--dry-run\b/.test(c),
    reason:
      "Packages are published only from GitHub Actions with trusted publishing and provenance (security.md section 7). Use --dry-run to check a package locally.",
  },
  {
    id: "no-unsafe-docker",
    test: (c) =>
      /\bdocker\s+(run|create)\b/.test(c) &&
      /(--privileged\b|--net(work)?[ =]host\b|(-v|--volume)[ =]\/:|\/var\/run\/docker\.sock|--cap-add[ =](ALL|SYS_ADMIN)\b)/.test(c),
    reason:
      "This container would get host-level access (privileged mode, host network, a root mount, or the Docker socket). Sandbox containers must follow security.md section 2.",
  },
  {
    id: "no-pipe-to-shell",
    test: (c) => /\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/.test(c),
    reason:
      "Piping a download straight into a shell runs unreviewed code on the host. Download the script, read it, then run it.",
  },
  {
    id: "no-malware-corpus-on-mac",
    test: (c) =>
      process.platform === "darwin" && /malicious-software-packages-dataset|malware[-_]?samples/i.test(c),
    reason:
      "Real malware samples never go on the Mac (security.md section 1). Use them only on the cloud VM, inside the sandbox.",
  },
  {
    id: "no-demo-packages-on-host",
    test: (c) =>
      !runsInsideDocker(c) &&
      (/\b(node|bun|deno|tsx)\s+(\S*\/)?demo\/\S+/.test(c) ||
        /\b(npm|pnpm|yarn)\s+(i|install|add|ci|rebuild|run|exec)\b.*(@sietch-demo\/|(^|\s|\/)demo\/)/.test(c) ||
        /\bnpx\s+.*@sietch-demo\//.test(c) ||
        /\bcd\s+\S*demo\/\S*\s*(&&|;)\s*(npm|pnpm|yarn|node|npx|bun)\b/.test(c)),
    reason:
      "Demo packages (including the worm lookalike) may only run inside Docker, never directly on the host (security.md sections 1 and 6).",
  },
];

const command = readCommand();
const hit = command ? RULES.find((rule) => rule.test(command)) : undefined;

if (hit) {
  process.stderr.write(`Blocked by host-guard [${hit.id}]: ${hit.reason}\n`);
  process.exit(2);
}
process.exit(0);
