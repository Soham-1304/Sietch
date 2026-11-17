#!/usr/bin/env node
// Kiro Prompt Submit hook.
// Stops a chat message from reaching the agent if it appears to contain a real secret.
//
// Exit 0 lets the message through. Exit 2 blocks it, and stderr is shown to the user.
// Known placeholder values (AWS "EXAMPLE" keys, <password>, ***) are ignored.

import { readFileSync } from "node:fs";

/** Collect every string in the hook event, plus the legacy USER_PROMPT variable. */
function readPromptText() {
  const parts = [process.env.USER_PROMPT ?? ""];
  let raw = "";
  try {
    raw = readFileSync(0, "utf8");
  } catch {
    // no stdin
  }
  try {
    const walk = (value) => {
      if (typeof value === "string") parts.push(value);
      else if (value && typeof value === "object") Object.values(value).forEach(walk);
    };
    walk(JSON.parse(raw));
  } catch {
    parts.push(raw);
  }
  return parts.join("\n");
}

const PATTERNS = [
  { name: "GitHub token", re: /\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{80,})\b/ },
  { name: "npm token", re: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { name: "AWS access key", re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { name: "private key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: "Slack token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: "OpenAI-style API key", re: /\bsk-(proj-)?[A-Za-z0-9_-]{32,}\b/ },
  { name: "database URL with a password", re: /\b(mongodb(\+srv)?|postgres(ql)?|mysql|redis):\/\/[^:\s/@]+:([^@\s]+)@/ },
];

/** Placeholders people paste on purpose. */
const isPlaceholder = (match) =>
  /EXAMPLE/.test(match) || /:\s*(<[^>]*>|\{[^}]*\}|\*+|password|PASSWORD|xxx+)@/.test(match);

const text = readPromptText();
for (const { name, re } of PATTERNS) {
  const m = text.match(re);
  if (m && !isPlaceholder(m[0])) {
    process.stderr.write(
      `Your message was not sent: it looks like it contains a real ${name}. ` +
        "Remove it and send again. Use dummy values, like the ones in .env.example. " +
        "If the secret was real and has been shared anywhere, rotate it.\n",
    );
    process.exit(2);
  }
}
process.exit(0);
