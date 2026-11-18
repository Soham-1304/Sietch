#!/usr/bin/env node
// Kiro Prompt Submit hook. Stops a chat message that appears to contain a real secret.
//
// Exit 0: let the message through. Exit 2: block it, and stderr is shown.
// The message is never echoed back, only the type of secret found.
//
// Where the message text comes from: Kiro IDE 1.x sends a JSON event on stdin; older versions set
// USER_PROMPT. We scan every string in both, so a renamed field can't hide the text. If neither
// source has any text at all, the hook blocks (fail closed) and says how to turn it off.

import { readFileSync } from "node:fs";
import { MAX_EVENT_BYTES, safeText } from "./lib/hook-io.mjs";

const MAX_DEPTH = 20;

function collectText() {
  const parts = [];
  const fromEnv = process.env.USER_PROMPT;
  if (typeof fromEnv === "string" && fromEnv.length > 0) parts.push(fromEnv);

  let raw = null;
  try {
    raw = readFileSync(0);
  } catch {
    // No stdin. USER_PROMPT may still have the text.
  }
  let hasPromptField = false;
  if (raw && raw.length > 0) {
    const text = raw.subarray(0, MAX_EVENT_BYTES).toString("utf8");
    try {
      const walk = (value, depth, key) => {
        if (depth > MAX_DEPTH) return;
        if (typeof value === "string") {
          parts.push(value);
          if (key === "prompt" || key === "user_prompt") hasPromptField = true;
        } else if (Array.isArray(value)) for (const v of value) walk(v, depth + 1, key);
        else if (value && typeof value === "object")
          for (const [k, v] of Object.entries(value)) walk(v, depth + 1, k);
      };
      walk(JSON.parse(text), 0, "");
    } catch {
      // Not JSON: scan the raw text instead. This scans more, not less.
      parts.push(text);
      hasPromptField = true;
    }
  }
  return {
    text: parts.join("\n"),
    found: parts.length > 0,
    hasPromptField: hasPromptField || Boolean(fromEnv),
  };
}

// Linear-time patterns only (no nested quantifiers), safe on any input length.
const PATTERNS = [
  { name: "GitHub token", re: /\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{80,})/ },
  { name: "npm token", re: /\bnpm_[A-Za-z0-9]{36}/ },
  { name: "AWS access key", re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { name: "private key", re: /-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----/ },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}/ },
  { name: "Slack token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/ },
  { name: "API key (sk-...)", re: /\bsk-(proj-|ant-)?[A-Za-z0-9_-]{32,}/ },
  {
    name: "database URL with a password",
    re: /\b(mongodb(\+srv)?|postgres(ql)?|mysql|rediss?|amqps?):\/\/[^:\s/@]{1,256}:([^@\s]{1,512})@/,
  },
];

// Exact placeholder values from public documentation. Anything else that matches is treated as real.
const DOC_EXAMPLES = new Set(["AKIAIOSFODNN7EXAMPLE"]);
const PASSWORD_PLACEHOLDER =
  /^(<[^<>]{1,64}>|\{[^{}]{1,64}\}|\*+|x+|password|PASSWORD|pass|secret|\$\{?[A-Z_]{1,64}\}?)$/;

function isPlaceholder(name, match) {
  if (name === "AWS access key") return DOC_EXAMPLES.has(match[0]);
  if (name === "database URL with a password") return PASSWORD_PLACEHOLDER.test(match[match.length - 1]);
  return false;
}

const { text, found, hasPromptField } = collectText();
if (!found) {
  process.stderr.write(
    "secret-guard couldn't find your message in the hook event, so it blocked it to be safe. If this keeps happening, turn secret-guard off in the Kiro panel and report it.\n",
  );
  process.exit(2);
}
for (const { name, re } of PATTERNS) {
  const pattern = new RegExp(re.source, "g");
  for (const match of text.matchAll(pattern)) {
    if (!isPlaceholder(name, match)) {
      process.stderr.write(
        `Your message was not sent: it looks like it contains a real ${safeText(name)}. Remove it and send again, using dummy values like the ones in .env.example. If the secret was real and has been shared anywhere, rotate it.\n`,
      );
      process.exit(2);
    }
  }
}
if (!hasPromptField) {
  // The event had text, and all of it was scanned, but not under the field we expect. Say so, so a
  // format change is noticed. This doesn't block: every string was still checked.
  process.stdout.write(
    "secret-guard: note: the hook event had no 'prompt' field. All of its text was scanned anyway.\n",
  );
}
process.exit(0);
