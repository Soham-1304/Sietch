// Shared input and output helpers for Kiro command hooks.
//
// Kiro IDE 1.x sends the hook event as JSON on stdin, then closes it. Captured examples (Nov 17, 2026):
//   PreToolUse:   {"session_id","hook_event_name":"PreToolUse","cwd","tool_name":"execute_bash",
//                  "tool_input":{"command","description","cwd":null,"run_in_background","timeout"}}
//   PostFileSave: {"session_id","hook_event_name":"PostFileSave","cwd","file_path":"/abs/path"}

import { readFileSync } from "node:fs";

export const MAX_EVENT_BYTES = 1024 * 1024;
const MAX_MESSAGE_CHARS = 2000;

export class HookInputError extends Error {
  constructor(message) {
    super(message);
    this.name = "HookInputError";
  }
}

/** Read and parse the hook event. Throws HookInputError on anything unexpected. */
export function readEvent() {
  let raw;
  try {
    raw = readFileSync(0);
  } catch {
    throw new HookInputError("couldn't read the hook event from stdin");
  }
  if (raw.length === 0) throw new HookInputError("the hook event was empty");
  if (raw.length > MAX_EVENT_BYTES) throw new HookInputError("the hook event is too large");
  let event;
  try {
    event = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new HookInputError("the hook event isn't valid JSON");
  }
  if (event === null || typeof event !== "object" || Array.isArray(event)) {
    throw new HookInputError("the hook event isn't a JSON object");
  }
  return event;
}

/**
 * Make text safe to print to a terminal or pass back to the agent: control characters (including
 * ANSI escapes and carriage returns) become visible \xNN escapes, and the length is capped.
 */
export function safeText(text) {
  let clean = "";
  for (const ch of String(text)) {
    const code = ch.codePointAt(0);
    clean += isUnsafeChar(code) ? `\\u{${code.toString(16)}}` : ch;
    if (clean.length > MAX_MESSAGE_CHARS) return `${clean.slice(0, MAX_MESSAGE_CHARS)}…`;
  }
  return clean;
}

/**
 * Control characters (ANSI escapes, carriage return, backspace, ...) and Unicode line separators and
 * bidirectional overrides, which can rewrite or disguise what a terminal or chat shows.
 * Newline (0x0a) and tab (0x09) are kept.
 */
function isUnsafeChar(code) {
  return (
    (code < 0x20 && code !== 0x09 && code !== 0x0a) ||
    (code >= 0x7f && code <= 0x9f) ||
    code === 0x2028 ||
    code === 0x2029 ||
    (code >= 0x202a && code <= 0x202e) ||
    (code >= 0x2066 && code <= 0x2069)
  );
}
