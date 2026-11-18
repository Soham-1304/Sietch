// A small, conservative shell parser for Kiro guard hooks (bash and zsh syntax).
//
// It turns a command string into simple commands (words + redirects), so guards can reason about
// argv instead of matching regexes against raw text. It is deliberately strict:
//
// - Anything it can't parse with confidence throws ShellParseError. Guards treat that as BLOCK.
// - Values built at run time ($VAR, $(...), backticks, globs, brace expansion) are marked dynamic,
//   unless the variable's value is known for certain (see `resolveWord`).
// - Code that will run is collected for analysis: $(...), backticks, <(...), >(...), and the bodies
//   of unquoted heredocs (which expand $(...) when read).
//
// It never executes anything and never touches the file system.

export const MAX_SOURCE_LENGTH = 256 * 1024;

export class ShellParseError extends Error {
  constructor(message) {
    super(message);
    this.name = "ShellParseError";
  }
}

const fail = (message) => {
  throw new ShellParseError(message);
};

const isBlank = (c) => c === " " || c === "\t" || c === "\r";
const OP_START = new Set([";", "&", "|", "(", ")", "<", ">"]);
const NAME_START = /[A-Za-z_]/;
const NAME_CHAR = /[A-Za-z0-9_]/;
const SPECIAL_PARAM = /[0-9@*#?$!-]/;
const REDIRECT_RE = /^(\d*)(&>>|&>|>>|>&|>\||<<<|<<-|<<|<&|<>|>|<)/;
const OPERATOR_RE = /^(&&|\|\||\|&|;;&|;;|;&|\||&|;|\(|\))/;

/** Find the end of a $( ... ) or <( ... ) body. `start` is the index just after the opening "(". */
function readParenBody(src, start) {
  let depth = 1;
  let i = start;
  while (i < src.length) {
    const c = src[i];
    if (c === "\\") {
      i += 2;
      continue;
    }
    if (c === "'") {
      const end = src.indexOf("'", i + 1);
      if (end < 0) fail("unterminated single quote inside $(...)");
      i = end + 1;
      continue;
    }
    if (c === '"') {
      i = skipDoubleQuoted(src, i + 1);
      continue;
    }
    if (c === "`") {
      i = skipBacktick(src, i + 1);
      continue;
    }
    // Comments, heredocs, and case patterns can contain ")" that doesn't close the substitution.
    // We don't model them inside $(...), so refuse rather than guess where it ends.
    if (c === "#" && (i === start || /[\s;&|(]/.test(src[i - 1]))) fail("comment inside $(...)");
    if (c === "<" && src[i + 1] === "<" && src[i + 2] !== "<") fail("heredoc inside $(...)");
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) return { body: src.slice(start, i), end: i + 1 };
    }
    i++;
  }
  return fail("unterminated $(...) or <(...)");
}

/** Skip a double-quoted string. `start` is just after the opening quote. Returns the index after the closing quote. */
function skipDoubleQuoted(src, start) {
  let i = start;
  while (i < src.length) {
    const c = src[i];
    if (c === "\\") {
      i += 2;
      continue;
    }
    if (c === '"') return i + 1;
    if (c === "`") {
      i = skipBacktick(src, i + 1);
      continue;
    }
    if (c === "$" && src[i + 1] === "(") {
      i = readParenBody(src, i + 2).end;
      continue;
    }
    i++;
  }
  return fail("unterminated double quote");
}

/** Skip a backtick substitution. `start` is just after the opening backtick. */
function skipBacktick(src, start) {
  let i = start;
  while (i < src.length) {
    if (src[i] === "\\") {
      i += 2;
      continue;
    }
    if (src[i] === "`") return i + 1;
    i++;
  }
  return fail("unterminated backtick");
}

/** Read a backtick body and unescape it as the shell would. `start` is just after the opening backtick. */
function readBacktick(src, start) {
  const end = skipBacktick(src, start);
  const raw = src.slice(start, end - 1);
  return { body: raw.replace(/\\([`\\$])/g, "$1"), end };
}

/** Find the end of ${ ... }. `start` is just after "${". */
function readBraceParam(src, start) {
  let depth = 1;
  let i = start;
  while (i < src.length) {
    const c = src[i];
    if (c === "\\") {
      i += 2;
      continue;
    }
    if (c === "'") {
      const end = src.indexOf("'", i + 1);
      if (end < 0) fail("unterminated quote inside a parameter expansion");
      i = end + 1;
      continue;
    }
    if (c === '"') {
      i = skipDoubleQuoted(src, i + 1);
      continue;
    }
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return { body: src.slice(start, i), end: i + 1 };
    }
    i++;
  }
  return fail("unterminated parameter expansion");
}

/**
 * True if an arithmetic body looks like a command: a word followed by whitespace and another word,
 * as in "npm publish". Arithmetic always has an operator between operands ("a + b", "x*2").
 */
function looksLikeCommand(body) {
  return /(?:^|[\s;&|(])[A-Za-z_./~][\w./~@:=+-]*[ \t]+[A-Za-z_./~"'$\\]/.test(body);
}

const ANSI_C_SIMPLE = {
  a: "\x07",
  b: "\b",
  e: "\x1b",
  E: "\x1b",
  f: "\f",
  n: "\n",
  r: "\r",
  t: "\t",
  v: "\v",
};

/** Decode $'...' (ANSI-C quoting). `start` is just after "$'". */
function readAnsiC(src, start) {
  let out = "";
  let i = start;
  while (i < src.length) {
    const c = src[i];
    if (c === "'") return { text: out, end: i + 1 };
    if (c !== "\\") {
      out += c;
      i++;
      continue;
    }
    const d = src[i + 1];
    if (d === undefined) break;
    if (d in ANSI_C_SIMPLE) {
      out += ANSI_C_SIMPLE[d];
      i += 2;
    } else if (d === "x") {
      const m = /^[0-9A-Fa-f]{1,2}/.exec(src.slice(i + 2, i + 4));
      if (!m) fail("bad \\x escape in $'...'");
      out += String.fromCharCode(Number.parseInt(m[0], 16));
      i += 2 + m[0].length;
    } else if (d === "u" || d === "U") {
      const max = d === "u" ? 4 : 8;
      const m = new RegExp(`^[0-9A-Fa-f]{1,${max}}`).exec(src.slice(i + 2, i + 2 + max));
      if (!m) fail("bad \\u escape in $'...'");
      const code = Number.parseInt(m[0], 16);
      if (code > 0x10ffff) fail("bad \\U escape in $'...'");
      out += String.fromCodePoint(code);
      i += 2 + m[0].length;
    } else if (/[0-7]/.test(d)) {
      const m = /^[0-7]{1,3}/.exec(src.slice(i + 1, i + 4));
      out += String.fromCharCode(Number.parseInt(m[0], 8) & 0xff);
      i += 1 + m[0].length;
    } else if (d === "c") {
      const ch = src[i + 2];
      if (ch === undefined) fail("bad \\c escape in $'...'");
      out += String.fromCharCode(ch.charCodeAt(0) & 0x1f);
      i += 3;
    } else {
      // \\ \' \" \? and unknown escapes: bash keeps the character (and the backslash for unknown ones).
      out += d === "\\" || d === "'" || d === '"' || d === "?" ? d : `\\${d}`;
      i += 2;
    }
  }
  return fail("unterminated $'...'");
}

/**
 * Lexer state for one source string.
 * Word parts: { lit: string } | { var: string, quoted: boolean } | { dyn: true }
 */
class Lexer {
  constructor(src) {
    if (typeof src !== "string") fail("command is not a string");
    if (src.length > MAX_SOURCE_LENGTH) fail("command is too long to analyse");
    if (src.includes("\0")) fail("command contains a NUL byte");
    this.src = src;
    this.i = 0;
    this.tokens = [];
    this.subs = []; // code that runs: bodies of $(...), backticks, <(...), >(...)
    this.pendingHeredocs = [];
  }

  /** Handle "$" at this.i. Appends parts to the word. `inDouble` disables $'...'. */
  dollar(word, inDouble) {
    const { src } = this;
    const next = src[this.i + 1];
    if (next === "(" && src[this.i + 2] === "(") {
      // $((...)) is arithmetic, but "$(" + "(cmd)" (a substitution containing a subshell) is spelled
      // the same way. bash 3.2 and zsh treat `$((npm publish))` as a math error, but parsing of
      // this case has varied across shell versions. Found by a property test. So a body that looks
      // like a command (two words side by side) is also analysed as commands.
      const { body, end } = readParenBody(src, this.i + 2);
      if (!body.endsWith(")")) fail("unterminated $((...))");
      if (looksLikeCommand(body)) this.subs.push(body);
      word.parts.push({ dyn: true });
      this.i = end;
      return;
    }
    if (next === "(") {
      const { body, end } = readParenBody(src, this.i + 2);
      this.subs.push(body);
      word.parts.push({ dyn: true });
      this.i = end;
      return;
    }
    if (next === "{") {
      const { body, end } = readBraceParam(src, this.i + 2);
      if (body.includes("$(") || body.includes("`"))
        fail("command substitution inside a parameter expansion");
      if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(body)) word.parts.push({ var: body, quoted: inDouble });
      else word.parts.push({ dyn: true });
      this.i = end;
      return;
    }
    if (!inDouble && next === "'") {
      const { text, end } = readAnsiC(src, this.i + 2);
      word.parts.push({ lit: text });
      word.quoted = true;
      this.i = end;
      return;
    }
    if (!inDouble && next === '"') {
      // $"..." is locale translation; treat it as a normal double-quoted string.
      this.i += 1;
      return;
    }
    if (next !== undefined && NAME_START.test(next)) {
      let j = this.i + 1;
      while (j < src.length && NAME_CHAR.test(src[j])) j++;
      word.parts.push({ var: src.slice(this.i + 1, j), quoted: inDouble });
      this.i = j;
      return;
    }
    if (next !== undefined && SPECIAL_PARAM.test(next)) {
      word.parts.push({ dyn: true });
      this.i += 2;
      return;
    }
    // zsh $=var and $~var change splitting and globbing of the next parameter.
    if (next === "=" || next === "~") {
      word.parts.push({ dyn: true });
      this.i += 2;
      return;
    }
    word.parts.push({ lit: "$" });
    this.i += 1;
  }

  readDoubleQuoted(word) {
    const { src } = this;
    word.quoted = true;
    this.i += 1; // opening quote
    while (this.i < src.length) {
      const c = src[this.i];
      if (c === '"') {
        this.i += 1;
        return;
      }
      if (c === "\\") {
        const d = src[this.i + 1];
        if (d === undefined) break;
        if (d === "\n") {
          this.i += 2;
          continue;
        }
        word.parts.push({ lit: '$`"\\'.includes(d) ? d : `\\${d}` });
        this.i += 2;
        continue;
      }
      if (c === "$") {
        this.dollar(word, true);
        continue;
      }
      if (c === "`") {
        const { body, end } = readBacktick(src, this.i + 1);
        this.subs.push(body);
        word.parts.push({ dyn: true });
        this.i = end;
        continue;
      }
      word.parts.push({ lit: c });
      this.i += 1;
    }
    fail("unterminated double quote");
  }

  readWord() {
    const { src } = this;
    const start = this.i;
    const word = { parts: [], quoted: false, glob: false, raw: "" };
    let unquoted = "";
    while (this.i < src.length) {
      const c = src[this.i];
      if (isBlank(c) || c === "\n") break;
      if ((c === "<" || c === ">") && src[this.i + 1] === "(") {
        const { body, end } = readParenBody(src, this.i + 2);
        this.subs.push(body);
        word.parts.push({ dyn: true });
        this.i = end;
        continue;
      }
      if (OP_START.has(c)) break;
      if (c === "\\") {
        const d = src[this.i + 1];
        if (d === undefined) fail("command ends with a backslash");
        if (d !== "\n") {
          word.parts.push({ lit: d });
          word.quoted = true;
        }
        this.i += 2;
        continue;
      }
      if (c === "'") {
        const end = src.indexOf("'", this.i + 1);
        if (end < 0) fail("unterminated single quote");
        word.parts.push({ lit: src.slice(this.i + 1, end) });
        word.quoted = true;
        this.i = end + 1;
        continue;
      }
      if (c === '"') {
        this.readDoubleQuoted(word);
        continue;
      }
      if (c === "$") {
        this.dollar(word, false);
        continue;
      }
      if (c === "`") {
        const { body, end } = readBacktick(src, this.i + 1);
        this.subs.push(body);
        word.parts.push({ dyn: true });
        this.i = end;
        continue;
      }
      unquoted += c;
      word.parts.push({ lit: c });
      this.i += 1;
    }
    // Brace expansion ({a,b} or {1..3}) turns one word into several, so its result is dynamic.
    if (/\{[^{}]*(,|\.\.)[^{}]*\}/.test(unquoted)) word.parts.push({ dyn: true });
    // Globs expand to file names. A lone "[" is the test command, not a glob.
    word.glob = /[*?]/.test(unquoted) || /\[[^\]]*\]/.test(unquoted);
    word.unquotedStartsWithEquals = unquoted.startsWith("=") && src[start] === "=";
    word.raw = src.slice(start, this.i);
    return word;
  }

  readHeredocBodies() {
    const { src } = this;
    for (const redirect of this.pendingHeredocs) {
      const delim = redirect.delimiter;
      let body = "";
      for (;;) {
        if (this.i >= src.length) fail(`heredoc "${delim}" is not terminated`);
        let end = src.indexOf("\n", this.i);
        if (end < 0) end = src.length;
        const line = src.slice(this.i, end);
        this.i = Math.min(end + 1, src.length);
        const compare = redirect.op === "<<-" ? line.replace(/^\t+/, "") : line;
        if (compare === delim) break;
        body += `${line}\n`;
        if (end === src.length) fail(`heredoc "${delim}" is not terminated`);
      }
      redirect.heredoc = body;
      if (!redirect.delimiterQuoted) this.collectHeredocSubs(body);
    }
    this.pendingHeredocs = [];
  }

  /** An unquoted heredoc expands $(...) and backticks, so that code runs. */
  collectHeredocSubs(body) {
    let i = 0;
    while (i < body.length) {
      const c = body[i];
      if (c === "\\") {
        i += 2;
        continue;
      }
      if (c === "$" && body[i + 1] === "(") {
        const { body: sub, end } = readParenBody(body, i + 2);
        // $((...)) is arithmetic unless it looks like a command (see Lexer.dollar).
        if (!sub.startsWith("(") || looksLikeCommand(sub)) this.subs.push(sub);
        i = end;
        continue;
      }
      if (c === "$" && body[i + 1] === "{") {
        const { body: inner, end } = readBraceParam(body, i + 2);
        if (inner.includes("$(") || inner.includes("`"))
          fail("command substitution inside a parameter expansion in a heredoc");
        i = end;
        continue;
      }
      if (c === "`") {
        const { body: sub, end } = readBacktick(body, i + 1);
        this.subs.push(sub);
        i = end;
        continue;
      }
      i++;
    }
  }

  run() {
    const { src } = this;
    while (this.i < src.length) {
      const c = src[this.i];
      if (isBlank(c)) {
        this.i++;
        continue;
      }
      if (c === "\\" && src[this.i + 1] === "\n") {
        this.i += 2;
        continue;
      }
      if (c === "\n") {
        this.tokens.push({ type: "op", op: "\n" });
        this.i++;
        if (this.pendingHeredocs.length > 0) this.readHeredocBodies();
        continue;
      }
      if (c === "#") {
        while (this.i < src.length && src[this.i] !== "\n") this.i++;
        continue;
      }
      const rest = src.slice(this.i, this.i + 8);
      const isProcSub = (c === "<" || c === ">") && src[this.i + 1] === "(";
      const redirect = isProcSub ? null : REDIRECT_RE.exec(rest);
      if (redirect && (redirect[1] === "" || /[<>&]/.test(rest[redirect[1].length] ?? ""))) {
        const op = redirect[2];
        this.i += redirect[0].length;
        while (this.i < src.length && isBlank(src[this.i])) this.i++;
        if (op === ">&" || op === "<&") {
          // fd duplication such as 2>&1 or >&- : the target is a short word.
          const m = /^(\d+|-)/.exec(src.slice(this.i));
          if (m) {
            this.tokens.push({
              type: "redirect",
              redirect: { op, fd: redirect[1], target: null, dup: m[0] },
            });
            this.i += m[0].length;
            continue;
          }
        }
        if (this.i >= src.length || src[this.i] === "\n" || OP_START.has(src[this.i])) {
          fail(`redirect "${op}" has no target`);
        }
        const target = this.readWord();
        const entry = { op, fd: redirect[1], target, heredoc: null };
        if (op === "<<" || op === "<<-") {
          entry.delimiter = target.parts.map((p) => ("lit" in p ? p.lit : "")).join("");
          entry.delimiterQuoted = target.quoted;
          if (target.parts.some((p) => !("lit" in p))) fail("heredoc delimiter is built at run time");
          this.pendingHeredocs.push(entry);
        }
        this.tokens.push({ type: "redirect", redirect: entry });
        continue;
      }
      const op = isProcSub ? null : OPERATOR_RE.exec(rest);
      if (op) {
        this.tokens.push({ type: "op", op: op[1] });
        this.i += op[1].length;
        continue;
      }
      this.tokens.push({ type: "word", word: this.readWord() });
    }
    if (this.pendingHeredocs.length > 0) fail("heredoc started but its body is missing");
    return this.tokens;
  }
}

// Words that are syntax when they appear in command position. Each opens or closes a block, or is a
// prefix that doesn't change what runs next.
const OPENS_BLOCK = new Set(["if", "then", "else", "elif", "do", "while", "until", "coproc", "repeat"]);
const CLOSES_BLOCK = new Set(["fi", "done", "esac", "end"]);
const PREFIX_WORDS = new Set(["!", "time", "function", "[[", "]]"]);
const LIST_HEADERS = new Set(["for", "select", "foreach"]);

const literalText = (word) =>
  word.parts.every((p) => "lit" in p) ? word.parts.map((p) => p.lit).join("") : null;

/**
 * Parse a command string.
 * Returns { commands, subs, loopVars } where each command is:
 *   { words, redirects, pipeFrom, pipeTo, opBefore, depth }
 * - opBefore: the operator before this command ("start", ";", "\n", "&&", "||", "|", "&", "(", ")" ...)
 * - depth: nesting inside ( ), { }, and control structures. Guards use it to decide whether an
 *   assignment or `cd` certainly runs.
 * - loopVars: variable names set by `for NAME in ...` loops (their values are unknown).
 */
export function parseShell(src) {
  const lexer = new Lexer(src);
  const tokens = lexer.run();
  const commands = [];
  const loopVars = [];
  let current = null;
  let opBefore = "start";
  let depth = 0;
  let pipeNext = false;

  const start = () => {
    current = { words: [], redirects: [], pipeFrom: pipeNext, pipeTo: false, opBefore, depth };
    pipeNext = false;
  };
  const finish = (op) => {
    if (current && (current.words.length > 0 || current.redirects.length > 0)) commands.push(current);
    current = null;
    opBefore = op;
  };

  for (let t = 0; t < tokens.length; t++) {
    const token = tokens[t];
    if (token.type === "op") {
      const op = token.op;
      if (op === "|" || op === "|&") {
        if (!current || current.words.length === 0) fail("pipe with no command before it");
        current.pipeTo = true;
        finish(op);
        pipeNext = true;
        continue;
      }
      if (pipeNext) fail(`pipe followed by "${op === "\n" ? "newline" : op}"`);
      finish(op);
      if (op === "(") depth++;
      if (op === ")") depth = Math.max(0, depth - 1);
      continue;
    }
    if (token.type === "redirect") {
      if (!current) start();
      current.redirects.push(token.redirect);
      continue;
    }
    const word = token.word;
    const text = word.quoted ? null : literalText(word);

    // Grouping braces are treated as separators wherever they appear as a whole word. That is
    // stricter than the shell (where "echo {" prints a brace), but it never hides a command:
    // `f() { npm publish; }` and `function f { ... }` both expose their bodies.
    if (text === "{" || text === "}") {
      finish(text);
      depth = text === "{" ? depth + 1 : Math.max(0, depth - 1);
      continue;
    }
    if (!current) start();
    if (current.words.length === 0 && text !== null) {
      if (OPENS_BLOCK.has(text)) {
        depth++;
        current.depth = depth;
        continue;
      }
      if (CLOSES_BLOCK.has(text)) {
        depth = Math.max(0, depth - 1);
        current.depth = depth;
        continue;
      }
      if (PREFIX_WORDS.has(text)) continue;
      if (LIST_HEADERS.has(text)) {
        // `for NAME in a b c` : the rest of this simple command is a word list, not a command.
        // Command substitutions in the list were already collected by the lexer.
        const next = tokens[t + 1];
        if (next?.type === "word") {
          const name = literalText(next.word);
          if (name !== null) loopVars.push(name);
        }
        depth++;
        while (t + 1 < tokens.length && tokens[t + 1].type === "word") t++;
        current = null;
        continue;
      }
      if (text === "case") {
        // `case WORD in` : skip up to and including "in". Patterns before ")" become harmless words.
        depth++;
        while (t + 1 < tokens.length && tokens[t + 1].type === "word") {
          t++;
          if (literalText(tokens[t].word) === "in") break;
        }
        current = null;
        continue;
      }
    }
    current.words.push(word);
  }
  if (pipeNext) fail("pipe at the end of the command");
  finish("end");
  return { commands, subs: lexer.subs, loopVars };
}

/**
 * Resolve a word to text, using only values that are certainly known.
 * Returns { text, dynamic }. If dynamic is true, `text` is not reliable and callers must not
 * make an allow decision based on it.
 */
export function resolveWord(word, vars) {
  let text = "";
  let dynamic = false;
  for (const part of word.parts) {
    if ("lit" in part) text += part.lit;
    else if ("var" in part) {
      if (!vars.has(part.var)) {
        dynamic = true;
        continue;
      }
      const value = vars.get(part.var);
      // An unquoted variable is split into several words and globbed. We only accept values
      // where that doesn't change anything.
      if (!part.quoted && /[\s*?[\]{}]/.test(value)) dynamic = true;
      text += value;
    } else dynamic = true;
  }
  if (word.glob) dynamic = true;
  return { text, dynamic };
}

/** True if the word is a shell assignment such as NAME=value or NAME+=value. */
export function isAssignmentWord(word) {
  return /^[A-Za-z_][A-Za-z0-9_]*\+?=/.test(word.raw);
}
