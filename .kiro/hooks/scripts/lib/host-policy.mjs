// host-guard policy: decides whether a shell command the agent wants to run is allowed on the host.
//
// Model: ordinary commands are allowed. A small set of dangerous classes is blocked, and anything the
// guard cannot analyse with confidence is blocked too (fail closed). The classes:
//
//   publish     npm/pnpm/yarn/bun publish, unpublish, deprecate, login (security.md section 7)
//   docker      containers with host-level access (security.md section 2)
//   pipe-shell  downloaded or piped code run by a shell or interpreter
//   malware     real malware corpora on the Mac (security.md section 1)
//   demo        running demo packages outside Docker (security.md sections 1 and 6)
//
// This is a development guard rail, not the security boundary. The sandbox is the boundary.
// Known gaps (code that hides a command inside a file the guard can't read, or inside another
// language) are listed in .kiro/hooks/README.md.

import { existsSync, readFileSync, statSync } from "node:fs";
import { basename, isAbsolute, relative, resolve, sep } from "node:path";
import { isAssignmentWord, parseShell, resolveWord, ShellParseError } from "./shell.mjs";

export const MAX_DEPTH = 8;
const MAX_SCRIPT_BYTES = 512 * 1024;

export class Blocked extends Error {
  constructor(rule, reason) {
    super(reason);
    this.name = "Blocked";
    this.rule = rule;
  }
}

const block = (rule, reason) => {
  throw new Blocked(rule, reason);
};

// npm's own abbreviations, generated from npm 11's lib/utils/cmd-list.js (deref). npm accepts any
// unique prefix, so "npm pu" is "npm publish".
const NPM_REGISTRY_WRITE = new Set([
  // publish
  "pu",
  "pub",
  "publ",
  "publi",
  "publis",
  "publish",
  // unpublish
  "unp",
  "unpu",
  "unpub",
  "unpubl",
  "unpubli",
  "unpublis",
  "unpublish",
  // deprecate
  "dep",
  "depr",
  "depre",
  "deprec",
  "depreca",
  "deprecat",
  "deprecate",
  // login and adduser put a registry token on this machine
  "logi",
  "login",
  "add-",
  "add-u",
  "add-us",
  "add-use",
  "add-user",
  "addu",
  "addus",
  "adduse",
  "adduser",
]);
const NPM_INSTALL_FAMILY = new Set([
  // install
  "add",
  "i",
  "in",
  "ins",
  "inst",
  "insta",
  "instal",
  "install",
  "isnt",
  "isnta",
  "isntal",
  "isntall",
  // ci
  "ci",
  "clean-install",
  "ic",
  "install-cl",
  "install-cle",
  "install-clea",
  "install-clean",
  "isntall-",
  "isntall-c",
  "isntall-cl",
  "isntall-cle",
  "isntall-clea",
  "isntall-clean",
  // install-test and install-ci-test
  "it",
  "install-t",
  "install-te",
  "install-tes",
  "install-test",
  "cit",
  "si",
  "sit",
  "install-ci",
  "install-ci-",
  "install-ci-t",
  "install-ci-te",
  "install-ci-tes",
  "install-ci-test",
  "clean-install-",
  "clean-install-t",
  "clean-install-te",
  "clean-install-tes",
  "clean-install-test",
  // rebuild, link, update, pack, init/create (all run package scripts or fetch and run packages)
  "rb",
  "reb",
  "rebu",
  "rebui",
  "rebuil",
  "rebuild",
  "lin",
  "link",
  "ln",
  "u",
  "ud",
  "udp",
  "udpa",
  "udpat",
  "udpate",
  "up",
  "upd",
  "upda",
  "updat",
  "update",
  "upg",
  "upgr",
  "upgra",
  "upgrad",
  "upgrade",
  "pa",
  "pac",
  "pack",
  "cr",
  "cre",
  "crea",
  "creat",
  "create",
  "ini",
  "init",
  "inn",
  "inni",
  "innit",
  // pnpm, yarn, and bun spellings
  "dlx",
  "x",
  "exec",
  "import",
  "fetch",
  "patch",
  "remove",
  "rm",
]);
const NPM_EXEC = new Set(["exe", "exec", "x"]);

const PACKAGE_MANAGERS = new Set(["npm", "pnpm", "yarn", "bun", "cnpm"]);
const RUNNERS = new Set(["npx", "pnpx", "bunx"]);
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "mksh", "fish", "ash", "busybox"]);
const INTERPRETERS = new Set([
  "node",
  "nodejs",
  "deno",
  "tsx",
  "ts-node",
  "python",
  "python3",
  "perl",
  "ruby",
  "php",
  "osascript",
]);
const CONTAINER_CLIS = new Set(["docker", "podman", "nerdctl"]);
// Wrappers that run the rest of their arguments as a command: name -> options that take a value.
const WRAPPERS = new Map([
  [
    "sudo",
    new Set([
      "-u",
      "-g",
      "-h",
      "-p",
      "-C",
      "-D",
      "-r",
      "-t",
      "-U",
      "-T",
      "--user",
      "--group",
      "--host",
      "--prompt",
      "--chdir",
      "--role",
      "--type",
      "--other-user",
      "--command-timeout",
    ]),
  ],
  ["doas", new Set(["-u", "-C"])],
  ["nohup", new Set()],
  ["time", new Set(["-o", "-f"])],
  ["builtin", new Set()],
  ["noglob", new Set()],
  ["nocorrect", new Set()],
  ["-", new Set()],
  ["nice", new Set(["-n", "--adjustment"])],
  ["ionice", new Set(["-c", "-n", "-p"])],
  ["chronic", new Set()],
  ["unbuffer", new Set()],
  ["caffeinate", new Set(["-t", "-w"])],
  ["arch", new Set()],
  ["stdbuf", new Set(["-i", "-o", "-e"])],
  ["exec", new Set(["-a"])],
  ["command", new Set()],
  ["setsid", new Set()],
]);
const XARGS_VALUE_OPTS = new Set([
  "-I",
  "-i",
  "-n",
  "-L",
  "-l",
  "-P",
  "-s",
  "-d",
  "-E",
  "-e",
  "-a",
  "--max-args",
  "--max-lines",
  "--max-procs",
  "--max-chars",
  "--delimiter",
  "--eof",
  "--arg-file",
  "--replace",
]);
const TIMEOUT_VALUE_OPTS = new Set(["-s", "-k", "--signal", "--kill-after"]);
const ENV_VALUE_OPTS = new Set(["-u", "--unset", "-C", "--chdir", "-P"]);

/** Analysis context. */
export function makeContext({ repoRoot, cwd, home, platform }) {
  if (!isAbsolute(repoRoot)) throw new Error("repoRoot must be absolute");
  return {
    repoRoot,
    demoRoot: resolve(repoRoot, "demo"),
    home: typeof home === "string" && isAbsolute(home) ? home : null,
    platform,
    cwd: typeof cwd === "string" && isAbsolute(cwd) ? cwd : repoRoot,
  };
}

const isInside = (child, parent) => {
  const rel = relative(parent, child);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
};

const lowerBase = (text) => basename(text).toLowerCase();

/** Resolve a literal path against the current directory, expanding a leading "~". Returns null if unknown. */
function resolvePath(text, ctx, cwd) {
  let p = text;
  if (p === "~" || p.startsWith("~/")) {
    if (!ctx.home) return null;
    p = ctx.home + p.slice(1);
  } else if (p.startsWith("~")) return null; // ~user
  if (isAbsolute(p)) return resolve(p);
  if (cwd === null) return null;
  return resolve(cwd, p);
}

/** Initial variables whose values are known with certainty. */
function initialVars(ctx, cwd) {
  const vars = new Map();
  if (ctx.home) vars.set("HOME", ctx.home);
  if (cwd) vars.set("PWD", cwd);
  return vars;
}

/**
 * Analyse a command string. Throws Blocked to block. Returns normally to allow.
 * `state` carries the virtual working directory and known variables between commands.
 */
export function analyse(src, ctx, depth = 0, inherited = null) {
  if (depth > MAX_DEPTH)
    block("too-deep", "the command nests shells, eval, or substitutions too deeply to analyse");

  if (ctx.platform === "darwin" && /malicious-software-packages-dataset|malware[-_]?samples/i.test(src)) {
    block(
      "malware",
      "real malware samples never go on the Mac (security.md section 1). Use them only on the cloud VM, inside the sandbox.",
    );
  }

  let parsed;
  try {
    parsed = parseShell(src);
  } catch (error) {
    if (error instanceof ShellParseError) {
      block(
        "unparsable",
        `host-guard couldn't parse this command safely (${error.message}). Rewrite it in simpler steps, or put file content in a file with the file tools instead of the shell.`,
      );
    }
    throw error;
  }

  const state = {
    cwd: inherited?.cwd !== undefined ? inherited.cwd : ctx.cwd,
    vars: inherited?.vars ?? initialVars(ctx, inherited?.cwd ?? ctx.cwd),
    // This source string and every one enclosing it. Used to check that nothing running alongside
    // a script can change it between host-guard reading it and the shell running it.
    levels: [...(inherited?.levels ?? []), parsed],
  };

  // Variables assigned more than once, or set by a loop, have values we can't know.
  const assignCounts = new Map();
  for (const name of parsed.loopVars) assignCounts.set(name, 2);
  for (const cmd of parsed.commands) {
    for (const word of leadingAssignmentsAndExports(cmd.words)) {
      const name = word.raw.slice(0, word.raw.search(/\+?=/));
      assignCounts.set(name, (assignCounts.get(name) ?? 0) + 1);
    }
    for (const name of unsetNames(cmd.words)) assignCounts.set(name, 2);
  }
  for (const [name, count] of assignCounts) if (count > 1) state.vars.delete(name);

  // Code in substitutions runs too. Analyse it with the same starting state. Substitutions are part
  // of this level, so a script run inside one is checked against this level's other commands.
  for (const sub of parsed.subs)
    analyse(sub, ctx, depth + 1, { cwd: state.cwd, vars: new Map(state.vars), levels: state.levels });

  for (const cmd of parsed.commands) analyseCommand(cmd, ctx, depth, state, assignCounts);
}

function leadingAssignmentsAndExports(words) {
  const out = [];
  let k = 0;
  if (
    words[0] &&
    ["export", "declare", "typeset", "local", "readonly"].includes(resolveWord(words[0], new Map()).text)
  ) {
    k = 1;
    while (words[k] && resolveWord(words[k], new Map()).text.startsWith("-")) k++;
    for (; k < words.length; k++) if (isAssignmentWord(words[k])) out.push(words[k]);
    return out;
  }
  for (; k < words.length && isAssignmentWord(words[k]); k++) out.push(words[k]);
  return out;
}

function unsetNames(words) {
  if (!words[0] || resolveWord(words[0], new Map()).text !== "unset") return [];
  return words
    .slice(1)
    .map((w) => resolveWord(w, new Map()).text)
    .filter((t) => /^[A-Za-z_]\w*$/.test(t));
}

/** True when this command certainly runs, in order, in the current shell (not a subshell or branch). */
const runsUnconditionally = (cmd) =>
  cmd.depth === 0 && !cmd.pipeFrom && !cmd.pipeTo && ["start", ";", "\n"].includes(cmd.opBefore);

function analyseCommand(cmd, ctx, depth, state, assignCounts) {
  const { vars } = state;
  let words = cmd.words;

  // Standalone assignments (and export NAME=value) update known variables when they certainly run.
  const assignments = leadingAssignmentsAndExports(words);
  const isPureAssignment =
    words.length > 0 &&
    (assignments.length === words.length ||
      (["export", "declare", "typeset", "local", "readonly"].includes(resolveWord(words[0], vars).text) &&
        words.slice(1).every((w) => isAssignmentWord(w) || resolveWord(w, vars).text.startsWith("-"))));
  if (isPureAssignment) {
    for (const word of assignments) {
      const eq = word.raw.search(/\+?=/);
      const name = word.raw.slice(0, eq);
      const append = word.raw[eq] === "+";
      const valueWord = { ...word, parts: dropNamePrefix(word.parts, eq + (append ? 2 : 1)), glob: false };
      const value = resolveWord(valueWord, vars);
      if (!value.dynamic && !append && runsUnconditionally(cmd) && (assignCounts.get(name) ?? 0) === 1) {
        vars.set(name, value.text);
      } else vars.delete(name);
    }
    return;
  }

  // Prefix assignments (NAME=value cmd) only affect that command's environment.
  while (words.length > 0 && isAssignmentWord(words[0])) words = words.slice(1);
  if (words.length === 0) return;

  checkInvocation(words, cmd, ctx, depth, state, { extraDynamicArgs: false });

  // `cd` changes where later commands run. Track it only when it certainly happens.
  const name = resolveWord(words[0], vars);
  if (!name.dynamic && (name.text === "cd" || name.text === "pushd")) {
    const target = words.find((w, k) => k > 0 && !resolveWord(w, vars).text.startsWith("-"));
    let next = null;
    if (!target) next = ctx.home;
    else {
      const t = resolveWord(target, vars);
      if (!t.dynamic && t.text !== "-") next = resolvePath(t.text, ctx, state.cwd);
    }
    if (runsUnconditionally(cmd)) state.cwd = next;
    else if (next !== state.cwd) state.cwd = null; // might or might not have changed
    if (state.cwd) vars.set("PWD", state.cwd);
    else vars.delete("PWD");
  }
}

/** Remove the first `count` characters (the "NAME=" prefix) from a word's parts. */
function dropNamePrefix(parts, count) {
  const out = [];
  let skip = count;
  for (const part of parts) {
    if (skip > 0 && "lit" in part) {
      if (part.lit.length <= skip) {
        skip -= part.lit.length;
        continue;
      }
      out.push({ lit: part.lit.slice(skip) });
      skip = 0;
      continue;
    }
    out.push(part);
  }
  return out;
}

/**
 * Check one invocation. `words` starts at the command name. Wrappers are unwrapped in a loop.
 * opts.extraDynamicArgs: xargs (or similar) will append unknown arguments.
 * opts.cwdOverride: a directory set by env -C or similar.
 */
function checkInvocation(initialWords, cmd, ctx, depth, state, opts) {
  const { vars } = state;
  let words = initialWords;
  let cwd = opts.cwdOverride !== undefined ? opts.cwdOverride : state.cwd;
  let extraDynamicArgs = opts.extraDynamicArgs;

  for (let hop = 0; hop < 16; hop++) {
    if (words.length === 0) return;
    const head = resolveWord(words[0], vars);
    if (head.dynamic)
      block(
        "dynamic-command",
        "the command name is built at run time ($VAR, $(...), or a glob), so host-guard can't tell what runs. Write the command name out literally.",
      );
    let text = head.text;
    // zsh "=cmd" expands to the full path of cmd.
    if (words[0].unquotedStartsWithEquals) text = text.slice(1);
    const name = lowerBase(text);
    const args = words.slice(1);
    const lit = (w) => resolveWord(w, vars);

    // --- wrappers ---------------------------------------------------------------------------
    if (WRAPPERS.has(name)) {
      if (name === "command" && args.some((w) => /^-[a-zA-Z]*[vV]/.test(lit(w).text))) return; // lookup only
      const valueOpts = WRAPPERS.get(name);
      let k = 0;
      while (k < args.length) {
        const a = lit(args[k]);
        if (a.dynamic) block("dynamic-args", `the options to "${name}" are built at run time`);
        if (a.text === "--") {
          k++;
          break;
        }
        if (!a.text.startsWith("-") || a.text === "-") break;
        if (valueOpts.has(a.text)) k += 2;
        else k++;
      }
      if (name === "sudo" && args.slice(0, k).some((w) => /^-[a-zA-Z]*[si]/.test(lit(w).text))) {
        if (k >= args.length) return; // interactive root shell, no command given
      }
      words = args.slice(k);
      continue;
    }
    if (name === "env") {
      let k = 0;
      while (k < args.length) {
        const a = lit(args[k]);
        if (a.dynamic) block("dynamic-args", 'the arguments to "env" are built at run time');
        if (
          a.text === "-S" ||
          a.text === "--split-string" ||
          a.text.startsWith("-S") ||
          a.text.startsWith("--split-string=")
        ) {
          const inline = a.text.startsWith("--split-string=")
            ? a.text.slice(15)
            : a.text.length > 2 && a.text.startsWith("-S")
              ? a.text.slice(2)
              : null;
          const codeWord = inline === null ? args[k + 1] : null;
          const code = inline ?? (codeWord ? lit(codeWord) : { dynamic: true, text: "" });
          if (typeof code === "object" && code.dynamic)
            block("dynamic-args", 'the string given to "env -S" is built at run time');
          const rest = args.slice(k + (inline === null ? 2 : 1)).map((w) => lit(w));
          if (rest.some((r) => r.dynamic))
            block("dynamic-args", 'the arguments after "env -S" are built at run time');
          analyse(
            [typeof code === "string" ? code : code.text, ...rest.map((r) => r.text)].join(" "),
            ctx,
            depth + 1,
            { cwd, vars: new Map(vars), levels: state.levels },
          );
          return;
        }
        if (a.text === "-C" || a.text === "--chdir") {
          const dir = args[k + 1] ? lit(args[k + 1]) : { dynamic: true, text: "" };
          cwd = dir.dynamic ? null : resolvePath(dir.text, ctx, cwd);
          k += 2;
          continue;
        }
        if (ENV_VALUE_OPTS.has(a.text)) {
          k += 2;
          continue;
        }
        if (a.text === "--") {
          k++;
          break;
        }
        if (a.text.startsWith("-") || isAssignmentWord(args[k])) {
          k++;
          continue;
        }
        break;
      }
      words = args.slice(k);
      continue;
    }
    if (name === "timeout" || name === "gtimeout") {
      let k = 0;
      while (k < args.length) {
        const a = lit(args[k]);
        if (a.dynamic) block("dynamic-args", `the options to "${name}" are built at run time`);
        if (TIMEOUT_VALUE_OPTS.has(a.text)) k += 2;
        else if (a.text.startsWith("-")) k++;
        else break;
      }
      words = args.slice(k + 1); // skip DURATION
      continue;
    }
    if (name === "xargs") {
      let k = 0;
      while (k < args.length) {
        const a = lit(args[k]);
        if (a.dynamic) block("dynamic-args", 'the options to "xargs" are built at run time');
        if (XARGS_VALUE_OPTS.has(a.text)) k += 2;
        else if (a.text.startsWith("-")) k++;
        else break;
      }
      words = args.slice(k);
      extraDynamicArgs = true;
      if (words.length === 0) return; // xargs runs echo by default
      continue;
    }
    if (name === "script") {
      // macOS: script [-q] [file [command ...]]. Linux: script [-c command] [file].
      let k = 0;
      while (k < args.length) {
        const a = lit(args[k]);
        if (a.dynamic) block("dynamic-args", 'the arguments to "script" are built at run time');
        if (a.text === "-c" || a.text === "--command") {
          const code = args[k + 1] ? lit(args[k + 1]) : null;
          if (!code || code.dynamic) block("dynamic-eval", '"script -c" runs a string built at run time');
          analyse(code.text, ctx, depth + 1, { cwd, vars: new Map(vars), levels: state.levels });
          return;
        }
        if (!a.text.startsWith("-")) break;
        k += [
          "-F",
          "-t",
          "-T",
          "-B",
          "-I",
          "-O",
          "-E",
          "--timing",
          "--log-in",
          "--log-out",
          "--echo",
        ].includes(a.text)
          ? 2
          : 1;
      }
      words = args.slice(k + 1); // skip the typescript file
      continue;
    }
    if (name === "find") {
      // find ... -exec CMD ... ; (or +). Each -exec, -execdir, -ok, -okdir runs a command.
      for (let k = 0; k < args.length; k++) {
        const a = lit(args[k]);
        if (["-exec", "-execdir", "-ok", "-okdir"].includes(a.text)) {
          let end = k + 1;
          while (end < args.length && ![";", "+"].includes(lit(args[end]).text)) end++;
          checkInvocation(args.slice(k + 1, end), cmd, ctx, depth + 1, state, {
            extraDynamicArgs: true,
            cwdOverride: cwd,
          });
          k = end;
        }
      }
      return;
    }
    if (name === "watch") {
      const parts = args.map((w) => lit(w));
      if (parts.some((p) => p.dynamic))
        block("dynamic-args", 'the command given to "watch" is built at run time');
      const firstCmd = parts.findIndex(
        (p, k) =>
          !p.text.startsWith("-") && !(k > 0 && ["-n", "--interval", "-d"].includes(parts[k - 1].text)),
      );
      if (firstCmd >= 0)
        analyse(
          parts
            .slice(firstCmd)
            .map((p) => p.text)
            .join(" "),
          ctx,
          depth + 1,
          { cwd, vars: new Map(vars), levels: state.levels },
        );
      return;
    }
    if (name === "eval") {
      const parts = args.map((w) => lit(w));
      if (parts.some((p) => p.dynamic))
        block(
          "dynamic-eval",
          '"eval" runs a string built at run time, so host-guard can\'t see what it runs',
        );
      analyse(parts.map((p) => p.text).join(" "), ctx, depth + 1, {
        cwd,
        vars: new Map(vars),
        levels: state.levels,
      });
      return;
    }
    if (name === "alias") {
      for (const w of args) {
        const a = lit(w);
        if (a.dynamic) block("dynamic-args", "an alias value is built at run time");
        const eq = a.text.indexOf("=");
        if (eq > 0)
          analyse(a.text.slice(eq + 1), ctx, depth + 1, { cwd, vars: new Map(vars), levels: state.levels });
      }
      return;
    }
    if (name === "source" || name === ".") {
      if (args.length === 0) return;
      inspectScript(args[0], "source", ctx, depth, state, cwd, cmd);
      return;
    }

    // --- shells -----------------------------------------------------------------------------
    if (SHELLS.has(name)) {
      checkShell(name, args, cmd, ctx, depth, state, cwd);
      return;
    }

    // --- node running a package manager's own entry point ----------------------------------
    if (name === "node" || name === "nodejs") {
      const scriptIdx = args.findIndex((w) => !lit(w).text.startsWith("-"));
      if (scriptIdx >= 0) {
        const script = lit(args[scriptIdx]);
        const base = script.dynamic ? "" : lowerBase(script.text);
        const pm = /^npm-cli\.c?js$/.test(base)
          ? "npm"
          : /^pnpm\.c?js$/.test(base)
            ? "pnpm"
            : /^yarn\.c?js$/.test(base)
              ? "yarn"
              : null;
        if (pm) {
          words = [
            { parts: [{ lit: pm }], quoted: false, glob: false, raw: pm },
            ...args.slice(scriptIdx + 1),
          ];
          continue;
        }
      }
    }

    // --- interpreters -----------------------------------------------------------------------
    if (INTERPRETERS.has(name) || (name === "bun" && isBunScriptRun(args, lit))) {
      checkInterpreter(name, args, cmd, ctx, cwd, lit);
      return;
    }

    // --- package managers and runners -------------------------------------------------------
    if (name === "corepack") {
      const first = args.findIndex((w) => !lit(w).text.startsWith("-"));
      if (first < 0) return;
      const sub = lit(args[first]);
      if (sub.dynamic) block("dynamic-args", 'the command given to "corepack" is built at run time');
      if (PACKAGE_MANAGERS.has(lowerBase(sub.text.split("@")[0]))) {
        words = args.slice(first);
        continue;
      }
      return; // corepack enable, prepare, use, ...
    }
    if (RUNNERS.has(name)) {
      const inner = checkRunner(name, args, ctx, depth, state, cwd, lit, extraDynamicArgs);
      if (inner === null) return;
      words = inner;
      continue;
    }
    if (PACKAGE_MANAGERS.has(name)) {
      const result = checkPackageManager(name, args, ctx, depth, state, cwd, lit, extraDynamicArgs);
      if (result === null) return;
      words = result.words;
      cwd = result.cwd;
      continue;
    }

    // --- containers -------------------------------------------------------------------------
    if (CONTAINER_CLIS.has(name)) {
      checkContainer(name, args, ctx, cwd, lit);
      return;
    }

    // --- direct execution of a script path --------------------------------------------------
    if (text.includes("/")) {
      const p = resolvePath(text, ctx, cwd);
      if (p !== null && isInside(p, ctx.demoRoot))
        block(
          "demo",
          "demo packages may only run inside Docker, never directly on the host (security.md sections 1 and 6).",
        );
      if (p !== null && /\.(sh|bash|zsh)$/.test(p))
        inspectScript(words[0], "run", ctx, depth, state, cwd, cmd);
    }
    return;
  }
  block("too-deep", "too many nested wrapper commands to analyse");
}

// --- shells ---------------------------------------------------------------------------------

function checkShell(name, args, cmd, ctx, depth, state, cwd) {
  const lit = (w) => resolveWord(w, state.vars);
  let k = 0;
  let codeFollows = false;
  while (k < args.length) {
    const a = lit(args[k]);
    if (a.dynamic) block("dynamic-args", `the arguments to "${name}" are built at run time`);
    if (a.text === "--") {
      k++;
      break;
    }
    if (/^-[a-zA-Z]*c[a-zA-Z]*$/.test(a.text)) codeFollows = true;
    if (a.text === "-o" || a.text === "+o" || a.text === "-O" || a.text === "+O") {
      k += 2;
      continue;
    }
    if (!/^[-+]/.test(a.text) || a.text === "-") break;
    k++;
  }
  if (codeFollows) {
    const code = args[k] ? lit(args[k]) : null;
    if (!code) block("unparsable", `"${name} -c" has no command string`);
    if (code.dynamic)
      block(
        "dynamic-eval",
        `"${name} -c" runs a string built at run time, so host-guard can't see what it runs`,
      );
    analyse(code.text, ctx, depth + 1, { cwd, vars: new Map(state.vars), levels: state.levels });
    return;
  }
  if (k < args.length && lit(args[k]).text !== "-") {
    inspectScript(args[k], "run", ctx, depth, state, cwd, cmd);
    return;
  }
  readsCodeFromStdin(name, cmd, ctx, depth, state, cwd);
}

/** A shell or interpreter that reads its program from stdin. */
function readsCodeFromStdin(name, cmd, ctx, depth, state, cwd) {
  const input = [...cmd.redirects]
    .reverse()
    .find((r) => ["<<", "<<-", "<<<", "<"].includes(r.op) && r.fd === "");
  if (input?.op === "<<" || input?.op === "<<-") {
    if (SHELLS.has(name))
      analyse(input.heredoc, ctx, depth + 1, { cwd, vars: new Map(state.vars), levels: state.levels });
    else scanForeignCode(input.heredoc, name);
    return;
  }
  if (input?.op === "<<<") {
    const t = resolveWord(input.target, state.vars);
    if (t.dynamic) block("dynamic-eval", `"${name}" reads a here-string built at run time`);
    if (SHELLS.has(name))
      analyse(t.text, ctx, depth + 1, { cwd, vars: new Map(state.vars), levels: state.levels });
    else scanForeignCode(t.text, name);
    return;
  }
  if (input?.op === "<") {
    if (SHELLS.has(name)) inspectScript(input.target, "run", ctx, depth, state, cwd, cmd);
    else
      block(
        "pipe-shell",
        `"${name}" would run a program read from a file that host-guard doesn't inspect. Pass the file as an argument instead.`,
      );
    return;
  }
  if (cmd.pipeFrom) {
    block(
      "pipe-shell",
      `piping into "${name}" runs whatever the previous command prints, which host-guard can't inspect. Save it to a file, read it, then run the file.`,
    );
  }
  // Otherwise: an interactive shell or REPL with no program. Nothing to check.
}

/** Read a script that a shell will run, and analyse its contents. */
function inspectScript(word, how, ctx, depth, state, cwd, self) {
  const w = resolveWord(word, state.vars);
  if (w.dynamic)
    block(
      "dynamic-args",
      `the script path given to ${how} is built at run time, so host-guard can't inspect it`,
    );
  const p = resolvePath(w.text, ctx, cwd);
  if (p === null)
    block("dynamic-args", `host-guard can't tell where "${w.text}" is (the working directory is unknown)`);
  if (isInside(p, ctx.demoRoot))
    block(
      "demo",
      "demo scripts may only run inside Docker, never directly on the host (security.md sections 1 and 6).",
    );
  // Scripts the agent can write: the repo and temporary directories. Others (for example
  // ~/.nvm/nvm.sh) are installed tools, which we don't parse.
  const inspectable = [ctx.repoRoot, "/tmp", "/private/tmp", "/var/folders", "/private/var/folders"].some(
    (d) => isInside(p, d),
  );
  if (!inspectable) return;
  // We read the script now, but it runs later. If anything else in the same command could write
  // files, it could swap the script's content in between. Require the script to run on its own.
  const writer = state.levels
    .map((level) => findPossibleWriter(level, state.vars, self))
    .find((x) => x !== null);
  if (writer) {
    block(
      "script-race",
      `this command runs "${w.text}" and also ${writer}, which could change the script after host-guard reads it. Run the script in its own command.`,
    );
  }
  if (!existsSync(p))
    block(
      "unreadable-script",
      `host-guard can't inspect "${w.text}": the file doesn't exist yet. Create it first, then run it in a separate command.`,
    );
  let content;
  try {
    const st = statSync(p);
    if (!st.isFile()) block("unreadable-script", `"${w.text}" is not a regular file`);
    if (st.size > MAX_SCRIPT_BYTES)
      block("unreadable-script", `"${w.text}" is too large for host-guard to inspect`);
    content = readFileSync(p, "utf8");
  } catch (error) {
    if (error instanceof Blocked) throw error;
    block("unreadable-script", `host-guard can't read "${w.text}"`);
  }
  analyse(content, ctx, depth + 1, { cwd, vars: initialVars(ctx, cwd), levels: state.levels });
}

// Commands that can't write files. Anything else next to a script run counts as a possible writer.
const READ_ONLY_COMMANDS = new Set([
  "cd",
  "pushd",
  "popd",
  "echo",
  "printf",
  "true",
  "false",
  ":",
  "test",
  "[",
  "pwd",
  "ls",
  "set",
  "export",
  "unset",
  "umask",
  "ulimit",
  "nvm",
  "source",
  ".",
  "sh",
  "bash",
  "zsh",
  "dash",
  "ksh",
]);
const WRITE_REDIRECTS = new Set([">", ">>", ">|", "&>", "&>>", "<>"]);
const HARMLESS_TARGETS = new Set(["/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"]);

/** Describe something in `level` that could write files, or return null. */
function findPossibleWriter(level, vars, self) {
  if (level.subs.length > 0) return "runs command substitutions";
  for (const cmd of level.commands) {
    if (cmd === self) {
      // The command that runs the script can't change it first, except through a write redirect.
      if (
        cmd.redirects.some(
          (r) =>
            WRITE_REDIRECTS.has(r.op) &&
            !(r.target && HARMLESS_TARGETS.has(resolveWord(r.target, vars).text)),
        )
      )
        return "redirects output to a file";
      continue;
    }
    for (const r of cmd.redirects) {
      if (!WRITE_REDIRECTS.has(r.op)) continue;
      const t = r.target ? resolveWord(r.target, vars) : null;
      if (!t || t.dynamic || !HARMLESS_TARGETS.has(t.text)) return "redirects output to a file";
    }
    const words = cmd.words.filter((w, k) => !(k === 0 && isAssignmentWord(w)));
    const first = words.find((w) => !isAssignmentWord(w));
    if (!first) continue; // only assignments
    const name = resolveWord(first, vars);
    if (name.dynamic || !READ_ONLY_COMMANDS.has(lowerBase(name.text)))
      return `runs "${name.dynamic ? "a dynamic command" : name.text}"`;
  }
  return null;
}

// --- interpreters ---------------------------------------------------------------------------

const BUN_SUBCOMMANDS = new Set([
  "add",
  "a",
  "install",
  "i",
  "remove",
  "rm",
  "update",
  "publish",
  "x",
  "run",
  "test",
  "build",
  "init",
  "create",
  "c",
  "pm",
  "link",
  "unlink",
  "outdated",
  "audit",
  "patch",
  "upgrade",
  "repl",
  "exec",
  "info",
]);
function isBunScriptRun(args, lit) {
  const first = args.find((w) => !lit(w).text.startsWith("-"));
  if (!first) return false;
  const t = lit(first);
  if (t.dynamic) return false; // the package-manager path blocks dynamic arguments
  // "bun run <file>" and "bun test <file>" run code directly; "bun run <script>" runs package.json.
  // Treat both "run" and "test" as script runs so file arguments get the demo check.
  return t.text === "run" || t.text === "test" || !BUN_SUBCOMMANDS.has(t.text);
}

const CODE_FLAGS = new Set(["-e", "--eval", "-p", "--print", "-c", "-r", "--require", "--import", "-E"]);
// Subcommands that come before the program: "deno run x.ts", "bun run x.ts".
const PROGRAM_SUBCOMMANDS = {
  deno: new Set(["run", "test", "bench", "serve", "task", "compile", "install", "repl"]),
  bun: new Set(["run", "test"]),
};
const EVAL_SUBCOMMANDS = { deno: new Set(["eval"]), bun: new Set() };

function checkInterpreter(name, args, cmd, ctx, cwd, lit) {
  const isDemo = (t) => {
    if (t.text.includes("@sietch-demo/")) return true;
    const p = resolvePath(t.text.replace(/^(file:|link:)/, ""), ctx, cwd);
    return p !== null && isInside(p, ctx.demoRoot);
  };
  if (cwd === null)
    block(
      "unknown-cwd",
      `"${name}" would run in a directory host-guard can't determine. Use a literal path with cd.`,
    );
  if (isInside(cwd, ctx.demoRoot))
    block(
      "demo",
      "demo packages may only run inside Docker, never directly on the host (security.md sections 1 and 6).",
    );

  let hasProgram = false;
  let sawSubcommand = false;
  for (let k = 0; k < args.length; k++) {
    const a = lit(args[k]);
    if (!a.dynamic && !sawSubcommand && !a.text.startsWith("-") && PROGRAM_SUBCOMMANDS[name]?.has(a.text)) {
      sawSubcommand = true;
      continue;
    }
    if (!a.dynamic && !sawSubcommand && !a.text.startsWith("-") && EVAL_SUBCOMMANDS[name]?.has(a.text)) {
      const code = args[k + 1] ? lit(args[k + 1]) : null;
      if (!code || code.dynamic) block("dynamic-eval", `"${name} ${a.text}" runs code built at run time`);
      scanForeignCode(code.text, name);
      return;
    }
    if (a.dynamic) {
      // A dynamic argument could be a demo path or a program.
      block(
        "dynamic-args",
        `the arguments to "${name}" are built at run time, so host-guard can't tell what it runs`,
      );
    }
    if (CODE_FLAGS.has(a.text)) {
      const code = args[k + 1] ? lit(args[k + 1]) : null;
      if (code && !code.dynamic) {
        if (["-r", "--require", "--import"].includes(a.text)) {
          if (isDemo(code))
            block(
              "demo",
              "demo packages may only run inside Docker, never directly on the host (security.md sections 1 and 6).",
            );
        } else {
          scanForeignCode(code.text, name);
          hasProgram = true;
        }
      }
      k++;
      continue;
    }
    if (a.text.startsWith("-")) continue;
    if (isDemo(a))
      block(
        "demo",
        "demo packages may only run inside Docker, never directly on the host (security.md sections 1 and 6).",
      );
    hasProgram = true;
    break; // the rest are the program's own arguments
  }
  if (!hasProgram) readsCodeFromStdinForeign(name, cmd);
}

function readsCodeFromStdinForeign(name, cmd) {
  const input = [...cmd.redirects]
    .reverse()
    .find((r) => ["<<", "<<-", "<<<", "<"].includes(r.op) && r.fd === "");
  if (input?.op === "<<" || input?.op === "<<-") return scanForeignCode(input.heredoc, name);
  if (input?.op === "<<<") return scanForeignCode(input.target.raw, name);
  if (input?.op === "<")
    block(
      "pipe-shell",
      `"${name}" would run a program from a redirected file. Pass the file as an argument instead.`,
    );
  if (cmd.pipeFrom)
    block(
      "pipe-shell",
      `piping into "${name}" runs whatever the previous command prints, which host-guard can't inspect.`,
    );
}

/**
 * Code in another language (Python, JavaScript, ...) can't be parsed here. Scan its text for the
 * dangerous patterns instead. This over-blocks on purpose: mentioning the command is enough.
 */
function scanForeignCode(code, name) {
  if (/\b(npm|pnpm|yarn|bun)\b[\s\S]{0,40}\b(publish|unpublish|deprecate|login|adduser)\b/i.test(code)) {
    block(
      "publish",
      `the ${name} code contains a package publish or login command. Packages are published only from GitHub Actions (security.md section 7).`,
    );
  }
  if (/--privileged|docker\.sock|--(net|network|pid|ipc|uts|userns)[ =]host/.test(code)) {
    block("docker", `the ${name} code contains Docker host-access options (security.md section 2).`);
  }
  if (/@sietch-demo\/|(^|[\s"'`/])demo\//.test(code)) {
    block(
      "demo",
      `the ${name} code references demo packages. They may only run inside Docker (security.md sections 1 and 6).`,
    );
  }
}

// --- package managers -----------------------------------------------------------------------

const DIR_OPTS = new Set(["--prefix", "-C", "--dir", "--cwd", "--workspace-root"]);

/**
 * Returns null when the invocation is fully checked, or { words, cwd } when it runs another
 * command that must be checked next (npm exec, pnpm dlx, yarn dlx, bun x).
 */
function checkPackageManager(name, args, ctx, depth, state, cwd, lit, extraDynamicArgs) {
  let effectiveCwd = cwd;
  const texts = [];
  let afterDashDash = false;
  for (let k = 0; k < args.length; k++) {
    const a = lit(args[k]);
    if (!afterDashDash && a.dynamic) {
      block(
        "dynamic-args",
        `the arguments to "${name}" are built at run time, so host-guard can't tell which ${name} command runs. Write them out literally.`,
      );
    }
    if (a.text === "--") afterDashDash = true;
    texts.push(a.dynamic ? null : a.text);
    if (!afterDashDash) {
      const eq = a.text.indexOf("=");
      const flag = eq > 0 ? a.text.slice(0, eq) : a.text;
      if (DIR_OPTS.has(flag)) {
        const value = eq > 0 ? a.text.slice(eq + 1) : args[k + 1] ? lit(args[k + 1]) : null;
        const v = typeof value === "string" ? { text: value, dynamic: false } : value;
        if (!v || v.dynamic) block("dynamic-args", `the ${flag} directory is built at run time`);
        effectiveCwd = resolvePath(v.text, ctx, effectiveCwd);
      }
    }
  }
  if (extraDynamicArgs) block("dynamic-args", `"xargs ${name}" adds arguments that host-guard can't see`);
  if (effectiveCwd === null)
    block(
      "unknown-cwd",
      `"${name}" would run in a directory host-guard can't determine. Use a literal path.`,
    );
  if (isInside(effectiveCwd, ctx.demoRoot)) {
    block(
      "demo",
      `running ${name} inside demo/ would run the demo package's scripts on the host. Demo packages may only run inside Docker (security.md sections 1 and 6).`,
    );
  }

  const beforeDashDash = [];
  for (const t of texts) {
    if (t === "--") break;
    beforeDashDash.push(t);
  }
  const positional = beforeDashDash.filter((t) => !t.startsWith("-")).map((t) => t.toLowerCase());
  const has = (flag) => beforeDashDash.some((t) => t === flag || t === `${flag}=true`);
  const dryRun = has("--dry-run") && !beforeDashDash.includes("--dry-run=false");

  // Registry writes. Any positional word counts, so flags with values ("npm --registry x publish")
  // can't hide the command. "npm install pub" is a false positive we accept.
  const write = positional.find((t) => NPM_REGISTRY_WRITE.has(t));
  if (write) {
    const isPublishLike = !["logi", "login"].includes(write) && !write.startsWith("add");
    if (!(dryRun && isPublishLike)) {
      block(
        "publish",
        `"${name} ${write}" changes the npm registry or stores a registry token on this machine. Packages are published only from GitHub Actions with trusted publishing and provenance (security.md section 7).${isPublishLike ? " Use --dry-run to check a package locally." : ""}`,
      );
    }
  }

  // Demo packages must not be installed, linked, packed, or executed on the host.
  const referencesDemo = beforeDashDash.some((t) => {
    if (t.includes("@sietch-demo/")) return true;
    const p = resolvePath(
      t.replace(/^(file:|link:|portal:)/, "").replace(/^--[a-z-]+=/, ""),
      ctx,
      effectiveCwd,
    );
    return t.length > 0 && !t.startsWith("-") && p !== null && isInside(p, ctx.demoRoot);
  });
  if (referencesDemo && positional.some((t) => NPM_INSTALL_FAMILY.has(t) || t === "run" || t === "test")) {
    block(
      "demo",
      "this would install or run a demo package on the host. Demo packages may only run inside Docker (security.md sections 1 and 6).",
    );
  }

  // Commands that run another program: check that program next.
  const subIdx = beforeDashDash.findIndex((t) => !t.startsWith("-"));
  const sub = subIdx >= 0 ? beforeDashDash[subIdx].toLowerCase() : null;
  const runsProgram =
    (name === "npm" && NPM_EXEC.has(sub)) ||
    (name === "pnpm" && (sub === "exec" || sub === "dlx")) ||
    (name === "yarn" && (sub === "dlx" || sub === "exec")) ||
    (name === "bun" && (sub === "x" || sub === "exec"));
  if (runsProgram) {
    const rest = args.slice(subIdx + 1);
    const inner = checkRunner(`${name} ${sub}`, rest, ctx, depth, state, effectiveCwd, lit, false);
    if (inner === null) return null;
    return { words: inner, cwd: effectiveCwd };
  }
  return null;
}

const RUNNER_VALUE_OPTS = new Set([
  "-p",
  "--package",
  "--registry",
  "--cache",
  "--userconfig",
  "--workspace",
  "-w",
  "--filter",
  "--shell-mode",
]);

/** npx-style runners. Returns the inner command's words, or null if nothing more to check. */
function checkRunner(name, args, ctx, depth, state, cwd, lit, extraDynamicArgs) {
  if (extraDynamicArgs) block("dynamic-args", `"xargs ${name}" adds arguments that host-guard can't see`);
  let k = 0;
  while (k < args.length) {
    const a = lit(args[k]);
    if (a.dynamic) block("dynamic-args", `the arguments to "${name}" are built at run time`);
    const eq = a.text.indexOf("=");
    const flag = eq > 0 ? a.text.slice(0, eq) : a.text;
    if (a.text === "--") {
      k++;
      break;
    }
    if (flag === "-c" || flag === "--call") {
      const code =
        eq > 0 ? { text: a.text.slice(eq + 1), dynamic: false } : args[k + 1] ? lit(args[k + 1]) : null;
      if (!code || code.dynamic) block("dynamic-eval", `"${name} -c" runs a string built at run time`);
      analyse(code.text, ctx, depth + 1, { cwd, vars: new Map(state.vars), levels: state.levels });
      return null;
    }
    if (flag === "-p" || flag === "--package") {
      const value = eq > 0 ? a.text.slice(eq + 1) : args[k + 1] ? lit(args[k + 1]).text : "";
      if (value.includes("@sietch-demo/") || isDemoSpec(value, ctx, cwd)) {
        block(
          "demo",
          "this would run a demo package on the host. Demo packages may only run inside Docker (security.md sections 1 and 6).",
        );
      }
    }
    if (!a.text.startsWith("-")) break;
    k += RUNNER_VALUE_OPTS.has(flag) && eq < 0 ? 2 : 1;
  }
  const inner = args.slice(k);
  if (inner.length === 0) return null;
  const first = lit(inner[0]);
  if (first.dynamic) block("dynamic-command", `the command run by "${name}" is built at run time`);
  if (first.text.includes("@sietch-demo/") || isDemoSpec(first.text, ctx, cwd)) {
    block(
      "demo",
      "this would run a demo package on the host. Demo packages may only run inside Docker (security.md sections 1 and 6).",
    );
  }
  // Strip a version from a package spec: "npm@11" -> "npm", "@scope/pkg@1" -> "@scope/pkg".
  const spec = first.text;
  const at = spec.lastIndexOf("@");
  const bare = at > 0 ? spec.slice(0, at) : spec;
  const binName = bare.startsWith("@") ? (bare.split("/")[1] ?? bare) : bare;
  return [{ parts: [{ lit: binName }], quoted: false, glob: false, raw: binName }, ...inner.slice(1)];
}

function isDemoSpec(text, ctx, cwd) {
  const p = resolvePath(text.replace(/^(file:|link:)/, ""), ctx, cwd);
  return (
    (text.startsWith(".") || text.startsWith("/") || text.startsWith("~") || text.startsWith("file:")) &&
    p !== null &&
    isInside(p, ctx.demoRoot)
  );
}

// --- containers -----------------------------------------------------------------------------

const DOCKER_GLOBAL_VALUE_OPTS = new Set([
  "-H",
  "--host",
  "-c",
  "--context",
  "--config",
  "-l",
  "--log-level",
  "--tlscacert",
  "--tlscert",
  "--tlskey",
]);
const COMPOSE_VALUE_OPTS = new Set([
  "-f",
  "--file",
  "-p",
  "--project-name",
  "--profile",
  "--env-file",
  "--project-directory",
  "--ansi",
  "--progress",
  "--parallel",
]);
const DANGEROUS_CAPS = new Set([
  "ALL",
  "SYS_ADMIN",
  "SYS_PTRACE",
  "SYS_MODULE",
  "SYS_RAWIO",
  "SYS_BOOT",
  "SYSLOG",
  "DAC_READ_SEARCH",
  "DAC_OVERRIDE",
  "NET_ADMIN",
  "NET_RAW",
  "BPF",
  "PERFMON",
  "MKNOD",
  "SETFCAP",
  "MAC_ADMIN",
  "MAC_OVERRIDE",
  "LINUX_IMMUTABLE",
  "SYS_CHROOT",
  "SYS_TIME",
]);
const HOST_NAMESPACE_FLAGS = new Set([
  "--pid",
  "--ipc",
  "--uts",
  "--userns",
  "--cgroupns",
  "--network",
  "--net",
]);
const SECRET_ENV_NAME =
  /(TOKEN|SECRET|PASSW|PASSWD|PRIVATE|CREDENTIAL|AUTH|API_?KEY|ACCESS_?KEY|NPM|GITHUB|GH_|AWS|GOOGLE|GCP|GCLOUD|AZURE|MONGO|DATABASE_URL|REDIS_URL|SSH)/i;
const SYSTEM_DIRS = [
  "/var/run",
  "/run",
  "/proc",
  "/sys",
  "/dev",
  "/etc",
  "/private/etc",
  "/private/var/run",
  "/var/lib/docker",
  "/boot",
  "/root",
  "/System",
  "/Library",
  "/usr",
  "/bin",
  "/sbin",
  "/lib",
  "/opt",
  "/private/var/db",
];
const HOME_SECRETS = [
  ".ssh",
  ".aws",
  ".npmrc",
  ".config",
  ".gnupg",
  ".docker",
  ".kube",
  ".netrc",
  ".git-credentials",
  ".gcloud",
  ".azure",
  ".pypirc",
  ".yarnrc",
  ".yarnrc.yml",
  "Library/Keychains",
  ".nvm",
  ".kiro",
];

function dangerousMountSource(source, ctx, cwd) {
  if (source.endsWith(".sock") || source.includes("docker.sock")) return "the Docker or containerd socket";
  // A named volume has no slash and doesn't start with "." or "~".
  if (!source.includes("/") && !source.startsWith(".") && !source.startsWith("~")) return null;
  const p = resolvePath(source, ctx, cwd);
  if (p === null) return "a path host-guard can't resolve";
  if (p === "/") return "the host root directory";
  for (const d of SYSTEM_DIRS) if (isInside(p, d)) return `the system directory ${d}`;
  if (ctx.home) {
    if (isInside(ctx.home, p)) return "your home directory or a directory containing it";
    for (const s of HOME_SECRETS)
      if (isInside(p, resolve(ctx.home, s))) return `~/${s}, which holds credentials`;
  }
  if (isInside(ctx.repoRoot, p) && p !== ctx.repoRoot) return "a directory containing the repo";
  return null;
}

// Short options of docker run/create/exec that take a value. In a cluster such as "-itv", the first
// value-taking letter consumes the rest of the word, or the next word if nothing is left.
const DOCKER_VALUE_SHORTS = new Set(["a", "c", "e", "h", "l", "m", "p", "u", "v", "w"]);

/** If `t` is a short-option cluster whose value-taking letter is `letter`, return that value. */
function shortOptionValue(t, next, letter) {
  if (!/^-[a-zA-Z]/.test(t) || t.startsWith("--")) return null;
  for (let i = 1; i < t.length; i++) {
    const ch = t[i];
    if (!DOCKER_VALUE_SHORTS.has(ch)) continue;
    if (ch !== letter) return null; // another option consumes the value
    const rest = t.slice(i + 1).replace(/^=/, "");
    if (rest.length > 0) return { text: rest, dynamic: false };
    return next ?? { text: "", dynamic: false };
  }
  return null;
}

function checkContainer(name, args, ctx, cwd, lit) {
  const texts = args.map((w) => lit(w));
  let k = 0;
  while (k < texts.length && texts[k].text.startsWith("-")) {
    if (texts[k].dynamic) block("dynamic-args", `the options to "${name}" are built at run time`);
    k += DOCKER_GLOBAL_VALUE_OPTS.has(texts[k].text) ? 2 : 1;
  }
  if (k >= texts.length) return;
  if (texts[k].dynamic) block("dynamic-args", `the ${name} subcommand is built at run time`);
  let sub = texts[k].text;
  k++;
  if (sub === "container" && k < texts.length) {
    sub = texts[k].text;
    k++;
  }
  if (sub === "compose") {
    while (k < texts.length && texts[k].text.startsWith("-"))
      k += COMPOSE_VALUE_OPTS.has(texts[k].text) ? 2 : 1;
    if (k >= texts.length) return;
    sub = texts[k].text;
    k++;
  }
  if (!["run", "create", "exec", "up"].includes(sub)) return;

  const reason = (what) =>
    `${name} ${sub} with ${what} gives the container host-level access. Containers must follow security.md section 2.`;
  // Scan every remaining argument. Options after the image belong to the container's command, so
  // this can over-block, which is the safe direction.
  for (let j = k; j < texts.length; j++) {
    const a = texts[j];
    const next = texts[j + 1];
    if (a.dynamic)
      block(
        "dynamic-args",
        `the options to "${name} ${sub}" are built at run time, so host-guard can't check them`,
      );
    const t = a.text;
    const eq = t.indexOf("=");
    const flag = t.startsWith("--") && eq > 0 ? t.slice(0, eq) : t;
    const optionValue = () => {
      if (t.startsWith("--") && eq > 0) return { text: t.slice(eq + 1), dynamic: false };
      return next ?? { text: "", dynamic: false };
    };

    if (flag === "--privileged") {
      const v = eq > 0 ? t.slice(eq + 1).toLowerCase() : "true";
      if (v !== "false") block("docker", reason("--privileged"));
      continue;
    }
    if (HOST_NAMESPACE_FLAGS.has(flag)) {
      const v = optionValue();
      if (v.dynamic) block("dynamic-args", `the ${flag} value is built at run time`);
      if (v.text.toLowerCase() === "host") block("docker", reason(`${flag}=host`));
      continue;
    }
    if (flag === "--cap-add") {
      const v = optionValue();
      if (v.dynamic) block("dynamic-args", "the --cap-add value is built at run time");
      for (const cap of v.text.split(",")) {
        const c = cap.trim().toUpperCase().replace(/^CAP_/, "");
        if (DANGEROUS_CAPS.has(c)) block("docker", reason(`--cap-add ${c}`));
      }
      continue;
    }
    if (flag === "--security-opt") {
      const v = optionValue();
      if (v.dynamic) block("dynamic-args", "the --security-opt value is built at run time");
      const s = v.text.toLowerCase().replace(":", "=");
      if (/^(seccomp|apparmor|systempaths)=unconfined$|^label=disable$|^no-new-privileges=false$/.test(s))
        block("docker", reason(`--security-opt ${v.text}`));
      continue;
    }
    if (flag === "--device" || flag === "--device-cgroup-rule" || flag === "--gpus")
      block("docker", reason(flag));
    if (flag === "--env-file")
      block(
        "docker",
        `${name} ${sub} --env-file would copy a file of secrets into the container. Pass only the variables the container needs, with dummy values for demo containers.`,
      );

    // Volumes: --volume, -v VALUE, -vVALUE, and short clusters such as -itv VALUE.
    const volume = flag === "--volume" ? optionValue() : shortOptionValue(t, next, "v");
    if (volume) {
      if (volume.dynamic)
        block("dynamic-args", "a volume path is built at run time, so host-guard can't check it");
      const source = volume.text.split(":")[0];
      const bad = dangerousMountSource(source, ctx, cwd);
      if (bad) block("docker", reason(`a mount of ${bad}`));
      continue;
    }
    if (flag === "--mount") {
      const v = optionValue();
      if (v.dynamic) block("dynamic-args", "a --mount value is built at run time");
      const fields = new Map(
        v.text.split(",").map((kv) => {
          const i = kv.indexOf("=");
          return i < 0
            ? [kv.trim().toLowerCase(), "true"]
            : [kv.slice(0, i).trim().toLowerCase(), kv.slice(i + 1)];
        }),
      );
      const source = fields.get("source") ?? fields.get("src");
      const type = (fields.get("type") ?? "volume").toLowerCase();
      if (type === "bind" && source === undefined) block("docker", reason("a bind mount with no source"));
      if (type === "bind" || source?.includes("/")) {
        const bad = dangerousMountSource(source, ctx, cwd);
        if (bad) block("docker", reason(`a mount of ${bad}`));
      }
      continue;
    }

    // Environment variables copied from the host: -e NAME (no value) or -e NAME=$VAR.
    const env = flag === "--env" ? optionValue() : shortOptionValue(t, next, "e");
    if (env) {
      const eqAt = env.text.indexOf("=");
      const varName = eqAt < 0 ? env.text : env.text.slice(0, eqAt);
      if (SECRET_ENV_NAME.test(varName) && (eqAt < 0 || env.dynamic)) {
        block(
          "docker",
          `${name} ${sub} would copy the host's ${varName} into the container. Never pass real credentials into containers (security.md section 3).`,
        );
      }
    }
  }
}
