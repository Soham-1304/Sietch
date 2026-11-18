// Build gVisor-shaped JSON log records for tests, exactly the way the JSON logger frames them.

export const TRACED = [
  "execve",
  "execveat",
  "openat",
  "unlinkat",
  "renameat",
  "renameat2",
  "symlinkat",
  "linkat",
  "fchmodat",
  "mkdirat",
  "connect",
  "sendto",
  "sendmsg",
  "clone",
  "clone3",
  "exit_group",
  "wait4",
  "waitid",
  "kill",
  "tgkill",
  "chdir",
  "fchdir",
];
export const LAYOUT = { initPid: 1, tracedSyscalls: TRACED };

let clock = 0;
export const rec = (tgid: number, comm: string, body: string, kind: "E" | "X" = "X") => {
  clock++;
  const msg = `strace.go:609] [${String(tgid).padStart(4)}:${String(tgid).padStart(4)}] ${comm} ${kind} ${body}`;
  return JSON.stringify({
    msg,
    level: "info",
    time: `2026-11-18T22:00:00.${String(clock).padStart(6, "0")}+05:30`,
  });
};
export const ok = (call: string, ret = 0) => `${call} = ${ret} (0x${ret.toString(16)}) (3µs)`;
export const err = (call: string, errno = 2) =>
  `${call} = -1 errno=${errno} (no such file or directory) (3µs)`;

export const clone = (parent: number, child: number) =>
  rec(parent, "sh", ok("clone(0x11, 0x0, 0x0, 0xfd00, 0xfd30)", child));
export const exitG = (pid: number, comm = "sh") => rec(pid, comm, "exit_group(0x0)", "E");
export const execve = (pid: number, path: string, argv: string[]) =>
  rec(
    pid,
    "sh",
    ok(
      `execve(0xfd01 ${path}, 0xfd02 ${JSON.stringify(argv).replaceAll('","', '", "')}, 0xfd03 ["PATH=/bin", "HOME=/home/probe"])`,
    ),
  );
export const openat = (pid: number, cwd: string, path: string, flags = "O_RDONLY|O_CLOEXEC", ret = 3) =>
  rec(pid, "node", ok(`openat(AT_FDCWD ${cwd}, 0xfd04 ${path}, ${flags}, 0o0)`, ret));

/** A minimal valid trace: init starts npm (install) and the harness (load). `inner` runs inside install. */
export function trace(inner: string[] = [], load: string[] = []): string {
  return [
    clone(1, 10),
    execve(10, "/usr/local/bin/npm", ["npm", "install"]),
    ...inner,
    exitG(10, "npm"),
    clone(1, 20),
    execve(20, "/usr/local/bin/node", ["node", "/sietch/harness.js"]),
    ...load,
    exitG(20, "node"),
  ].join("\n");
}
