// Harmless Spike 1 probe (see README.md). Runs only inside a gVisor container.
// Reads a fake file, starts a detached child, and exits immediately, like Shai-Hulud 2.0's loader.
const { spawn } = require("node:child_process");
const fs = require("node:fs");

fs.readFileSync("/home/probe/.npmrc", "utf8");
const child = spawn(process.execPath, ["/probe/child.js"], { detached: true, stdio: "ignore" });
child.unref();
process.stdout.write(`parent: started child ${child.pid}, exiting now\n`);
