#!/bin/sh
# Harmless trace-sample probe, part 2 (see README.md): long strings and UDP sends. gVisor only.
set -u
cd /tmp
# A path of about 4,000 bytes (each segment 200 characters, 19 deep).
seg=$(printf 'b%.0s' $(seq 1 200))
p=/tmp
for i in $(seq 1 19); do p="$p/$seg"; done
mkdir -p "$p" && echo x > "$p/f"
# An execve with 600 arguments.
/bin/true $(seq 1 600)
# UDP sendto with an explicit destination (TEST-NET-1, never routed; --network none anyway).
node -e '
const d = require("node:dgram").createSocket("udp4"); d.on("error", () => {});
d.send("hello", 4444, "192.0.2.10", () => d.close());
setTimeout(() => process.exit(0), 300);
'
echo done
