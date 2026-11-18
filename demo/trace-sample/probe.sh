#!/bin/sh
# Harmless trace-sample probe (see README.md). Runs inside a gVisor container only.
# Each block makes one kind of system call the normaliser must handle.
set -u
cd /tmp

# Files: create, write, append, read, relative paths, a subdirectory, and a dirfd-relative open.
echo one > rel.txt
echo two >> rel.txt
cat rel.txt > /dev/null
mkdir -p sub/deeper
cd sub && echo three > inner.txt && cd ..
cat /home/probe/.npmrc > /dev/null

# Rename, symlink, hard link, chmod, delete, rmdir.
mv rel.txt moved.txt
ln -s /home/probe/.npmrc link-to-npmrc
ln moved.txt hard-link.txt
chmod 700 moved.txt
rm hard-link.txt
rmdir sub/deeper

# Hostile-looking file names: a newline, a quote, a backslash, and non-ASCII.
touch "$(printf 'nl\nname')" 'quo"te' 'back\slash' 'caf\303\251'

# A long path.
long=/tmp/$(printf 'a%.0s' $(seq 1 200))
mkdir -p "$long" && echo x > "$long/f"

# Processes: a failed exec, a background child, and a child killed by a signal.
/does/not/exist 2>/dev/null
sh -c 'sleep 0.2; echo bg > /tmp/bg.txt' &
sh -c 'sleep 30' &
victim=$!
kill -9 "$victim"
wait

# Network (all fail: --network none): IPv4 TCP, IPv6 TCP, UDP sendto, and a Unix socket.
node -e '
const net = require("node:net"); const dgram = require("node:dgram");
const quiet = (s) => s.on("error", () => {});
quiet(net.connect({ host: "192.0.2.10", port: 443 }));
quiet(net.connect({ host: "2001:db8::1", port: 80 }));
quiet(net.connect({ path: "/tmp/no-such.sock" }));
const u = dgram.createSocket("udp4"); quiet(u);
u.send("hello", 53, "192.0.2.10", () => u.close());
setTimeout(() => process.exit(0), 500);
'
echo done
