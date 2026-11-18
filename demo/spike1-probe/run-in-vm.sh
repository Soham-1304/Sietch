#!/bin/sh
# Runs the Spike 1 probe inside a locked-down gVisor container. Run this INSIDE the Colima VM
# (colima ssh -p sietch -- sh probe/run-in-vm.sh), never on the Mac.
set -eu

# A fake token, built from fixed text. It is not and never was a real credential.
FAKE="npm_spikeFAKEtoken$(printf '0%.0s' $(seq 1 18))"

docker rm -f sietch-spike1 >/dev/null 2>&1 || true
docker run --name sietch-spike1 \
  --runtime=runsc-trace-min \
  --network none \
  --read-only --tmpfs /tmp:rw,size=16m --tmpfs /home/probe:rw,size=1m,uid=1000,gid=1000 \
  --user 1000:1000 --cap-drop=ALL --security-opt no-new-privileges \
  --memory 256m --pids-limit 64 --cpus 1 \
  -e FAKE="$FAKE" \
  -v "$HOME/probe:/probe:ro" \
  node:24-alpine \
  sh -c 'printf "//registry.npmjs.org/:_authToken=%s\n" "$FAKE" > /home/probe/.npmrc; node /probe/parent.js; sleep 5; cat /tmp/marker'

ID="$(docker inspect --format '{{.Id}}' sietch-spike1)"
docker rm sietch-spike1 >/dev/null
echo "container id: $ID"
echo "log dir: /var/log/runsc/$ID"
