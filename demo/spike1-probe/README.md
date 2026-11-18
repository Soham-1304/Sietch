# Spike 1 probe (harmless test sample)

**This is a harmless test sample, not malware.** It exists to check whether gVisor's tracing can see what a detached child process does after its parent exits, which is the trick Shai-Hulud 2.0 used.

- It only reads a fake `.npmrc` that the test itself creates inside the container, with a fake token built at run time.
- It only connects to `192.0.2.10`, a TEST-NET-1 address (RFC 5737) that is never routed, and the container has no network anyway (`--network none`).
- It runs **only inside a gVisor container** in the local Colima VM. Never run it on the host. `host-guard` blocks that.

Files:
- `parent.js` reads the fake `.npmrc`, starts a detached child, and exits at once.
- `child.js` waits 1.5 s, reads the file again, runs `/bin/sh` (a grandchild process), and tries to connect out with the token base64-encoded.

How it was run and what it showed: `docs/spikes/spike-1-recording.md`.
