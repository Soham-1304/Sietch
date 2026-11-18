# Trace sample probe (harmless test sample)

**This is a harmless test sample, not malware.** It makes every kind of system call the trace normaliser has to understand, so we can record what gVisor's trace really looks like and use it as a test fixture.

- It only touches files under `/tmp` and a fake home directory inside the container.
- Its network calls go to `192.0.2.10` (TEST-NET-1, RFC 5737), `2001:db8::1` (the IPv6 documentation range, RFC 3849), and a Unix socket path that doesn't exist. The container runs with `--network none`, so nothing leaves it.
- It runs **only inside a gVisor container** in the local Colima VM, never on the Mac.

How it was run: `docs/spikes/trace-sample.md`.
