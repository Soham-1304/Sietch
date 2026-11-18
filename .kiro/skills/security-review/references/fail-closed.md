# Fail closed

**Rule:** when something unexpected happens on a security path, the result is **block**, and the reason is visible. "Unexpected" includes errors, timeouts, missing tools, missing configuration, unparsable input, unknown types, and empty input.

## Patterns that are findings

```ts
// 1. Swallowed error that allows
try { verdict = judge(events) } catch { verdict = "SAFE" }

// 2. Default that allows
const allowed = policy.allow ?? true;

// 3. Missing input treated as "nothing to check"
if (!command) process.exit(0);

// 4. Unknown case ignored
switch (event.type) { case "exec": ...; default: break; }

// 5. Tool missing, so the check is skipped
if (!existsSync(tsc)) return;

// 6. Timeout that resolves instead of rejecting
await Promise.race([scan(), sleep(60_000).then(() => [])]);
```

## What correct code looks like

```ts
try { verdict = judge(events) } catch (error) { verdict = { kind: "ERROR", reason: describe(error) } } // ERROR blocks

const allowed = policy.allow ?? false;

if (!command) block("hook event had no command");

default: { const unreachable: never = event; throw new UnknownEventError(unreachable); }
```

## When a fallback is acceptable

Only when **all** of these hold, and a comment next to the code says so:

1. The path is **not** a security decision. For example, choosing a display colour, or a developer convenience hook whose failure is reported.
2. The fallback is **visible**: logged or reported, never silent.
3. Blocking would cause a worse safety outcome, and the comment explains why.

"It's simpler" or "it might break" are not reasons.
