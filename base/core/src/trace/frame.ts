// Stage 1: split gVisor's JSON debug log into records. One JSON object per line; gVisor escapes
// newlines inside strings, so a file name can never start a new record (docs/spikes/trace-sample.md).

import { TraceFailure } from "./errors.js";

export const MAX_LOG_CHARS = 64 * 1024 * 1024;
export const MAX_RECORDS = 500_000;

export interface StraceRecord {
  /** 1-based line number, for error messages. */
  readonly line: number;
  /** The message after "strace.go:<n>] ". */
  readonly body: string;
  readonly timeMs: number;
}

const STRACE_PREFIX = "strace.go:";

/** Records from strace, in log order. Throws TraceFailure on anything that isn't clean framing. */
export function frameLog(log: string): StraceRecord[] {
  if (log.length > MAX_LOG_CHARS) throw new TraceFailure("TRACE_TOO_LARGE", 0);
  const lines = log.split("\n");
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  if (lines.length > MAX_RECORDS) throw new TraceFailure("TRACE_TOO_LARGE", 0);

  const out: StraceRecord[] = [];
  lines.forEach((text, i) => {
    const line = i + 1;
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new TraceFailure("UNFRAMED_RECORD", line);
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed))
      throw new TraceFailure("UNFRAMED_RECORD", line);
    const msg: unknown = (parsed as Record<string, unknown>).msg;
    const time: unknown = (parsed as Record<string, unknown>).time;
    if (typeof msg !== "string" || typeof time !== "string") throw new TraceFailure("UNFRAMED_RECORD", line);
    if (!msg.startsWith(STRACE_PREFIX)) return;
    const close = msg.indexOf("] ", STRACE_PREFIX.length);
    const lineNo = msg.slice(STRACE_PREFIX.length, close);
    if (close < 0 || lineNo.length === 0 || lineNo.length > 6 || !isDigits(lineNo)) return; // not a strace record
    const timeMs = parseRfc3339(time);
    if (timeMs === null) throw new TraceFailure("MALFORMED_RECORD", line);
    out.push({ line, body: msg.slice(close + 2), timeMs });
  });
  return out;
}

export function isDigits(s: string): boolean {
  if (s.length === 0) return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 48 || c > 57) return false;
  }
  return true;
}

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/;

/** Milliseconds since the Unix epoch for an RFC 3339 timestamp, or null. Pure (no Date). */
export function parseRfc3339(s: string): number | null {
  if (s.length > 40) return null;
  const m = RFC3339.exec(s);
  if (m === null) return null;
  const [y, mo, d, h, mi, se] = [m[1], m[2], m[3], m[4], m[5], m[6]].map(Number) as [
    number,
    number,
    number,
    number,
    number,
    number,
  ];
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || se > 60) return null;
  const frac = m[7] === undefined ? 0 : Number(`0.${m[7]}`);
  const zone = m[8] ?? "Z";
  const offsetMin =
    zone === "Z"
      ? 0
      : (zone[0] === "-" ? -1 : 1) * (Number(zone.slice(1, 3)) * 60 + Number(zone.slice(4, 6)));
  const days = daysFromCivil(y, mo, d);
  return ((days * 24 + h) * 60 + mi - offsetMin) * 60_000 + se * 1000 + frac * 1000;
}

/** Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm). */
function daysFromCivil(y: number, m: number, d: number): number {
  const yy = m <= 2 ? y - 1 : y;
  const era = Math.floor(yy / 400);
  const yoe = yy - era * 400;
  const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146097 + doe - 719468;
}
