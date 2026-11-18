// Reference encoders for tests, written differently from src/encoding.ts (bit strings instead of
// integer shifts) so the tests don't rely on the code they check.

const STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function refBase64(bytes: string, urlSafe = false, pad = true): string {
  let bits = "";
  for (let i = 0; i < bytes.length; i++) bits += bytes.charCodeAt(i).toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; i < bits.length; i += 6)
    out += STD[Number.parseInt(bits.slice(i, i + 6).padEnd(6, "0"), 2)];
  if (urlSafe) out = out.replaceAll("+", "-").replaceAll("/", "_");
  if (pad) while (out.length % 4 !== 0) out += "=";
  return out;
}

export function refHex(bytes: string, upper = false): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes.charCodeAt(i).toString(16).padStart(2, "0");
  return upper ? out.toUpperCase() : out;
}

/** Percent-encode every character, including unreserved ones (what an evasive sender might do). */
export function percentEncodeAll(text: string): string {
  let out = "";
  for (let i = 0; i < text.length; i++)
    out += `%${text.charCodeAt(i).toString(16).padStart(2, "0").toUpperCase()}`;
  return out;
}

/** Wrap text into lines of `width`, like the `base64` command line tool. */
export function wrapLines(text: string, width = 76): string {
  const lines: string[] = [];
  for (let i = 0; i < text.length; i += width) lines.push(text.slice(i, i + width));
  return lines.join("\n");
}
