/**
 * Base class for every error thrown inside Sietch's base packages.
 *
 * `code` is a stable, machine-readable identifier (for example `TRACE_PARSE_FAILED`).
 * The API layer maps codes to HTTP responses, so messages can change without breaking clients.
 */
export class SietchError extends Error {
  readonly code: string;

  constructor(code: string, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
    this.code = code;
  }
}
