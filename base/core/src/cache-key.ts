import { InvalidPackageIdentityError } from "./errors.js";
import { INTEGRITY_PATTERN, MAX_NAME, MAX_VERSION } from "./limits.js";

export interface PackageIdentity {
  readonly name: string;
  readonly version: string;
  readonly integrity: string;
}

const MAX_RULESET_VERSION = 64;

function check(value: string, field: string, max: number): void {
  if (typeof value !== "string" || value.length === 0 || value.length > max || !value.isWellFormed()) {
    throw new InvalidPackageIdentityError(
      `${field} must be a non-empty, well-formed string of at most ${max} characters`,
    );
  }
}

/**
 * The key a verdict is cached under. Equal keys mean equal name, version, integrity, and ruleset
 * version. Each part is passed through encodeURIComponent, which always encodes ":", so no part
 * can contain the separator. A re-published tarball (new integrity) never reuses an old verdict.
 */
export function verdictCacheKey(identity: PackageIdentity, rulesetVersion: string): string {
  check(identity.name, "name", MAX_NAME);
  check(identity.version, "version", MAX_VERSION);
  check(rulesetVersion, "rulesetVersion", MAX_RULESET_VERSION);
  if (typeof identity.integrity !== "string" || !INTEGRITY_PATTERN.test(identity.integrity)) {
    throw new InvalidPackageIdentityError("integrity must be a sha512 Subresource Integrity value");
  }
  const parts = [identity.name, identity.version, identity.integrity, rulesetVersion].map(encodeURIComponent);
  return `verdict:v1:${parts.join(":")}`;
}
