// The TLS version both Workers accept (docs/design/domain-placement.md, "3. Always Use HTTPS と TLS の最小バージョン").
// The zone's minimum TLS version is a zone-wide setting the IdP does not own when the zone is shared with its
// service, so the Workers refuse anything below TLS 1.2 themselves (RFC 8996 §§4-5; the edge exception is recorded
// in the design). The rule is an allowlist, so a missing, malformed, or unknown value is refused (fail-closed).

/** The `request.cf.tlsVersion` spellings accepted, as in Cloudflare's "Block on TLS" example. */
export const ACCEPTED_TLS_VERSIONS: ReadonlySet<string> = new Set(["TLSv1.2", "TLSv1.3"]);

/**
 * Tells whether the connection that carried a request used TLS 1.2 or 1.3.
 *
 * @param cf The request's `cf` object; undefined outside Cloudflare's edge, which is refused like any other unknown.
 * @returns `true` only when `cf.tlsVersion` is exactly one of {@link ACCEPTED_TLS_VERSIONS}.
 */
export function isAcceptedTlsVersion(cf: unknown): boolean {
  if (typeof cf !== "object" || cf === null) return false;
  const version = (cf as Record<string, unknown>)["tlsVersion"];
  return typeof version === "string" && ACCEPTED_TLS_VERSIONS.has(version);
}
