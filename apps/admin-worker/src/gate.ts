// The checks before any work: the admin host, then the edge mTLS re-checked fail-closed, then the allowlist
// (docs/design/idpctl.md, "管理者の認証（mTLS）" and "許可リストによる管理者の確定"). The admin is never decided by the
// certificate's subject: the managed CA verifies per account, so anyone who can issue a certificate could pick a
// subject, while the allowlist also requires the right to deploy.
import type { AdminIdentity } from "@idp/core/admin";
import type { AdminConfig } from "./config.js";

/** Why a request was refused; written to the Worker log only, never to the response. */
export type GateRefusal = "host" | "tls" | "no-client-auth" | "not-verified" | "revoked" | "bad-fingerprint" | "not-allowlisted";

/** The outcome of the gate. */
export type GateResult =
  | { readonly ok: true; readonly admin: AdminIdentity }
  | { readonly ok: false; readonly reason: GateRefusal; readonly fingerprint?: string };

const HEX_SHA256 = /^[0-9a-fA-F]{64}$/;

/**
 * Checks that the request reached the configured admin host over https on the default port.
 *
 * @param url The request URL.
 * @param config The configuration.
 * @returns Whether the host is the admin host.
 */
export function isAdminHost(url: URL, config: AdminConfig): boolean {
  return url.protocol === "https:" && url.host === config.adminHost;
}

/**
 * Resolves the admin from the request's client certificate.
 *
 * Cloudflare reports `certVerified` as the string `"SUCCESS"` (not a boolean), `certRevoked` as `"0"` or `"1"`, and
 * the fingerprint as hex (Cloudflare "Client certificate variables", "Workers variables"). Anything else, including
 * a missing `request.cf`, is refused. The fingerprint is normalised only by lowercasing 64 hex digits; any other
 * spelling (colons, whitespace) is malformed.
 *
 * @param cf The request's `cf` object; undefined outside Cloudflare's edge.
 * @param config The configuration with the allowlist.
 * @returns The admin, or the reason for the refusal.
 */
export function resolveAdmin(cf: unknown, config: AdminConfig): GateResult {
  const auth = typeof cf === "object" && cf !== null ? (cf as Record<string, unknown>)["tlsClientAuth"] : undefined;
  if (typeof auth !== "object" || auth === null) return { ok: false, reason: "no-client-auth" };
  const { certVerified, certRevoked, certFingerprintSHA256 } = auth as Record<string, unknown>;
  if (certVerified !== "SUCCESS") return { ok: false, reason: "not-verified" };
  if (certRevoked !== "0") return { ok: false, reason: "revoked" };
  if (typeof certFingerprintSHA256 !== "string" || !HEX_SHA256.test(certFingerprintSHA256)) return { ok: false, reason: "bad-fingerprint" };
  const fingerprint = certFingerprintSHA256.toLowerCase();
  const name = config.allowlist.get(fingerprint);
  if (name === undefined) return { ok: false, reason: "not-allowlisted", fingerprint };
  return { ok: true, admin: { name, certSha256: fingerprint } };
}
