// The checks before any work (docs/design/hosting-modes.md 3.8; docs/design/idpctl.md, "管理者の認証（RFC 9421 の署名）"),
// cheapest first and the only D1 write last: the host, scheme, and TLS version; the Rate Limiting binding per client
// IP; the body size; the RFC 9421 signature against the ADMIN_SIGNING_KEYS allowlist; and the nonce. The admin is
// decided only by the allowlisted key that verified the signature, never by anything the request names.
import { AdminNonceStoreError, verifyAdminSignature, type AdminIdentity, type AdminSignatureRefusal } from "@idp/core/admin";
import { isAcceptedTlsVersion } from "@idp/core/shared";
import { createD1AdminNonceStore } from "@idp/d1-adapter/admin";
import type { AdminConfig } from "./config.js";

/**
 * Why a request was refused; written to the Worker log only, never to the response:
 * - `host` and `tls`: item 1 (the host, the scheme, the TLS version);
 * - `no-client-ip`: item 2 without a CF-Connecting-IP to count;
 * - `body-size`: item 3;
 * - the verifier's reasons: items 4 to 9;
 * - `replayed`: item 10, the nonce was already stored.
 */
export type GateRefusal = "host" | "tls" | "no-client-ip" | "body-size" | AdminSignatureRefusal | "replayed";

/** The outcome of the gate before the operation. */
export type GateResult =
  | { readonly ok: true; readonly admin: AdminIdentity; readonly body: Uint8Array }
  /** Refused with `forbidden` and no reason; `keyid` is the claimed keyid once its form was checked. */
  | { readonly ok: false; readonly refusal: GateRefusal; readonly keyid?: string }
  /** Refused with 429 and no body (hosting-modes.md 3.8). */
  | { readonly ok: false; readonly limited: true }
  /** Refused with `internal`: the limiter or the nonce store failed, so the request cannot be judged (fail-closed). */
  | { readonly ok: false; readonly internal: string };

/**
 * The largest body the admin API reads. Every admin input is a small JSON object; a body over this is no request of
 * idpctl, and its bytes are never hashed.
 */
export const ADMIN_BODY_LIMIT_BYTES = 64 * 1024;

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
 * Reads the body as bytes, at most {@link ADMIN_BODY_LIMIT_BYTES}. The limit is enforced on the bytes as they arrive:
 * a chunked body declares no length, and buffering it whole first would let one request hold the isolate's memory.
 *
 * @param request The request.
 * @returns The bytes, or `undefined` when the body is over the limit.
 */
export async function readLimitedBody(request: Request): Promise<Uint8Array | undefined> {
  const declared = request.headers.get("content-length");
  if (declared !== null && !(Number(declared) <= ADMIN_BODY_LIMIT_BYTES)) return undefined;
  if (request.body === null) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > ADMIN_BODY_LIMIT_BYTES) {
      await reader.cancel();
      return undefined;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

function describe(error: unknown): string {
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error);
}

/**
 * Runs every check of the gate on a request, in the order of docs/design/hosting-modes.md 3.8.
 *
 * Nothing is written before the signature and the body digest passed: the only write of the gate is the nonce, so
 * an unauthenticated request leaves no row in D1 (3.6).
 *
 * @param request The received request; its body is consumed, and returned in the result for the operation.
 * @param config The configuration.
 * @param now The clock in UNIX seconds, read once for the whole request.
 * @returns The admin and the body, or how to refuse the request. Never rejects for a refusal.
 */
export async function admitRequest(request: Request, config: AdminConfig, now: number): Promise<GateResult> {
  // 1. The host and scheme, then TLS 1.2 or later: the zone's minimum TLS version is not the IdP's to set.
  if (!isAdminHost(new URL(request.url), config)) return { ok: false, refusal: "host" };
  if (!isAcceptedTlsVersion(request.cf)) return { ok: false, refusal: "tls" };
  // 2. The rate limit, before any parsing, so a flood of unsigned requests costs no verification. The IP is only the
  //    counting key: it is never logged or stored (design principle 7).
  const clientIp = request.headers.get("cf-connecting-ip");
  if (clientIp === null || clientIp === "") return { ok: false, refusal: "no-client-ip" };
  let outcome: RateLimitOutcome;
  try {
    outcome = await config.rateLimiter.limit({ key: clientIp });
  } catch (error) {
    return { ok: false, internal: `rate limiter failed: ${describe(error)}` };
  }
  if (!outcome.success) return { ok: false, limited: true };
  // 3. The body size, so that only a bounded body is hashed.
  const body = await readLimitedBody(request);
  if (body === undefined) return { ok: false, refusal: "body-size" };
  // 4 to 9. @target-uri is request.url exactly as received (RFC 9421 §2.2.2), which is what idpctl signed.
  const verified = await verifyAdminSignature({ method: request.method, url: request.url, headers: request.headers, body }, config.signingKeys, now);
  if (!verified.ok) return { ok: false, refusal: verified.reason, ...(verified.keyid === undefined ? {} : { keyid: verified.keyid }) };
  // 10. The nonce, the first and only write before the operation's own.
  try {
    const claim = await createD1AdminNonceStore(config.db).claim(verified.nonce, verified.expiresAt, now);
    if (claim === "replayed") return { ok: false, refusal: "replayed", keyid: verified.admin.keyid };
  } catch (error) {
    if (!(error instanceof AdminNonceStoreError)) throw error;
    return { ok: false, internal: `nonce store failed: ${describe(error)}` };
  }
  return { ok: true, admin: verified.admin, body };
}
