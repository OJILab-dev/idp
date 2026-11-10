// A test-time signer of admin requests, written independently of the core's verifier from the profile of
// docs/design/hosting-modes.md 3.2 to 3.4 (the same shape idpctl sends). The keys are generated per test run and
// held only in memory: no real admin key is ever read.
import { createHash } from "node:crypto";

const P384 = { name: "ECDSA", namedCurve: "P-384" } as const;

/** A test admin key: the pair, its keyid, and its SPKI DER as base64, the shape of an ADMIN_SIGNING_KEYS row. */
export type TestAdminKey = {
  readonly pair: CryptoKeyPair;
  readonly keyid: string;
  readonly publicKey: string;
};

/**
 * Generates a P-384 key for a test.
 *
 * @returns The key with its keyid (SHA-256 of the SPKI DER, lowercase hex) and base64 SPKI.
 */
export async function generateTestAdminKey(): Promise<TestAdminKey> {
  const pair = (await crypto.subtle.generateKey(P384, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = new Uint8Array((await crypto.subtle.exportKey("spki", pair.publicKey)) as ArrayBuffer);
  return { pair, keyid: createHash("sha256").update(spki).digest("hex"), publicKey: Buffer.from(spki).toString("base64") };
}

/**
 * The `ADMIN_SIGNING_KEYS` value for named test keys.
 *
 * @param rows The admins and their keys.
 * @returns The JSON array the admin Worker reads.
 */
export function signingKeysJson(rows: readonly (readonly [string, TestAdminKey])[]): string {
  return JSON.stringify(rows.map(([name, key]) => ({ keyid: key.keyid, name, public_key: key.publicKey })));
}

/** What to sign: the request as it will be sent. */
export type ToSign = {
  readonly method: string;
  readonly url: string;
  /** The headers to send; Content-Type and Idempotency-Key are covered when present (and the body is not empty). */
  readonly headers: Headers;
  readonly body: Uint8Array;
};

/** Overrides of the signature, for the negative cases. */
export type SignOptions = {
  /** UNIX seconds; defaults to now. */
  readonly created?: number;
  /** Defaults to 32 fresh random bytes. */
  readonly nonce?: string;
  /** The keyid the request claims; defaults to the signing key's. */
  readonly keyid?: string;
};

function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/**
 * Signs a request with RFC 9421 as idpctl does, adding Content-Digest, Signature-Input, and Signature.
 *
 * @param request The request to sign; its headers are not changed.
 * @param key The signing key.
 * @param options Overrides for the negative cases.
 * @returns The headers to send.
 */
export async function signAdminRequest(request: ToSign, key: TestAdminKey, options: SignOptions = {}): Promise<Headers> {
  const headers = new Headers(request.headers);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", request.body));
  headers.set("content-digest", `sha-256=:${Buffer.from(digest).toString("base64")}:`);
  const components = ["@method", "@target-uri", "@authority", "content-digest"];
  if (request.body.length > 0) components.push("content-type");
  if (headers.has("idempotency-key")) components.push("idempotency-key");
  const created = options.created ?? Math.floor(Date.now() / 1000);
  const nonce = options.nonce ?? base64url(crypto.getRandomValues(new Uint8Array(32)));
  const params = `(${components.map((c) => `"${c}"`).join(" ")});created=${String(created)};nonce="${nonce}";keyid="${options.keyid ?? key.keyid}";tag="idp-admin"`;
  const url = new URL(request.url);
  const values: Readonly<Record<string, string>> = { "@method": request.method, "@target-uri": request.url, "@authority": url.host };
  const lines = components.map((c) => `"${c}": ${values[c] ?? headers.get(c) ?? ""}`);
  lines.push(`"@signature-params": ${params}`);
  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-384" }, key.pair.privateKey, new TextEncoder().encode(lines.join("\n"))),
  );
  headers.set("signature-input", `sig1=${params}`);
  headers.set("signature", `sig1=:${Buffer.from(signature).toString("base64")}:`);
  return headers;
}
