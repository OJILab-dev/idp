// Turns the verifier cases of contract/testdata/vectors.json (admin_signature.verify) into concrete requests. The
// vectors hold no private key: the keys are made at test time, and each case's signature is made over its
// `signature_base` with the placeholders filled in (docs/design/cross-language-contract.md).
import { createHash } from "node:crypto";
import type { AdminSignatureRefusal } from "../src/admin/signature.js";
import type { SignedRequest, VerifyCase } from "./vectors.js";

const subtle = crypto.subtle;
const P384 = { name: "ECDSA", namedCurve: "P-384" } as const;

/** The test-time keys: the allowlisted one and one that is not allowlisted. */
export type TestKeys = {
  readonly allowlisted: CryptoKeyPair;
  readonly other: CryptoKeyPair;
  readonly keyid: string;
  readonly otherKeyid: string;
};

/** A request ready to send: the vector's request with every placeholder replaced. */
export type ConcreteRequest = SignedRequest;

/**
 * Which check of docs/design/hosting-modes.md 3.8 (items 4 to 9) refuses each invalid case. The vectors only say
 * that a case is refused; the reason pins that the intended check fired rather than an earlier one by accident.
 */
export const EXPECTED_REFUSALS: Readonly<Record<string, AdminSignatureRefusal>> = {
  "no-signature": "malformed",
  "signature-input-without-signature": "malformed",
  "signature-without-signature-input": "malformed",
  "two-signatures": "malformed",
  "duplicate-label": "malformed",
  "label-mismatch": "malformed",
  "signature-not-byte-sequence": "malformed",
  "missing-content-digest-component": "profile",
  "extra-component": "profile",
  "components-out-of-order": "profile",
  "path-instead-of-target-uri": "profile",
  "host-header-instead-of-authority": "profile",
  "post-without-content-type-component": "profile",
  "idempotency-key-not-covered": "profile",
  "idempotency-key-covered-but-absent": "profile",
  "content-type-covered-without-body": "profile",
  "alg-present": "profile",
  "expires-present": "profile",
  "unknown-parameter": "profile",
  "missing-created": "profile",
  "missing-nonce": "profile",
  "missing-keyid": "profile",
  "missing-tag": "profile",
  "wrong-tag": "profile",
  "created-not-integer": "profile",
  "created-too-old": "created",
  "created-in-future": "created",
  "nonce-padded": "profile",
  "nonce-too-short": "profile",
  "keyid-uppercase": "profile",
  "keyid-not-allowlisted": "unknown-key",
  "signed-by-another-key": "signature",
  "signature-byte-flipped": "signature",
  "signature-95-bytes": "signature",
  "signature-97-bytes": "signature",
  "signature-der-encoded": "signature",
  "method-changed": "signature",
  "path-changed": "signature",
  "query-added": "signature",
  "authority-changed": "signature",
  "content-type-changed": "signature",
  "idempotency-key-changed": "signature",
  "body-changed": "content-digest",
  "body-and-content-digest-changed": "signature",
  "content-digest-sha-512-only": "malformed",
  "content-digest-two-members": "malformed",
  "content-digest-wrong-value": "content-digest",
};

/**
 * Makes two fresh P-384 key pairs and their keyids (the SPKI DER's SHA-256 in lowercase hex).
 *
 * @returns The keys; the private halves never leave the test process.
 */
export async function makeTestKeys(): Promise<TestKeys> {
  const allowlisted = (await subtle.generateKey(P384, true, ["sign", "verify"])) as CryptoKeyPair;
  const other = (await subtle.generateKey(P384, true, ["sign", "verify"])) as CryptoKeyPair;
  return { allowlisted, other, keyid: await keyidOf(allowlisted.publicKey), otherKeyid: await keyidOf(other.publicKey) };
}

/**
 * Exports a public key as base64 SPKI DER, the form of `public_key` in `admin_signing_keys`.
 *
 * @param key A public key.
 * @returns The base64 (padded) SPKI DER.
 */
export async function spkiBase64(key: CryptoKey): Promise<string> {
  return Buffer.from((await subtle.exportKey("spki", key)) as ArrayBuffer).toString("base64");
}

/**
 * Computes a keyid: the SHA-256 of the SPKI DER in lowercase hex (docs/design/hosting-modes.md 3.7).
 *
 * @param key A public key.
 * @returns The 64-character keyid.
 */
export async function keyidOf(key: CryptoKey): Promise<string> {
  return createHash("sha256").update(new Uint8Array((await subtle.exportKey("spki", key)) as ArrayBuffer)).digest("hex");
}

/**
 * Replaces the key placeholders of a vector string.
 *
 * @param text A vector string.
 * @param keys The test-time keys.
 * @returns The string with `{keyid_upper}`, `{other_keyid}`, and `{keyid}` replaced.
 */
export function substitute(text: string, keys: TestKeys): string {
  return text
    .replaceAll("{keyid_upper}", keys.keyid.toUpperCase())
    .replaceAll("{other_keyid}", keys.otherKeyid)
    .replaceAll("{keyid}", keys.keyid);
}

/**
 * Signs a signature base with ECDSA P-384 and SHA-384, giving r and s concatenated (RFC 9421 §3.3.5).
 *
 * @param key The private key.
 * @param base The signature base.
 * @returns The 96-byte signature.
 */
export async function signBase(key: CryptoKey, base: string): Promise<Uint8Array> {
  return new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-384" }, key, new TextEncoder().encode(base)));
}

function derInteger(bytes: Uint8Array): number[] {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start += 1;
  const body = [...bytes.subarray(start)];
  if ((body[0] ?? 0) & 0x80) body.unshift(0);
  return [0x02, body.length, ...body];
}

/**
 * Re-encodes an r||s signature as ASN.1 DER, which RFC 9421 §3.3.5 does not allow on the wire.
 *
 * @param raw The r||s signature.
 * @returns The DER encoding.
 */
export function derEncode(raw: Uint8Array): Uint8Array {
  const half = raw.length / 2;
  const content = [...derInteger(raw.subarray(0, half)), ...derInteger(raw.subarray(half))];
  return Uint8Array.from([0x30, content.length, ...content]);
}

/**
 * Applies a vector's signature tampering.
 *
 * @param signature The valid signature.
 * @param how The tampering named by the vector, or undefined for none.
 * @returns The signature to send.
 */
export function tamper(signature: Uint8Array, how: VerifyCase["signature_tamper"]): Uint8Array {
  switch (how) {
    case undefined:
      return signature;
    case "flip_first_byte":
      return Uint8Array.from(signature, (b, i) => (i === 0 ? b ^ 1 : b));
    case "drop_last_byte":
      return signature.subarray(0, signature.length - 1);
    case "append_zero_byte":
      return Uint8Array.from([...signature, 0]);
    case "der_encode":
      return derEncode(signature);
  }
}

/**
 * Builds the request a case describes: placeholders filled in and the signature made with the case's key.
 *
 * @param c The verifier case.
 * @param keys The test-time keys.
 * @returns The concrete request.
 */
export async function materialize(c: VerifyCase, keys: TestKeys): Promise<ConcreteRequest> {
  let signature = "";
  if (c.signature_base !== undefined) {
    const signer = c.key === "other" ? keys.other : keys.allowlisted;
    const raw = tamper(await signBase(signer.privateKey, substitute(c.signature_base, keys)), c.signature_tamper);
    signature = Buffer.from(raw).toString("base64");
  }
  return {
    ...c.request,
    headers: c.request.headers.map(([name, value]) => [name, substitute(value, keys).replaceAll("{signature}", signature)] as const),
  };
}

/**
 * Builds the Headers a Worker would see: a repeated header is joined with ", " as the Fetch standard does.
 *
 * @param request The concrete request.
 * @returns The headers.
 */
export function toHeaders(request: ConcreteRequest): Headers {
  const headers = new Headers();
  for (const [name, value] of request.headers) headers.append(name, value);
  return headers;
}
