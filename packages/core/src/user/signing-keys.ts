// Loads the signing keys from the Worker Secrets and validates them against docs/design/cross-language-contract.md.
// The Worker calls this once per isolate and caches the result at module scope (docs/design/tokens.md).
import { InvalidBase64urlError, base64urlDecode } from "@idp/base64url";
import { InvalidJwkError, jwkThumbprint } from "@idp/jwk-thumbprint";

/** The JWS algorithms the IdP signs and verifies with (RFC 9864 §2.2 `Ed25519`, RFC 7518 §3.3 `RS256`). */
export type JwsAlgorithm = "Ed25519" | "RS256";

/** An Ed25519 public key as published in the JWKS (RFC 8037 §2). */
export type Ed25519PublicJwk = {
  readonly kty: "OKP";
  readonly crv: "Ed25519";
  readonly x: string;
  readonly kid: string;
  readonly alg: "Ed25519";
  readonly use: "sig";
};

/** An RSA public key as published in the JWKS (RFC 7518 §6.3.1). */
export type RsaPublicJwk = {
  readonly kty: "RSA";
  readonly n: string;
  readonly e: string;
  readonly kid: string;
  readonly alg: "RS256";
  readonly use: "sig";
};

/** A public JWK with exactly the members the contract allows in the JWKS. */
export type PublicJwk = Ed25519PublicJwk | RsaPublicJwk;

/** One loaded signing key. Each key is used with exactly one algorithm (RFC 8725 §3.1). */
export type SigningKey = {
  /** The RFC 7638 JWK thumbprint. */
  readonly kid: string;
  readonly alg: JwsAlgorithm;
  /** Non-extractable, so the private key cannot leave WebCrypto once imported. */
  readonly privateKey: CryptoKey;
  readonly publicKey: CryptoKey;
  readonly publicJwk: PublicJwk;
};

/** The configured keys. Only the current key of each type signs; every key verifies and appears in the JWKS. */
export type SigningKeySet = {
  /** The current Ed25519 key; always present. */
  readonly ed25519: SigningKey;
  /** The current RSA key; present exactly when RS256 is enabled. */
  readonly rsa: SigningKey | undefined;
  /** Every configured key: Ed25519 current, Ed25519 previous, RSA current, RSA previous, skipping absent ones. */
  readonly all: readonly SigningKey[];
};

/** The raw Worker Secret values, each a private JWK as JSON; `undefined` when the Secret is not set. */
export type SigningKeySecrets = {
  readonly ed25519Current?: string | undefined;
  readonly ed25519Previous?: string | undefined;
  readonly rsaCurrent?: string | undefined;
  readonly rsaPrevious?: string | undefined;
};

/**
 * Thrown when the signing-key configuration is invalid; the Worker must then refuse requests (fail-closed).
 *
 * The message names only the slot and the rule, and no cause is attached: parser and WebCrypto errors can quote
 * their input, and the input here is private key material that must not reach logs.
 */
export class InvalidSigningKeyConfigError extends Error {
  override readonly name = "InvalidSigningKeyConfigError";
}

type Slot = "ed25519Current" | "ed25519Previous" | "rsaCurrent" | "rsaPrevious";

type JwkMembers = Readonly<Record<string, unknown>>;

// RFC 8032 §5.1.5: an Ed25519 private key (the seed) is 32 bytes.
const ED25519_PRIVATE_KEY_BYTES = 32;

// The contract fixes the RSA modulus at exactly 4096 bits, which is 512 bytes with the top bit set.
const RSA_MODULUS_BYTES = 512;

// RFC 7518 §6.3.2: the CRT members accompany d. WebCrypto implementations differ on importing d alone.
const RSA_PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi"] as const;

const ED25519_IMPORT = { name: "Ed25519" } as const;
const RSA_IMPORT = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as const;

/**
 * Loads and validates the signing keys.
 *
 * RS256 is enabled exactly when `rsaCurrent` is set. Every key must carry `use: sig` and the `alg` of its slot
 * (`Ed25519` for OKP, `RS256` for RSA); a `kid` member, if present, must equal the thumbprint.
 *
 * @param secrets The Worker Secret values.
 * @returns The key set, with non-extractable private keys.
 * @throws {InvalidSigningKeyConfigError} `ed25519Current` is unset; `rsaPrevious` is set without `rsaCurrent`; a set
 *   Secret is empty, not a JSON object, or not a private JWK of its slot's type; `use` is not `sig`; `alg` does not
 *   match the key type (`EdDSA` included); a member is not canonical base64url; an Ed25519 `d` is not 32 bytes or `x`
 *   is not its public key; an RSA modulus is not exactly 4096 bits; `kid` differs from the thumbprint; or two slots
 *   hold the same key.
 */
export async function loadSigningKeys(secrets: SigningKeySecrets): Promise<SigningKeySet> {
  if (secrets.ed25519Current === undefined) {
    throw new InvalidSigningKeyConfigError("ed25519Current is not set");
  }
  if (secrets.rsaPrevious !== undefined && secrets.rsaCurrent === undefined) {
    throw new InvalidSigningKeyConfigError("rsaPrevious is set without rsaCurrent");
  }
  const ed25519 = await loadEd25519Key("ed25519Current", secrets.ed25519Current);
  const all: SigningKey[] = [ed25519];
  if (secrets.ed25519Previous !== undefined) {
    all.push(await loadEd25519Key("ed25519Previous", secrets.ed25519Previous));
  }
  let rsa: SigningKey | undefined;
  if (secrets.rsaCurrent !== undefined) {
    rsa = await loadRsaKey("rsaCurrent", secrets.rsaCurrent);
    all.push(rsa);
  }
  if (secrets.rsaPrevious !== undefined) {
    all.push(await loadRsaKey("rsaPrevious", secrets.rsaPrevious));
  }
  // A duplicate kid would make kid-based key selection ambiguous; it also means a rotation went wrong.
  if (new Set(all.map((key) => key.kid)).size !== all.length) {
    throw new InvalidSigningKeyConfigError("two slots hold the same key");
  }
  return { ed25519, rsa, all };
}

async function loadEd25519Key(slot: Slot, secret: string): Promise<SigningKey> {
  const members = parseSecret(slot, secret);
  requireSigningMembers(slot, members, "OKP", "Ed25519");
  if (members["crv"] !== "Ed25519") {
    throw new InvalidSigningKeyConfigError(`${slot}: crv is not Ed25519`);
  }
  const d = requireBase64url(slot, members, "d");
  if (d.length !== ED25519_PRIVATE_KEY_BYTES) {
    throw new InvalidSigningKeyConfigError(`${slot}: d is not 32 bytes`);
  }
  const kid = await thumbprint(slot, members);
  const x = members["x"] as string;
  const publicJwk: Ed25519PublicJwk = { kty: "OKP", crv: "Ed25519", x, kid, alg: "Ed25519", use: "sig" };
  // Import from the required members only, so stray members (key_ops, ext) cannot change the import.
  const privateKey = await importKey(slot, { kty: "OKP", crv: "Ed25519", x, d: members["d"] as string }, ED25519_IMPORT, "sign");
  const publicKey = await importKey(slot, { kty: "OKP", crv: "Ed25519", x }, ED25519_IMPORT, "verify");
  // Not every WebCrypto implementation checks that x is d's public key; a mismatch would publish a JWKS key that
  // verifies none of our signatures. Ed25519 signing is cheap, so prove the pair once at load.
  const probe = new TextEncoder().encode(kid);
  const signature = await crypto.subtle.sign(ED25519_IMPORT, privateKey, probe);
  if (!(await crypto.subtle.verify(ED25519_IMPORT, publicKey, signature, probe))) {
    throw new InvalidSigningKeyConfigError(`${slot}: x is not the public key of d`);
  }
  return { kid, alg: "Ed25519", privateKey, publicKey, publicJwk };
}

async function loadRsaKey(slot: Slot, secret: string): Promise<SigningKey> {
  const members = parseSecret(slot, secret);
  requireSigningMembers(slot, members, "RSA", "RS256");
  const n = requireBase64url(slot, members, "n");
  if (n.length !== RSA_MODULUS_BYTES || (n[0] ?? 0) < 0x80) {
    throw new InvalidSigningKeyConfigError(`${slot}: the RSA modulus is not exactly 4096 bits`);
  }
  requireBase64url(slot, members, "e");
  for (const name of RSA_PRIVATE_MEMBERS) requireBase64url(slot, members, name);
  // Every member was checked to be a string just above.
  function member(name: string): string {
    return members[name] as string;
  }
  const privateJwk: JsonWebKey = {
    kty: "RSA",
    n: member("n"),
    e: member("e"),
    d: member("d"),
    p: member("p"),
    q: member("q"),
    dp: member("dp"),
    dq: member("dq"),
    qi: member("qi"),
  };
  const kid = await thumbprint(slot, members);
  const publicJwk: RsaPublicJwk = { kty: "RSA", n: member("n"), e: member("e"), kid, alg: "RS256", use: "sig" };
  // Unlike Ed25519, no sign-and-verify probe: an RSA-4096 signature costs milliseconds of CPU per isolate start,
  // and n and e are part of the private key itself, so the public half cannot drift from it.
  const privateKey = await importKey(slot, privateJwk, RSA_IMPORT, "sign");
  const publicKey = await importKey(slot, { kty: "RSA", n: publicJwk.n, e: publicJwk.e }, RSA_IMPORT, "verify");
  return { kid, alg: "RS256", privateKey, publicKey, publicJwk };
}

function parseSecret(slot: Slot, secret: string): JwkMembers {
  let parsed: unknown;
  try {
    parsed = JSON.parse(secret);
  } catch {
    // The SyntaxError quotes the input, which is the private key, so it is dropped rather than chained.
    throw new InvalidSigningKeyConfigError(`${slot}: not JSON`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new InvalidSigningKeyConfigError(`${slot}: not a JSON object`);
  }
  return parsed as JwkMembers;
}

function requireSigningMembers(slot: Slot, members: JwkMembers, kty: "OKP" | "RSA", alg: JwsAlgorithm): void {
  if (members["kty"] !== kty) {
    throw new InvalidSigningKeyConfigError(`${slot}: kty is not ${kty}`);
  }
  if (members["use"] !== "sig") {
    throw new InvalidSigningKeyConfigError(`${slot}: use is not sig`);
  }
  // This also rejects the deprecated EdDSA (RFC 9864 §4.1.2) and any alg of another key type.
  if (members["alg"] !== alg) {
    throw new InvalidSigningKeyConfigError(`${slot}: alg is not ${alg}`);
  }
}

function requireBase64url(slot: Slot, members: JwkMembers, name: string): Uint8Array {
  const value = members[name];
  if (typeof value !== "string") {
    throw new InvalidSigningKeyConfigError(`${slot}: ${name} is missing or not a string`);
  }
  try {
    return base64urlDecode(value);
  } catch (error) {
    if (error instanceof InvalidBase64urlError) {
      throw new InvalidSigningKeyConfigError(`${slot}: ${name} is not canonical base64url`);
    }
    throw error;
  }
}

async function thumbprint(slot: Slot, members: JwkMembers): Promise<string> {
  let kid: string;
  try {
    kid = await jwkThumbprint(members);
  } catch (error) {
    if (error instanceof InvalidJwkError) {
      throw new InvalidSigningKeyConfigError(`${slot}: ${error.message}`);
    }
    throw error;
  }
  // A kid written by hand or by a different algorithm would let the JWKS and the token headers disagree.
  if (members["kid"] !== undefined && members["kid"] !== kid) {
    throw new InvalidSigningKeyConfigError(`${slot}: kid is not the JWK thumbprint`);
  }
  return kid;
}

async function importKey(
  slot: Slot,
  jwk: JsonWebKey,
  algorithm: typeof ED25519_IMPORT | typeof RSA_IMPORT,
  usage: "sign" | "verify",
): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey("jwk", jwk, algorithm, false, [usage]);
  } catch {
    throw new InvalidSigningKeyConfigError(`${slot}: WebCrypto rejected the ${usage === "sign" ? "private" : "public"} key`);
  }
}
