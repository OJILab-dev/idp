// Signing keys generated fresh in each test run, so no private key other than the RFC 8037 example is committed.

type JwkRecord = Record<string, unknown>;

// key_ops and ext are WebCrypto export artefacts, not members the generation script writes.
function stripExportMembers(jwk: JsonWebKey): JwkRecord {
  const rest: JwkRecord = { ...jwk };
  delete rest["key_ops"];
  delete rest["ext"];
  return rest;
}

/**
 * Generates an Ed25519 private JWK in the contract's shape (use sig, alg Ed25519).
 *
 * @returns The JWK as an object; serialise it with JSON.stringify to get the Worker Secret value.
 */
export async function generateEd25519Jwk(): Promise<JwkRecord> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", pair.privateKey)) as JsonWebKey;
  return { ...stripExportMembers(jwk), use: "sig", alg: "Ed25519" };
}

/**
 * Generates an RSA private JWK in the contract's shape (use sig, alg RS256).
 *
 * @param modulusLength The modulus size in bits; the contract allows only 4096.
 * @returns The JWK as an object.
 */
export async function generateRsaJwk(modulusLength = 4096): Promise<JwkRecord> {
  const pair = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", pair.privateKey)) as JsonWebKey;
  return { ...stripExportMembers(jwk), use: "sig", alg: "RS256" };
}
