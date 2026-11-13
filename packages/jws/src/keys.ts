// The algorithms and key shapes the JWS functions work with: Ed25519 (RFC 8037 §3.1, under the fully specified name
// of RFC 9864 §2.2) and RS256 (RFC 7518 §3.3). Each key is used with exactly one algorithm (RFC 8725 §3.1).

/** The JWS algorithms this package signs and verifies with (RFC 9864 §2.2 `Ed25519`, RFC 7518 §3.3 `RS256`). */
export type JwsAlgorithm = "Ed25519" | "RS256";

/** A key that signs. */
export type JwsSigningKey = {
  /** The `kid` header value of the JWS it signs. */
  readonly kid: string;
  readonly alg: JwsAlgorithm;
  readonly privateKey: CryptoKey;
};

/** A key that verifies; the `kid` header selects it. */
export type JwsVerificationKey = {
  readonly kid: string;
  readonly alg: JwsAlgorithm;
  readonly publicKey: CryptoKey;
};

/** An Ed25519 public key as published in a JWK Set (RFC 8037 §2). */
export type Ed25519PublicJwk = {
  readonly kty: "OKP";
  readonly crv: "Ed25519";
  readonly x: string;
  readonly kid: string;
  readonly alg: "Ed25519";
  readonly use: "sig";
};

/** An RSA public key as published in a JWK Set (RFC 7518 §6.3.1). */
export type RsaPublicJwk = {
  readonly kty: "RSA";
  readonly n: string;
  readonly e: string;
  readonly kid: string;
  readonly alg: "RS256";
  readonly use: "sig";
};

/** A public signature-verification JWK with its `kid`, `alg`, and `use` (RFC 7517 §4). */
export type PublicJwk = Ed25519PublicJwk | RsaPublicJwk;

/** A JWK Set (RFC 7517 §5). */
export type JwkSet = { readonly keys: readonly PublicJwk[] };
