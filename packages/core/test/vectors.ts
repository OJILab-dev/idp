// Loads contract/testdata/vectors.json, the language-neutral test vectors (docs/design/cross-language-contract.md).
// Tests read expected values from here so that a future Rust implementation checks the same values.
import { readFileSync } from "node:fs";
import { join } from "node:path";

type InvalidCase = { readonly value: string; readonly reason: string };

/** A request as the admin API receives it. Headers are name and value pairs so that a repeated header can be expressed. */
export type SignedRequest = {
  readonly method: string;
  readonly url: string;
  readonly headers: readonly (readonly [string, string])[];
  readonly body_utf8: string;
};

/**
 * One verifier case. The request may hold the placeholders `{keyid}` (the allowlisted key made at test time),
 * `{keyid_upper}` (the same in uppercase), `{other_keyid}` (a second test-time key that is not allowlisted), and
 * `{signature}` (the base64 signature over `signature_base` after the same substitution). Without
 * `signature_base` the case carries no signature at all.
 */
export type VerifyCase = {
  readonly case: string;
  readonly reason?: string;
  readonly request: SignedRequest;
  readonly signature_base?: string;
  /** Which test-time key signs: the allowlisted one by default. */
  readonly key?: "other";
  readonly signature_tamper?: "flip_first_byte" | "drop_last_byte" | "append_zero_byte" | "der_encode";
};

/** Test vectors for the RFC 9421 admin signatures (docs/design/hosting-modes.md 3; cross-language-contract.md). */
export type AdminSignatureVectors = {
  readonly profile: {
    readonly label: string;
    readonly tag: string;
    readonly algorithm: "ecdsa-p384-sha384";
    readonly fallback_algorithm: "ed25519";
    readonly signature_bytes: number;
    readonly window_seconds: number;
    readonly nonce_bytes: number;
    readonly content_digest_algorithm: "sha-256";
    readonly components: readonly string[];
    readonly parameters: readonly string[];
  };
  readonly content_digest: {
    readonly valid: readonly { readonly source: string; readonly body_utf8: string; readonly header: string }[];
    readonly invalid: readonly { readonly body_utf8: string; readonly header: string; readonly reason: string }[];
  };
  readonly keyid: {
    readonly valid: readonly { readonly source: string; readonly spki: string; readonly keyid: string }[];
    readonly invalid: readonly InvalidCase[];
  };
  readonly nonce: { readonly valid: readonly string[]; readonly invalid: readonly InvalidCase[] };
  /** What the signer must produce for a request, given `created`, `nonce`, and `keyid`. */
  readonly signature_base: readonly {
    readonly case: string;
    readonly request: SignedRequest;
    readonly created: number;
    readonly nonce: string;
    readonly keyid: string;
    readonly signature_input: string;
    readonly signature_base: string;
  }[];
  /** Fixed signatures: a P-384 key whose private half was discarded, and the published RFC 9421 Ed25519 example. */
  readonly interop: readonly {
    readonly case: string;
    readonly source?: string;
    readonly algorithm: "ecdsa-p384-sha384" | "ed25519";
    readonly spki: string;
    readonly signature_base: string;
    readonly signature: string;
  }[];
  readonly verify: {
    readonly now: number;
    readonly admin_host: string;
    readonly valid: readonly VerifyCase[];
    readonly invalid: readonly VerifyCase[];
    readonly replay: VerifyCase;
  };
};

type Vectors = {
  readonly max_passkeys_per_user: number;
  readonly base64url: {
    readonly valid: readonly { readonly hex: string; readonly encoded: string }[];
    readonly invalid: readonly InvalidCase[];
  };
  readonly sha256_base64url: readonly { readonly input_utf8: string; readonly digest: string }[];
  readonly pkce_s256: readonly { readonly source: string; readonly verifier: string; readonly challenge: string }[];
  readonly jwk_thumbprint: {
    readonly valid: readonly { readonly source: string; readonly jwk: Readonly<Record<string, unknown>>; readonly kid: string }[];
    readonly invalid: readonly { readonly reason: string; readonly jwk: Readonly<Record<string, unknown>> }[];
  };
  readonly uuid_v4: { readonly valid: readonly string[]; readonly invalid: readonly InvalidCase[] };
  readonly client_id: { readonly valid: readonly string[]; readonly invalid: readonly InvalidCase[] };
  readonly redirect_uri: {
    readonly valid: readonly { readonly value: string; readonly kind: "https" | "loopback" | "custom-scheme" }[];
    readonly invalid: readonly InvalidCase[];
    readonly confidential_rejects: readonly string[];
  };
  readonly random_token: { readonly valid: readonly string[]; readonly invalid: readonly InvalidCase[] };
  readonly issuer: {
    readonly valid: readonly { readonly value: string; readonly rp_id: string; readonly origin: string }[];
    readonly invalid: readonly InvalidCase[];
  };
  readonly signing_key_jwk: {
    readonly valid: readonly {
      readonly source: string;
      readonly jwk: Readonly<Record<string, unknown>>;
      readonly public_jwk: Readonly<Record<string, unknown>>;
    }[];
    readonly invalid_ed25519: readonly { readonly reason: string; readonly secret: string }[];
  };
  readonly jws_ed25519: readonly {
    readonly source: string;
    readonly jwk: Readonly<Record<string, unknown>>;
    readonly signing_input: string;
    readonly signature: string;
  }[];
  readonly discovery: {
    readonly issuer: string;
    readonly ed25519_only: Readonly<Record<string, unknown>>;
    readonly with_rs256_id_token_signing_alg_values_supported: readonly string[];
  };
  readonly token_claims: {
    readonly id_token: readonly {
      readonly case: string;
      readonly input: {
        readonly issuer: string;
        readonly sub: string;
        readonly client_id: string;
        readonly auth_time: number;
        readonly nonce?: string;
        readonly scopes: readonly ("openid" | "profile")[];
        readonly name: string;
        readonly now: number;
      };
      readonly claims: Readonly<Record<string, unknown>>;
    }[];
    readonly access_token: readonly {
      readonly case: string;
      readonly input: {
        readonly issuer: string;
        readonly sub: string;
        readonly client_id: string;
        readonly scopes: readonly ("openid" | "profile")[];
        readonly now: number;
      };
      readonly claims: Readonly<Record<string, unknown>>;
    }[];
    readonly id_token_forbidden: readonly string[];
  };
  readonly redirect_uri_match: readonly {
    readonly case: string;
    readonly registered: string;
    readonly requested: string;
    readonly matches: boolean;
  }[];
  readonly ui_locale: readonly {
    readonly case: string;
    readonly ui_locales: string | null;
    readonly accept_language: string | null;
    readonly locale: "en" | "ja";
  }[];
  readonly admin_signature: AdminSignatureVectors;
};

export const vectors = JSON.parse(
  readFileSync(join(import.meta.dirname, "..", "..", "..", "contract", "testdata", "vectors.json"), "utf8"),
) as Vectors;

export function hexToBytes(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
}
