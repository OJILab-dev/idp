// Loads contract/testdata/vectors.json, the language-neutral test vectors (docs/design/cross-language-contract.md).
// Tests read expected values from here so that a future Rust implementation checks the same values.
import { readFileSync } from "node:fs";
import { join } from "node:path";

type InvalidCase = { readonly value: string; readonly reason: string };

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
};

export const vectors = JSON.parse(
  readFileSync(join(import.meta.dirname, "..", "..", "..", "contract", "testdata", "vectors.json"), "utf8"),
) as Vectors;

export function hexToBytes(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
}
