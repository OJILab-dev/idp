import { beforeAll, describe, expect, it } from "vitest";
import { parseIssuer } from "@idp/issuer";
import { buildDiscoveryDocument, buildJwks, loadSigningKeys, type SigningKeySet } from "../../src/domain/index.js";
import { generateEd25519Jwk, generateRsaJwk } from "./keys.js";
import { vectors } from "../../../../contract/test/vectors.js";

const issuer = parseIssuer(vectors.discovery.issuer);

let edOnly: SigningKeySet;
let withRsa: SigningKeySet;

beforeAll(async () => {
  const [edCurrent, edPrevious, rsaCurrent, rsaPrevious] = await Promise.all([
    generateEd25519Jwk(),
    generateEd25519Jwk(),
    generateRsaJwk(),
    generateRsaJwk(),
  ]);
  edOnly = await loadSigningKeys({ ed25519Current: JSON.stringify(edCurrent) });
  withRsa = await loadSigningKeys({
    ed25519Current: JSON.stringify(edCurrent),
    ed25519Previous: JSON.stringify(edPrevious),
    rsaCurrent: JSON.stringify(rsaCurrent),
    rsaPrevious: JSON.stringify(rsaPrevious),
  });
}, 120_000);

describe("buildDiscoveryDocument", () => {
  it("matches the contract vector for an Ed25519-only deployment", () => {
    expect(buildDiscoveryDocument(issuer, edOnly)).toStrictEqual(vectors.discovery.ed25519_only);
  });

  it("advertises RS256 exactly when an RSA key is configured", () => {
    expect(buildDiscoveryDocument(issuer, withRsa)).toStrictEqual({
      ...vectors.discovery.ed25519_only,
      id_token_signing_alg_values_supported: vectors.discovery.with_rs256_id_token_signing_alg_values_supported,
    });
  });
});

describe("buildJwks", () => {
  it("lists the RFC 8037 key with only public members, kid, alg, and use", async () => {
    const vector = vectors.signing_key_jwk.valid[0];
    if (vector === undefined) throw new Error("missing vector");
    const keys = await loadSigningKeys({ ed25519Current: JSON.stringify(vector.jwk) });
    expect(buildJwks(keys)).toStrictEqual({ keys: [vector.public_jwk] });
  });

  it("lists every configured key without private members", () => {
    const jwks = buildJwks(withRsa);
    expect(jwks.keys.map((key) => key.kid)).toEqual(withRsa.all.map((key) => key.kid));
    for (const key of jwks.keys) {
      const allowed = key.kty === "OKP" ? ["alg", "crv", "kid", "kty", "use", "x"] : ["alg", "e", "kid", "kty", "n", "use"];
      expect(Object.keys(key).sort()).toEqual(allowed);
    }
    const serialised = JSON.stringify(jwks);
    for (const member of ['"d"', '"p"', '"q"', '"dp"', '"dq"', '"qi"', '"key_ops"', '"ext"']) {
      expect(serialised).not.toContain(member);
    }
  });
});
