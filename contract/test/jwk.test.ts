import { describe, expect, it } from "vitest";
import { InvalidJwkError, jwkThumbprint } from "../../packages/jwk-thumbprint/src/index.js";
import { vectors } from "./vectors.js";

// The contract's kid vectors, checked against the package core uses (docs/design/packages.md, coupling 10).
describe("jwkThumbprint", () => {
  it.each(vectors.jwk_thumbprint.valid)("computes the kid ($source)", async ({ jwk, kid }) => {
    expect(await jwkThumbprint(jwk)).toBe(kid);
  });

  it.each(vectors.jwk_thumbprint.invalid)("rejects $reason", async ({ jwk }) => {
    await expect(jwkThumbprint(jwk)).rejects.toThrow(InvalidJwkError);
  });
});
