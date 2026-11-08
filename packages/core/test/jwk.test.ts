import { describe, expect, it } from "vitest";
import { InvalidJwkError, jwkThumbprint } from "../src/shared/index.js";
import { vectors } from "./vectors.js";

describe("jwkThumbprint", () => {
  it.each(vectors.jwk_thumbprint.valid)("computes the kid ($source)", async ({ jwk, kid }) => {
    expect(await jwkThumbprint(jwk)).toBe(kid);
  });

  it.each(vectors.jwk_thumbprint.invalid)("rejects $reason", async ({ jwk }) => {
    await expect(jwkThumbprint(jwk)).rejects.toThrow(InvalidJwkError);
  });

  it.each([null, "jwk", 1, []])("rejects the non-object %j", async (jwk) => {
    await expect(jwkThumbprint(jwk)).rejects.toThrow(InvalidJwkError);
  });
});
