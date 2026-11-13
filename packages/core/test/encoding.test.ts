import { describe, expect, it } from "vitest";
import {
  InvalidBase64urlError,
  base64urlDecode,
  base64urlEncode,
  sha256Base64url,
} from "../src/shared/index.js";
import { hexToBytes, vectors } from "./vectors.js";

describe("base64url", () => {
  it.each(vectors.base64url.valid)("encodes hex '$hex' as '$encoded'", ({ hex, encoded }) => {
    expect(base64urlEncode(hexToBytes(hex))).toBe(encoded);
  });

  it.each(vectors.base64url.valid)("decodes '$encoded' to hex '$hex'", ({ hex, encoded }) => {
    expect(base64urlDecode(encoded)).toEqual(hexToBytes(hex));
  });

  it.each(vectors.base64url.invalid)("rejects $value ($reason)", ({ value }) => {
    expect(() => base64urlDecode(value)).toThrow(InvalidBase64urlError);
  });
});

describe("sha256Base64url", () => {
  it.each(vectors.sha256_base64url)("hashes '$input_utf8'", async ({ input_utf8, digest }) => {
    expect(await sha256Base64url(input_utf8)).toBe(digest);
  });

  it.each(vectors.sha256_base64url)("hashes the bytes of '$input_utf8'", async ({ input_utf8, digest }) => {
    expect(await sha256Base64url(new TextEncoder().encode(input_utf8))).toBe(digest);
  });

  it.each(vectors.pkce_s256)("derives the S256 challenge ($source)", async ({ verifier, challenge }) => {
    expect(await sha256Base64url(verifier)).toBe(challenge);
  });
});
