import { describe, expect, it } from "vitest";
import { pkceChallenge, randomToken } from "../src/pkce.js";

describe("randomToken", () => {
  it("is 32 random bytes as unpadded base64url, fresh on every call", () => {
    const tokens = new Set(Array.from({ length: 50 }, () => randomToken()));
    expect(tokens.size).toBe(50);
    for (const token of tokens) expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("is a valid PKCE verifier: 43 to 128 unreserved characters (RFC 7636 §4.1)", () => {
    expect(randomToken()).toMatch(/^[A-Za-z0-9._~-]{43,128}$/);
  });
});

describe("pkceChallenge", () => {
  it("is BASE64URL(SHA256(ASCII(verifier))), the S256 method (RFC 7636 Appendix B test vector)", async () => {
    await expect(pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).resolves.toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });
});
