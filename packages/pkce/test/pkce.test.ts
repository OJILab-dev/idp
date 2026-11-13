import { describe, expect, it } from "vitest";
import { isCodeVerifier, isS256CodeChallenge, s256CodeChallenge } from "../src/index.js";

// RFC 7636 Appendix B.
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

describe("RFC 7636 Appendix B", () => {
  it("derives the S256 code challenge of the example verifier", async () => {
    expect(await s256CodeChallenge(VERIFIER)).toBe(CHALLENGE);
  });

  it("accepts the example verifier and challenge", () => {
    expect(isCodeVerifier(VERIFIER)).toBe(true);
    expect(isS256CodeChallenge(CHALLENGE)).toBe(true);
  });
});

describe("isCodeVerifier (RFC 7636 §4.1)", () => {
  it.each([
    ["43 unreserved characters", "a".repeat(43), true],
    ["128 unreserved characters", "-._~".repeat(32), true],
    ["42 characters", "a".repeat(42), false],
    ["129 characters", "a".repeat(129), false],
    ["a character outside the unreserved set", `${"a".repeat(42)}+`, false],
  ])("%s: %s", (_name, value, expected) => {
    expect(isCodeVerifier(value)).toBe(expected);
  });
});

describe("isS256CodeChallenge (RFC 7636 §4.2)", () => {
  it.each([
    ["a challenge with padding", `${CHALLENGE}=`],
    ["a challenge of 42 characters", CHALLENGE.slice(1)],
    ["a challenge in the standard base64 alphabet", CHALLENGE.replace("-", "+")],
    ["a challenge whose last character has non-zero pad bits", `${CHALLENGE.slice(0, -1)}N`],
  ])("rejects %s", (_name, value) => {
    expect(isS256CodeChallenge(value)).toBe(false);
  });
});
