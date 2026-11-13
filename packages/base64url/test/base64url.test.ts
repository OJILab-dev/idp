import { describe, expect, it } from "vitest";
import { InvalidBase64urlError, base64urlDecode, base64urlEncode } from "../src/index.js";

// RFC 4648 §10. The alphabets of §4 and §5 agree on these values; the unpadded form drops the "=" (RFC 7515 §2).
const RFC4648_SECTION_10 = [
  { input: "", padded: "" },
  { input: "f", padded: "Zg==" },
  { input: "fo", padded: "Zm8=" },
  { input: "foo", padded: "Zm9v" },
  { input: "foob", padded: "Zm9vYg==" },
  { input: "fooba", padded: "Zm9vYmE=" },
  { input: "foobar", padded: "Zm9vYmFy" },
] as const;

describe("RFC 4648 §10 test vectors, unpadded", () => {
  it.each(RFC4648_SECTION_10)("encodes '$input'", ({ input, padded }) => {
    expect(base64urlEncode(new TextEncoder().encode(input))).toBe(padded.replace(/=+$/, ""));
  });

  it.each(RFC4648_SECTION_10)("decodes the encoding of '$input'", ({ input, padded }) => {
    expect(new TextDecoder().decode(base64urlDecode(padded.replace(/=+$/, "")))).toBe(input);
  });

  it.each(RFC4648_SECTION_10.filter(({ padded }) => padded.endsWith("=")))("rejects the padded '$padded'", ({ padded }) => {
    expect(() => base64urlDecode(padded)).toThrow(InvalidBase64urlError);
  });
});
