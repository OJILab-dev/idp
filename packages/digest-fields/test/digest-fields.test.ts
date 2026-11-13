import { describe, expect, it } from "vitest";
import { computeDigest, isDigestAlgorithm, verifyDigest } from "../src/index.js";

function base64(encoded: string): Uint8Array {
  return Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
}

const encoder = new TextEncoder();

// RFC 9530 Appendix B: the Content-Digest values of B.1 (the full content), B.2 (empty content, a HEAD response),
// and B.3 (bytes 10 to 18 of the content, a range response).
const APPENDIX_B = [
  { section: "B.1", content: '{"hello": "world"}\n', digest: "RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=" },
  { section: "B.2", content: "", digest: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=" },
  { section: "B.3", content: '"world"}\n', digest: "jjcgBDWNAtbYUXI37CVG3gRuGOAjaaDRGpIUFsdyepQ=" },
] as const;

describe("RFC 9530 Appendix B", () => {
  it.each(APPENDIX_B)("computes the sha-256 Content-Digest of $section", async ({ content, digest }) => {
    expect(await computeDigest("sha-256", encoder.encode(content))).toEqual(base64(digest));
  });

  it.each(APPENDIX_B)("verifies the sha-256 Content-Digest of $section", async ({ content, digest }) => {
    expect(await verifyDigest("sha-256", base64(digest), encoder.encode(content))).toBe(true);
  });
});

describe("verifyDigest", () => {
  it("rejects a digest of other content", async () => {
    const [b1, b2] = APPENDIX_B;
    expect(await verifyDigest("sha-256", base64(b2.digest), encoder.encode(b1.content))).toBe(false);
  });

  it("rejects a digest of the wrong length", async () => {
    const [b1] = APPENDIX_B;
    expect(await verifyDigest("sha-256", base64(b1.digest).subarray(0, 31), encoder.encode(b1.content))).toBe(false);
  });
});

describe("isDigestAlgorithm", () => {
  it.each([
    ["sha-256", true],
    ["sha-512", false],
    ["md5", false],
    ["SHA-256", false],
  ] as const)("%s is %s", (key, expected) => {
    expect(isDigestAlgorithm(key)).toBe(expected);
  });
});
