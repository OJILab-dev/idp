import { describe, expect, it } from "vitest";
import { base64urlDecode } from "@idp/base64url";
import { InvalidCoseKeyError, importCosePublicKey, verifyCoseSignature } from "../src/index.js";
import { encodeCbor, rawToDer, type CborInput } from "./support/cbor-encode.js";

function hex(encoded: string): Uint8Array {
  return Uint8Array.from(encoded.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
}

// RFC 9052 Appendix C.7.1, the public COSE Key Set. The keys carry no alg (RFC 9052 §7.1 makes it optional), while
// this package selects the verification by the key's alg, so each key is tried as given and with alg ES256 (-7).
const RFC9052_C71 = [
  {
    kid: "meriadoc.brandybuck@buckland.example",
    crv: 1,
    x: "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d",
    y: "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c",
  },
  {
    kid: "11",
    crv: 1,
    x: "bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff",
    y: "20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e",
  },
  {
    kid: "bilbo.baggins@hobbiton.example",
    crv: 3,
    x: "0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad",
    y: "01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475",
  },
  {
    kid: "peregrin.took@tuckborough.example",
    crv: 1,
    x: "98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280",
    y: "f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb",
  },
] as const;

function c71Key(key: (typeof RFC9052_C71)[number], alg?: number): Uint8Array {
  const entries: [number, CborInput][] = [[-1, key.crv], [-2, hex(key.x)], [-3, hex(key.y)], [1, 2], [2, new TextEncoder().encode(key.kid)]];
  if (alg !== undefined) entries.push([3, alg]);
  return encodeCbor(new Map(entries));
}

describe("RFC 9052 Appendix C.7.1", () => {
  it.each(RFC9052_C71.filter((key) => key.crv === 1))("imports the P-256 key $kid with alg ES256", async (key) => {
    expect((await importCosePublicKey(c71Key(key, -7))).alg).toBe(-7);
  });

  it.each(RFC9052_C71)("rejects the key $kid without alg", async (key) => {
    await expect(importCosePublicKey(c71Key(key))).rejects.toBeInstanceOf(InvalidCoseKeyError);
  });

  it("rejects the P-521 key under ES256", async () => {
    const [, , p521] = RFC9052_C71;
    await expect(importCosePublicKey(c71Key(p521, -7))).rejects.toBeInstanceOf(InvalidCoseKeyError);
  });
});

describe("COSE keys and signatures", () => {
  it("rejects keys whose type, curve, or coordinates do not match the algorithm", async () => {
    const x = new Uint8Array(32);
    for (const key of [
      new Map<number, CborInput>([[1, 1], [3, -7], [-1, 6], [-2, x]]),
      new Map<number, CborInput>([[1, 2], [3, -7], [-1, 2], [-2, x], [-3, x]]),
      new Map<number, CborInput>([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, new Uint8Array(31)]]),
      new Map<number, CborInput>([[1, 1], [3, -8], [-1, 6], [-2, new Uint8Array(31)]]),
      new Map<number, CborInput>([[1, 3], [3, -257], [-1, new Uint8Array(128).fill(1)], [-2, new Uint8Array([1, 0, 1])]]),
      new Map<number, CborInput>([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, x]]),
    ]) {
      await expect(importCosePublicKey(encodeCbor(key))).rejects.toBeInstanceOf(InvalidCoseKeyError);
    }
    await expect(importCosePublicKey(new Uint8Array([0x00]))).rejects.toBeInstanceOf(InvalidCoseKeyError);
  });

  describe("RSA keys", () => {
    async function rsaModulus(): Promise<Uint8Array> {
      const pair = (await crypto.subtle.generateKey(
        { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
        true,
        ["sign", "verify"],
      )) as CryptoKeyPair;
      const jwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey;
      return base64urlDecode(jwk.n ?? "");
    }

    function rsaKey(n: Uint8Array, e: readonly number[] = [1, 0, 1]): Uint8Array {
      return encodeCbor(new Map<number, CborInput>([[1, 3], [3, -257], [-1, n], [-2, new Uint8Array(e)]]));
    }

    it("accepts a 2048-bit modulus with exponent 65537", async () => {
      expect((await importCosePublicKey(rsaKey(await rsaModulus()))).alg).toBe(-257);
    });

    it("rejects a 256-byte modulus that is only 2041 bits", async () => {
      const short = (await rsaModulus()).slice();
      short[0] = 0x01;
      await expect(importCosePublicKey(rsaKey(short))).rejects.toThrow(/2048 to 4096 bits/);
    });

    it("rejects a modulus above 4096 bits", async () => {
      const long = new Uint8Array(513).fill(0xff);
      await expect(importCosePublicKey(rsaKey(long))).rejects.toThrow(/2048 to 4096 bits/);
    });

    it.each([[[3]], [[1, 0, 3]], [[0, 1, 0, 1]]])("rejects the public exponent %j", async (e) => {
      await expect(importCosePublicKey(rsaKey(await rsaModulus(), e))).rejects.toThrow(/exponent is not 65537/);
    });
  });

  it("accepts only minimal DER for ES256 signatures", async () => {
    const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const point = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
    const cose = encodeCbor(new Map<number, CborInput>([[1, 2], [3, -7], [-1, 1], [-2, point.slice(1, 33)], [-3, point.slice(33)]]));
    const key = await importCosePublicKey(cose);
    const data = new Uint8Array([1, 2, 3]);
    const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, data));
    const der = rawToDer(raw);
    expect(await verifyCoseSignature(key, der, data)).toBe(true);
    expect(await verifyCoseSignature(key, raw, data)).toBe(false);
    // Re-encode r with a superfluous leading zero byte.
    const rLength = der[3] ?? 0;
    const padded = new Uint8Array([0x30, (der[1] ?? 0) + 1, 0x02, rLength + 1, 0x00, ...der.subarray(4)]);
    expect(await verifyCoseSignature(key, padded, data)).toBe(false);
    expect(await verifyCoseSignature(key, new Uint8Array([...der, 0]), data)).toBe(false);
  });
});
