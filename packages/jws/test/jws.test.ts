import { createPublicKey, verify as nodeVerify } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { base64urlDecode, base64urlEncode } from "@idp/base64url";
import {
  InvalidJwsError,
  createJwsSignature,
  signJwt,
  verifyJws,
  type JwsAlgorithm,
  type JwsSigningKey,
  type JwsVerificationKey,
} from "../src/index.js";

const encoder = new TextEncoder();

function encodeJson(value: unknown): string {
  return base64urlEncode(encoder.encode(JSON.stringify(value)));
}

function decodeJson(segment: string): unknown {
  return JSON.parse(new TextDecoder().decode(base64urlDecode(segment)));
}

type TestKey = JwsSigningKey & JwsVerificationKey & { readonly publicJwk: JsonWebKey };

async function generateKey(alg: JwsAlgorithm, kid: string): Promise<TestKey> {
  const params =
    alg === "Ed25519"
      ? { name: "Ed25519" }
      : { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
  const pair = (await crypto.subtle.generateKey(params, true, ["sign", "verify"])) as CryptoKeyPair;
  const publicJwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey;
  return { kid, alg, privateKey: pair.privateKey, publicKey: pair.publicKey, publicJwk };
}

async function importPrivateJwk(jwk: JsonWebKey, alg: JwsAlgorithm): Promise<JwsSigningKey> {
  const params = alg === "Ed25519" ? { name: "Ed25519" } : { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  return { kid: "rfc", alg, privateKey: await crypto.subtle.importKey("jwk", jwk, params, false, ["sign"]) };
}

describe("RFC test vectors", () => {
  it("reproduces the Ed25519 signature of RFC 8037 Appendix A.4", async () => {
    const key = await importPrivateJwk(
      { kty: "OKP", crv: "Ed25519", d: "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" },
      "Ed25519",
    );
    expect(await createJwsSignature(key, "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc")).toBe(
      "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg",
    );
  });

  it("reproduces the RS256 signature of RFC 7515 Appendix A.2", async () => {
    const key = await importPrivateJwk(
      {
        kty: "RSA",
        n: "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
        e: "AQAB",
        d: "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
        p: "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
        q: "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
        dp: "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
        dq: "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
        qi: "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U",
      },
      "RS256",
    );
    const signingInput =
      "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
    expect(await createJwsSignature(key, signingInput)).toBe(
      "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw",
    );
  });
});

let keys: readonly [TestKey, TestKey, TestKey];

beforeAll(async () => {
  keys = [await generateKey("Ed25519", "ed-current"), await generateKey("Ed25519", "ed-previous"), await generateKey("RS256", "rsa")];
}, 60_000);

// Signs an arbitrary header and payload with one of the keys, to build tokens the profile would never issue.
async function forge(header: unknown, payload: unknown, keyIndex: 0 | 1 | 2 = 0): Promise<string> {
  const signingInput = `${encodeJson(header)}.${encodeJson(payload)}`;
  return `${signingInput}.${await createJwsSignature(keys[keyIndex], signingInput)}`;
}

describe("signJwt", () => {
  it.each([
    ["Ed25519", 0, "JWT"],
    ["RS256", 2, "JWT"],
    ["Ed25519", 0, "at+jwt"],
  ] as const)("signs with %s and typ %s in a form node:crypto verifies", async (alg, index, typ) => {
    const key = keys[index];
    const token = await signJwt(key, typ, { sub: "s" });
    const [header, payload, signature] = token.split(".") as [string, string, string];
    expect(decodeJson(header)).toEqual({ alg, kid: key.kid, typ });
    expect(decodeJson(payload)).toEqual({ sub: "s" });
    // An independent implementation (OpenSSL through node:crypto) must accept the signature.
    const publicKey = createPublicKey({ key: key.publicJwk, format: "jwk" });
    const data = Buffer.from(`${header}.${payload}`);
    const ok = nodeVerify(alg === "RS256" ? "sha256" : null, data, publicKey, base64urlDecode(signature));
    expect(ok).toBe(true);
  });
});

describe("verifyJws", () => {
  const both = { algorithms: ["Ed25519", "RS256"], typ: "JWT" } as const;

  it("returns the header and payload of a valid token", async () => {
    const token = await signJwt(keys[1], "JWT", { sub: "s" });
    expect(await verifyJws(token, { ...both, keys })).toEqual({
      header: { alg: "Ed25519", kid: keys[1].kid, typ: "JWT" },
      payload: { sub: "s" },
    });
  });

  it("accepts RS256 when allowed", async () => {
    const token = await signJwt(keys[2], "JWT", { sub: "s" });
    await expect(verifyJws(token, { ...both, keys })).resolves.toMatchObject({ payload: { sub: "s" } });
  });

  async function rejects(token: string | Promise<string>, options: Partial<Parameters<typeof verifyJws>[1]> = {}) {
    await expect(verifyJws(await token, { ...both, keys, ...options })).rejects.toThrow(InvalidJwsError);
  }

  it("rejects RS256 when only Ed25519 is allowed", async () => {
    await rejects(signJwt(keys[2], "JWT", {}), { algorithms: ["Ed25519"] });
  });

  it("rejects alg none", async () => {
    await rejects(`${encodeJson({ alg: "none", kid: keys[0].kid, typ: "JWT" })}.${encodeJson({})}.`);
  });

  it("rejects alg EdDSA even with a valid Ed25519 signature", async () => {
    await rejects(forge({ alg: "EdDSA", kid: keys[0].kid, typ: "JWT" }, {}));
  });

  it.each(["HS256", "ed25519"])("rejects alg %s", async (alg) => {
    await rejects(forge({ alg, kid: keys[0].kid, typ: "JWT" }, {}));
  });

  it("rejects RS256 in the header with an Ed25519 kid (alg bound to the key type)", async () => {
    await rejects(forge({ alg: "RS256", kid: keys[0].kid, typ: "JWT" }, {}, 2));
  });

  it("rejects Ed25519 in the header with an RSA kid", async () => {
    await rejects(forge({ alg: "Ed25519", kid: keys[2].kid, typ: "JWT" }, {}, 0));
  });

  it("rejects a kid not in the key set", async () => {
    await rejects(signJwt(await generateKey("Ed25519", "other"), "JWT", {}));
  });

  it.each([
    ["at+jwt", "JWT"],
    ["JWT", "at+jwt"],
  ] as const)("rejects typ %s where %s is expected", async (actual, expected) => {
    await rejects(signJwt(keys[0], actual, {}), { typ: expected });
  });

  it.each(["jwt", "application/at+jwt"])("rejects typ %s where at+jwt is expected", async (typ) => {
    await rejects(forge({ alg: "Ed25519", kid: keys[0].kid, typ }, {}), { typ: "at+jwt" });
  });

  it.each([
    ["crit", { crit: ["exp"] }],
    ["jwk", { jwk: { kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" } }],
  ])("rejects a header with %s", async (_name, extra) => {
    await rejects(forge({ alg: "Ed25519", kid: keys[0].kid, typ: "JWT", ...extra }, {}));
  });

  it("rejects a tampered payload", async () => {
    const [header, , signature] = (await signJwt(keys[0], "JWT", { sub: "a" })).split(".");
    await rejects(`${header}.${encodeJson({ sub: "b" })}.${signature}`);
  });

  it("rejects a signature by another key with the same kid", async () => {
    const other = await generateKey("Ed25519", keys[0].kid);
    const signingInput = `${encodeJson({ alg: "Ed25519", kid: keys[0].kid, typ: "JWT" })}.${encodeJson({})}`;
    await rejects(`${signingInput}.${await createJwsSignature(other, signingInput)}`);
  });

  it.each([
    ["two segments", "a.b"],
    ["padding in a segment", "eyJhbGciOiJFZDI1NTE5In0=.e30.AA"],
    ["a header that is not JSON", `${base64urlEncode(encoder.encode("{"))}.e30.AA`],
    ["a header that is an array", `${encodeJson([])}.e30.AA`],
  ])("rejects %s", async (_name, token) => {
    await rejects(token);
  });

  it("rejects a payload that is not an object", async () => {
    await rejects(forge({ alg: "Ed25519", kid: keys[0].kid, typ: "JWT" }, ["sub"]));
  });

  it("rejects an oversized token before parsing it", async () => {
    await rejects(forge({ alg: "Ed25519", kid: keys[0].kid, typ: "JWT" }, { pad: "x".repeat(20_000) }));
  });
});
