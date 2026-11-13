// The WebAuthn verifier against responses from the software authenticator. Each check of WebAuthn Level 3 §7.1 and
// §7.2 that the IdP's options make applicable, and each WebAuthn item of docs/design/security-checklist.md, has a
// case that breaks exactly that check.
import { describe, expect, it } from "vitest";
import { base64urlEncode } from "@idp/base64url";
import { decodeCbor } from "@idp/cbor";
import { importCosePublicKey, InvalidCoseKeyError, verifyCoseSignature } from "../src/user/webauthn/cose.js";
import {
  claimedChallenge,
  parseAuthenticationResponse,
  parseRegistrationResponse,
  verifyAuthentication,
  verifyRegistration,
  WebAuthnVerificationError,
  type StoredCredential,
} from "../src/user/webauthn/verify.js";
import {
  authenticationResponse,
  encodeCbor,
  generateCredential,
  rawToDer,
  registrationResponse,
  signWith,
  type CborInput,
  type CeremonyOverrides,
  type SoftCredential,
  type TestAlgorithm,
} from "./webauthn-authenticator.js";

const rp = { rpId: "idp.example.com", origin: "https://idp.example.com" };
const CHALLENGE = base64urlEncode(new Uint8Array(32).fill(7));

async function register(credential: SoftCredential, o: CeremonyOverrides = {}) {
  return verifyRegistration(parseRegistrationResponse(await registrationResponse(credential, CHALLENGE, rp, o)), { challenge: CHALLENGE, rp });
}

function stored(credential: SoftCredential, overrides: Partial<StoredCredential> = {}): StoredCredential {
  return {
    publicKey: credential.cosePublicKey,
    signCount: credential.signCount,
    backupEligible: credential.backupEligible,
    userHandle: credential.userHandle,
    ...overrides,
  };
}

async function authenticate(credential: SoftCredential, o: CeremonyOverrides = {}, record: Partial<StoredCredential> = {}, userHandleRequired = true) {
  const expected = { challenge: CHALLENGE, rp, credential: stored(credential, record), userHandleRequired };
  return verifyAuthentication(parseAuthenticationResponse(await authenticationResponse(credential, CHALLENGE, rp, o)), expected);
}

describe("registration (§7.1)", () => {
  it.each<TestAlgorithm>([-8, -7, -257])("accepts none attestation with COSE algorithm %i", async (alg) => {
    const credential = await generateCredential(alg);
    const verified = await register(credential);
    expect(verified).toEqual({
      credentialId: base64urlEncode(credential.id),
      publicKey: credential.cosePublicKey,
      signCount: 0,
      backupEligible: true,
      backupState: true,
    });
  });

  it("accepts packed self attestation", async () => {
    const credential = await generateCredential(-7);
    expect((await register(credential, { fmt: "packed" })).credentialId).toBe(base64urlEncode(credential.id));
  });

  it("records a device-bound credential's flags", async () => {
    const credential = await generateCredential(-7, { backupEligible: false, signCount: 3 });
    expect(await register(credential)).toMatchObject({ signCount: 3, backupEligible: false, backupState: false });
  });

  it("rejects a public key algorithm other than -8, -7, and -257", async () => {
    await expect(register(await generateCredential(-35))).rejects.toThrow(/not accepted/);
  });

  it.each<[string, CeremonyOverrides]>([
    ["the get type", { type: "webauthn.get" }],
    ["another challenge", { challenge: base64urlEncode(new Uint8Array(32)) }],
    ["another origin", { origin: "https://evil.example.com" }],
    ["a subdomain origin", { origin: "https://sub.idp.example.com" }],
    ["crossOrigin true", { crossOrigin: true }],
    ["a topOrigin", { topOrigin: "https://evil.example.com" }],
    ["another RP ID", { rpId: "example.com" }],
    ["no user presence", { flags: 0x04 }],
    ["no user verification", { flags: 0x01 }],
    ["backup state without backup eligibility", { flags: 0x01 | 0x04 | 0x10 }],
    ["a none statement that is not empty", { attStmt: new Map([["sig", new Uint8Array(1)]]) }],
    [
      "packed attestation with x5c",
      { fmt: "packed", attStmt: new Map<string, CborInput>([["alg", -7], ["sig", new Uint8Array(70)], ["x5c", [new Uint8Array(1)]]]) },
    ],
    ["a packed self signature that does not verify", { fmt: "packed", corruptSignature: true }],
    ["an attestation format the IdP does not accept", { fmt: "fido-u2f" }],
    ["an id that differs from the attested credential ID", { id: base64urlEncode(new Uint8Array(16).fill(9)) }],
    ["clientDataJSON that is not JSON", { clientDataJSON: new TextEncoder().encode("{") }],
  ])("rejects %s", async (_name, overrides) => {
    await expect(register(await generateCredential(-7), overrides)).rejects.toBeInstanceOf(WebAuthnVerificationError);
  });

  it("rejects a packed self attestation whose alg differs from the key's", async () => {
    const credential = await generateCredential(-7);
    const sig = await signWith(credential, new Uint8Array(1));
    await expect(register(credential, { fmt: "packed", attStmt: new Map<string, number | Uint8Array>([["alg", -8], ["sig", sig]]) })).rejects.toThrow(
      /self attestation/,
    );
  });
});

describe("response parsing", () => {
  it("rejects an id that differs from rawId, a wrong type, and non-canonical base64url", async () => {
    const credential = await generateCredential(-8);
    const good = await registrationResponse(credential, CHALLENGE, rp);
    expect(() => parseRegistrationResponse({ ...good, rawId: "AAAA" })).toThrow(WebAuthnVerificationError);
    expect(() => parseRegistrationResponse({ ...good, type: "password" })).toThrow(WebAuthnVerificationError);
    const response = good["response"] as Record<string, string>;
    expect(() => parseRegistrationResponse({ ...good, response: { ...response, clientDataJSON: `${response["clientDataJSON"]}=` } })).toThrow(
      WebAuthnVerificationError,
    );
    expect(() => parseRegistrationResponse(null)).toThrow(WebAuthnVerificationError);
    expect(() => parseAuthenticationResponse({ ...good, response: {} })).toThrow(WebAuthnVerificationError);
  });

  it("bounds the size of each member before decoding it", async () => {
    const good = await registrationResponse(await generateCredential(-8), CHALLENGE, rp);
    const response = { ...(good["response"] as Record<string, string>), clientDataJSON: base64urlEncode(new Uint8Array(4097)) };
    expect(() => parseRegistrationResponse({ ...good, response })).toThrow(/invalid length/);
  });

  it("reads the claimed challenge only from JSON client data", () => {
    expect(claimedChallenge(new TextEncoder().encode(JSON.stringify({ challenge: "abc" })))).toBe("abc");
    expect(claimedChallenge(new TextEncoder().encode("not json"))).toBeUndefined();
    expect(claimedChallenge(new TextEncoder().encode("null"))).toBeUndefined();
    expect(claimedChallenge(new TextEncoder().encode(JSON.stringify({ challenge: 1 })))).toBeUndefined();
  });
});

describe("authentication (§7.2)", () => {
  it.each<TestAlgorithm>([-8, -7, -257])("accepts an assertion with COSE algorithm %i", async (alg) => {
    const credential = await generateCredential(alg);
    expect(await authenticate(credential)).toEqual({ signCount: 0, backupState: true });
  });

  it("accepts and ignores authenticator extensions", async () => {
    const credential = await generateCredential(-8);
    expect(await authenticate(credential, { extensions: new Map([["credProtect", 2]]) })).toEqual({ signCount: 0, backupState: true });
  });

  it.each<[string, CeremonyOverrides]>([
    ["the create type", { type: "webauthn.create" }],
    ["another challenge", { challenge: base64urlEncode(new Uint8Array(32)) }],
    // The client data and flag checks are shared with registration, which covers each of them above.
    ["another origin", { origin: "http://idp.example.com" }],
    ["no user verification", { flags: 0x01 | 0x08 | 0x10 }],
    ["a changed backup eligibility", { flags: 0x01 | 0x04 }],
    ["a signature over other data", { corruptSignature: true }],
  ])("rejects %s", async (_name, overrides) => {
    await expect(authenticate(await generateCredential(-7), overrides)).rejects.toBeInstanceOf(WebAuthnVerificationError);
  });

  it("requires the user handle in a discoverable sign-in and checks it against the owner", async () => {
    const credential = await generateCredential(-8);
    await expect(authenticate(credential, { userHandle: null })).rejects.toThrow(/user handle is missing/);
    await expect(authenticate(credential, { userHandle: new Uint8Array(64) })).rejects.toThrow(/owner/);
    expect(await authenticate(credential, { userHandle: null }, {}, false)).toEqual({ signCount: 0, backupState: true });
  });

  it("verifies with the stored key, not one the response could supply", async () => {
    const credential = await generateCredential(-8);
    const other = await generateCredential(-8);
    await expect(authenticate(credential, {}, { publicKey: other.cosePublicKey })).rejects.toThrow(/signature/);
  });

  it("rejects a sign count that did not increase unless both counts are 0", async () => {
    const credential = await generateCredential(-7, { signCount: 5 });
    // The authenticator moves to 6; the record says 5.
    expect(await authenticate(credential, {}, { signCount: 5 })).toEqual({ signCount: 6, backupState: true });
    await expect(authenticate(credential, { signCount: 6 }, { signCount: 6 })).rejects.toThrow(/sign count/);
    await expect(authenticate(credential, { signCount: 3 }, { signCount: 6 })).rejects.toThrow(/sign count/);
    await expect(authenticate(credential, { signCount: 0 }, { signCount: 6 })).rejects.toThrow(/sign count/);
    const synced = await generateCredential(-8);
    expect((await authenticate(synced, {}, { signCount: 0 })).signCount).toBe(0);
  });

  it("rejects the ED flag with no extension bytes after it", async () => {
    const credential = await generateCredential(-8);
    await expect(authenticate(credential, { flags: 0x01 | 0x04 | 0x08 | 0x10 | 0x80 })).rejects.toThrow(/authenticator data is malformed/);
  });

  it("rejects authenticator data with trailing bytes or attested credential data", async () => {
    const credential = await generateCredential(-8);
    const response = await authenticationResponse(credential, CHALLENGE, rp);
    const body = response["response"] as Record<string, string>;
    const authData = Buffer.from(body["authenticatorData"] ?? "", "base64url");
    for (const tampered of [Buffer.concat([authData, Buffer.from([0])]), Buffer.concat([authData.subarray(0, 32), Buffer.from([0x45]), authData.subarray(33)])]) {
      const parsed = parseAuthenticationResponse({ ...response, response: { ...body, authenticatorData: tampered.toString("base64url") } });
      await expect(verifyAuthentication(parsed, { challenge: CHALLENGE, rp, credential: stored(credential), userHandleRequired: true })).rejects.toThrow(
        WebAuthnVerificationError,
      );
    }
  });
});

describe("the software authenticator's CBOR", () => {
  // The test encoder must produce what the decoder reads, or the ceremony tests above would test the encoder.
  it("round-trips the values WebAuthn uses", () => {
    const value = new Map<number | string, unknown>([[1, -7], ["a", [true, false, null, "x", new Uint8Array([1, 2])]], [-300, 70000]]);
    expect(decodeCbor(encodeCbor(value as never))).toEqual(value);
  });
});

describe("COSE keys and signatures", () => {
  it("rejects keys whose type, curve, or coordinates do not match the algorithm", async () => {
    const x = new Uint8Array(32);
    for (const key of [
      new Map<number, unknown>([[1, 1], [3, -7], [-1, 6], [-2, x]]),
      new Map<number, unknown>([[1, 2], [3, -7], [-1, 2], [-2, x], [-3, x]]),
      new Map<number, unknown>([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, new Uint8Array(31)]]),
      new Map<number, unknown>([[1, 1], [3, -8], [-1, 6], [-2, new Uint8Array(31)]]),
      new Map<number, unknown>([[1, 3], [3, -257], [-1, new Uint8Array(128).fill(1)], [-2, new Uint8Array([1, 0, 1])]]),
      new Map<number, unknown>([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, x]]),
    ]) {
      await expect(importCosePublicKey(encodeCbor(key as never))).rejects.toBeInstanceOf(InvalidCoseKeyError);
    }
    await expect(importCosePublicKey(new Uint8Array([0x00]))).rejects.toBeInstanceOf(InvalidCoseKeyError);
  });

  describe("RSA keys", () => {
    async function rsaParts(): Promise<{ readonly n: Uint8Array }> {
      const credential = await generateCredential(-257);
      const map = decodeCbor(credential.cosePublicKey) as ReadonlyMap<number, Uint8Array>;
      return { n: map.get(-1) ?? new Uint8Array() };
    }

    function rsaKey(n: Uint8Array, e: readonly number[] = [1, 0, 1]): Uint8Array {
      return encodeCbor(new Map<number, CborInput>([[1, 3], [3, -257], [-1, n], [-2, new Uint8Array(e)]]));
    }

    it("accepts a 2048-bit modulus with exponent 65537", async () => {
      const { n } = await rsaParts();
      expect((await importCosePublicKey(rsaKey(n))).alg).toBe(-257);
    });

    it("rejects a 256-byte modulus that is only 2041 bits", async () => {
      const { n } = await rsaParts();
      const short = n.slice();
      short[0] = 0x01;
      await expect(importCosePublicKey(rsaKey(short))).rejects.toThrow(/2048 to 4096 bits/);
    });

    it("rejects a modulus above 4096 bits", async () => {
      const long = new Uint8Array(513).fill(0xff);
      await expect(importCosePublicKey(rsaKey(long))).rejects.toThrow(/2048 to 4096 bits/);
    });

    it.each([[[3]], [[1, 0, 3]], [[0, 1, 0, 1]]])("rejects the public exponent %j", async (e) => {
      const { n } = await rsaParts();
      await expect(importCosePublicKey(rsaKey(n, e))).rejects.toThrow(/exponent is not 65537/);
    });
  });

  it("accepts only minimal DER for ES256 signatures", async () => {
    const credential = await generateCredential(-7);
    const key = await importCosePublicKey(credential.cosePublicKey);
    const data = new Uint8Array([1, 2, 3]);
    const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, credential.privateKey, data));
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
