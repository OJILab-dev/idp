// A software authenticator and client for the tests: it creates credentials and assertions the way a browser and a
// passkey provider would, with WebCrypto keys generated per test run (no private key is committed), and every field
// can be overridden so each verification step has a case that breaks exactly that step.
import { base64urlEncode } from "@idp/base64url";

/** A value the test CBOR encoder can write. */
export type CborInput = number | string | boolean | null | Uint8Array | readonly CborInput[] | ReadonlyMap<number | string, CborInput>;

function head(major: number, value: number): Uint8Array {
  if (value < 24) return new Uint8Array([(major << 5) | value]);
  if (value < 0x100) return new Uint8Array([(major << 5) | 24, value]);
  if (value < 0x10000) return new Uint8Array([(major << 5) | 25, value >> 8, value & 0xff]);
  const out = new Uint8Array(5);
  out[0] = (major << 5) | 26;
  new DataView(out.buffer).setUint32(1, value);
  return out;
}

/** Encodes CBOR with definite lengths, as CTAP2 does. */
export function encodeCbor(value: CborInput): Uint8Array {
  if (typeof value === "number") return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    return concat(head(3, bytes.length), bytes);
  }
  if (typeof value === "boolean") return new Uint8Array([value ? 0xf5 : 0xf4]);
  if (value === null) return new Uint8Array([0xf6]);
  if (value instanceof Uint8Array) return concat(head(2, value.length), value);
  if (Array.isArray(value)) return concat(head(4, value.length), ...value.map(encodeCbor));
  const map = value as ReadonlyMap<number | string, CborInput>;
  return concat(head(5, map.size), ...[...map].flatMap(([k, v]) => [encodeCbor(k), encodeCbor(v)]));
}

/** Concatenates byte strings. */
export function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

/** A COSE algorithm the authenticator can generate keys for; -35 is only for the "not offered" case. */
export type TestAlgorithm = -8 | -7 | -257 | -35;

/** A credential held by the software authenticator. */
export type SoftCredential = {
  readonly id: Uint8Array;
  readonly alg: TestAlgorithm;
  readonly privateKey: CryptoKey;
  /** The COSE_Key the RP stores. */
  readonly cosePublicKey: Uint8Array;
  readonly userHandle: Uint8Array;
  signCount: number;
  backupEligible: boolean;
  backupState: boolean;
};

/** P1363 r || s to DER (WebAuthn §6.5.6). */
export function rawToDer(raw: Uint8Array): Uint8Array {
  function integer(bytes: Uint8Array): Uint8Array {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    let body = bytes.subarray(start);
    if ((body[0] ?? 0) & 0x80) body = concat(new Uint8Array([0]), body);
    return concat(new Uint8Array([0x02, body.length]), body);
  }
  const body = concat(integer(raw.subarray(0, raw.length / 2)), integer(raw.subarray(raw.length / 2)));
  return concat(new Uint8Array([0x30, body.length]), body);
}

/**
 * Generates a credential key pair and its COSE public key.
 *
 * @param alg The COSE algorithm; -35 makes an ES384 key, which the IdP must refuse.
 * @param options The credential ID, user handle, and flags.
 */
export async function generateCredential(
  alg: TestAlgorithm,
  options: { readonly id?: Uint8Array; readonly userHandle?: Uint8Array; readonly backupEligible?: boolean; readonly signCount?: number } = {},
): Promise<SoftCredential> {
  let pair: CryptoKeyPair;
  let cose: Map<number, CborInput>;
  if (alg === -8) {
    pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const x = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
    cose = new Map<number, CborInput>([[1, 1], [3, -8], [-1, 6], [-2, x]]);
  } else if (alg === -7 || alg === -35) {
    const curve = alg === -7 ? "P-256" : "P-384";
    pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: curve }, true, ["sign", "verify"])) as CryptoKeyPair;
    const point = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
    const size = (point.length - 1) / 2;
    cose = new Map<number, CborInput>([[1, 2], [3, alg], [-1, alg === -7 ? 1 : 2], [-2, point.slice(1, 1 + size)], [-3, point.slice(1 + size)]]);
  } else {
    pair = (await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const jwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey;
    cose = new Map<number, CborInput>([
      [1, 3],
      [3, -257],
      [-1, new Uint8Array(Buffer.from(jwk.n ?? "", "base64url"))],
      [-2, new Uint8Array(Buffer.from(jwk.e ?? "", "base64url"))],
    ]);
  }
  return {
    id: options.id ?? crypto.getRandomValues(new Uint8Array(16)),
    alg,
    privateKey: pair.privateKey,
    cosePublicKey: encodeCbor(cose),
    userHandle: options.userHandle ?? crypto.getRandomValues(new Uint8Array(64)),
    signCount: options.signCount ?? 0,
    backupEligible: options.backupEligible ?? true,
    backupState: options.backupEligible ?? true,
  };
}

/** Signs with the credential's algorithm, producing what an authenticator returns. */
export async function signWith(credential: SoftCredential, data: Uint8Array): Promise<Uint8Array> {
  switch (credential.alg) {
    case -8:
      return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, credential.privateKey, data));
    case -7:
      return rawToDer(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, credential.privateKey, data)));
    case -35:
      return rawToDer(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-384" }, credential.privateKey, data)));
    case -257:
      return new Uint8Array(await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, credential.privateKey, data));
  }
}

/** Fields a test can override to break exactly one verification step. */
export type CeremonyOverrides = {
  readonly type?: string;
  readonly challenge?: string;
  readonly origin?: string;
  readonly crossOrigin?: boolean;
  readonly topOrigin?: string;
  readonly rpId?: string;
  /** Replaces the flags byte; by default UP, UV, and the credential's BE and BS are set. */
  readonly flags?: number;
  readonly signCount?: number;
  /** Replaces the clientDataJSON bytes entirely. */
  readonly clientDataJSON?: Uint8Array;
  readonly fmt?: string;
  readonly attStmt?: ReadonlyMap<string, CborInput>;
  /** Signs over different bytes, so the signature does not verify. */
  readonly corruptSignature?: boolean;
  /** `null` drops the user handle from the assertion. */
  readonly userHandle?: Uint8Array | null;
  readonly id?: string;
  readonly rawId?: string;
  readonly extensions?: ReadonlyMap<string, CborInput>;
};

/** The flags for UP, UV, and the credential's backup bits. */
export function defaultFlags(credential: SoftCredential): number {
  return 0x01 | 0x04 | (credential.backupEligible ? 0x08 : 0) | (credential.backupState ? 0x10 : 0);
}

function clientData(type: string, challenge: string, origin: string, o: CeremonyOverrides): Uint8Array {
  if (o.clientDataJSON !== undefined) return o.clientDataJSON;
  const data: Record<string, unknown> = { type: o.type ?? type, challenge: o.challenge ?? challenge, origin: o.origin ?? origin };
  if (o.crossOrigin !== undefined) data["crossOrigin"] = o.crossOrigin;
  if (o.topOrigin !== undefined) data["topOrigin"] = o.topOrigin;
  return new TextEncoder().encode(JSON.stringify(data));
}

async function authenticatorData(credential: SoftCredential, rpId: string, o: CeremonyOverrides, attested: Uint8Array | undefined): Promise<Uint8Array> {
  let flags = o.flags ?? defaultFlags(credential);
  if (attested !== undefined) flags |= 0x40;
  if (o.extensions !== undefined) flags |= 0x80;
  const count = new Uint8Array(4);
  new DataView(count.buffer).setUint32(0, o.signCount ?? credential.signCount);
  return concat(
    await sha256(new TextEncoder().encode(o.rpId ?? rpId)),
    new Uint8Array([flags]),
    count,
    attested ?? new Uint8Array(),
    o.extensions === undefined ? new Uint8Array() : encodeCbor(o.extensions),
  );
}

/** The RP values the authenticator signs for. */
export type TestRp = { readonly rpId: string; readonly origin: string };

/**
 * Creates a registration response for `navigator.credentials.create()`, as `toJSON()` serialises it.
 *
 * @param credential The new credential.
 * @param challenge The challenge from the creation options.
 * @param rp The RP.
 * @param o Overrides; by default the attestation is `none`.
 */
export async function registrationResponse(
  credential: SoftCredential,
  challenge: string,
  rp: TestRp,
  o: CeremonyOverrides = {},
): Promise<Record<string, unknown>> {
  const idLength = new Uint8Array([credential.id.length >> 8, credential.id.length & 0xff]);
  const attested = concat(new Uint8Array(16), idLength, credential.id, credential.cosePublicKey);
  const authData = await authenticatorData(credential, rp.rpId, o, attested);
  const cData = clientData("webauthn.create", challenge, rp.origin, o);
  let attStmt: ReadonlyMap<string, CborInput> = o.attStmt ?? new Map();
  const fmt = o.fmt ?? "none";
  if (fmt === "packed" && o.attStmt === undefined) {
    const signed = concat(authData, o.corruptSignature ? new Uint8Array(32) : await sha256(cData));
    attStmt = new Map<string, CborInput>([["alg", credential.alg], ["sig", await signWith(credential, signed)]]);
  }
  const attestationObject = encodeCbor(new Map<string, CborInput>([["fmt", fmt], ["attStmt", attStmt], ["authData", authData]]));
  const id = o.id ?? base64urlEncode(credential.id);
  return {
    id,
    rawId: o.rawId ?? id,
    type: "public-key",
    response: { clientDataJSON: base64urlEncode(cData), attestationObject: base64urlEncode(attestationObject), transports: ["internal"] },
    authenticatorAttachment: "platform",
    clientExtensionResults: {},
  };
}

/**
 * Creates an authentication response for `navigator.credentials.get()`, as `toJSON()` serialises it, and advances
 * the credential's counter when it is in use.
 *
 * @param credential The credential that signs.
 * @param challenge The challenge from the request options.
 * @param rp The RP.
 * @param o Overrides.
 */
export async function authenticationResponse(
  credential: SoftCredential,
  challenge: string,
  rp: TestRp,
  o: CeremonyOverrides = {},
): Promise<Record<string, unknown>> {
  if (credential.signCount !== 0) credential.signCount += 1;
  const authData = await authenticatorData(credential, rp.rpId, o, undefined);
  const cData = clientData("webauthn.get", challenge, rp.origin, o);
  const signed = concat(authData, o.corruptSignature ? new Uint8Array(32) : await sha256(cData));
  const signature = await signWith(credential, signed);
  const id = o.id ?? base64urlEncode(credential.id);
  const userHandle = o.userHandle === undefined ? credential.userHandle : o.userHandle;
  return {
    id,
    rawId: o.rawId ?? id,
    type: "public-key",
    response: {
      clientDataJSON: base64urlEncode(cData),
      authenticatorData: base64urlEncode(authData),
      signature: base64urlEncode(signature),
      userHandle: userHandle === null ? null : base64urlEncode(userHandle),
    },
    authenticatorAttachment: "platform",
    clientExtensionResults: {},
  };
}
