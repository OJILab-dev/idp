// Verification of WebAuthn registration (Level 3 §7.1) and authentication (§7.2) responses, limited to what the IdP
// asks for: attestation "none" (the client may still pass packed self attestation, §5.1.3), the three COSE algorithms
// of cose.ts, user verification required, one fixed origin and RP ID, and no extensions. Every step the IdP's options
// make applicable is performed; the step numbers in the comments are those of §7.1 and §7.2.
import { InvalidBase64urlError, base64urlDecode, base64urlEncode } from "@idp/base64url";
import type { Issuer } from "../../shared/index.js";
import { InvalidCborError, decodeCbor, decodeCborPrefix } from "@idp/cbor";
import { InvalidCoseKeyError, importCosePublicKey, verifyCoseSignature } from "@idp/cose-key";

/** Thrown when a response is malformed or fails a verification step; the message names the step for the logs. */
export class WebAuthnVerificationError extends Error {
  override readonly name = "WebAuthnVerificationError";
}

/** The RP the responses must be bound to; both values come from the issuer. */
export type RelyingParty = Pick<Issuer, "rpId" | "origin">;

/** The parts of a `PublicKeyCredential.toJSON()` registration response the IdP reads, decoded. */
export type RegistrationResponse = {
  readonly credentialId: string;
  readonly clientDataJSON: Uint8Array;
  readonly attestationObject: Uint8Array;
};

/** The parts of a `PublicKeyCredential.toJSON()` authentication response the IdP reads, decoded. */
export type AuthenticationResponse = {
  readonly credentialId: string;
  readonly clientDataJSON: Uint8Array;
  readonly authenticatorData: Uint8Array;
  readonly signature: Uint8Array;
  /** `undefined` when the authenticator returned no user handle. */
  readonly userHandle: Uint8Array | undefined;
};

/** A new credential that passed §7.1, ready to store. */
export type VerifiedRegistration = {
  readonly credentialId: string;
  /** The COSE_Key bytes exactly as the authenticator sent them. */
  readonly publicKey: Uint8Array;
  readonly signCount: number;
  readonly backupEligible: boolean;
  readonly backupState: boolean;
};

/** The stored state of the credential an assertion claims to come from. */
export type StoredCredential = {
  readonly publicKey: Uint8Array;
  readonly signCount: number;
  readonly backupEligible: boolean;
  /** The owner's user handle (users.user_handle). */
  readonly userHandle: Uint8Array;
};

/** What an assertion that passed §7.2 changes in the credential record (step 25). */
export type VerifiedAuthentication = {
  readonly signCount: number;
  readonly backupState: boolean;
};

// The authenticator data flags (Level 3 §6.1).
const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_BE = 0x08;
const FLAG_BS = 0x10;
const FLAG_AT = 0x40;
const FLAG_ED = 0x80;

// Bounds on attacker-controlled input before any parsing; real responses are far smaller (an RSA-4096 key and its
// packed self attestation stay under 2 KiB).
const MAX_CLIENT_DATA_BYTES = 4096;
const MAX_ATTESTATION_OBJECT_BYTES = 16384;
const MAX_AUTHENTICATOR_DATA_BYTES = 4096;
const MAX_SIGNATURE_BYTES = 1024;
// §5.4.3: user.id is at most 64 bytes.
const MAX_USER_HANDLE_BYTES = 64;
// §5.1 (rawId) and §6.5.1: a credential ID is at most 1023 bytes.
const MAX_CREDENTIAL_ID_BYTES = 1023;

// §7.1 step 5 and §7.2 step 10 say "UTF-8 decode", which strips a leading BOM (WHATWG Encoding §4.1).
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });

function fail(message: string): never {
  throw new WebAuthnVerificationError(message);
}

function record(value: unknown, what: string): Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail(`${what} is not an object`);
  return value as Readonly<Record<string, unknown>>;
}

function bytesMember(object: Readonly<Record<string, unknown>>, name: string, maxBytes: number): Uint8Array {
  const value = object[name];
  if (typeof value !== "string") fail(`${name} is not a string`);
  let bytes: Uint8Array;
  try {
    bytes = base64urlDecode(value);
  } catch (error) {
    if (error instanceof InvalidBase64urlError) fail(`${name} is not base64url`);
    throw error;
  }
  if (bytes.length === 0 || bytes.length > maxBytes) fail(`${name} has an invalid length`);
  return bytes;
}

// §5.1: id is base64url(rawId); the two must agree, and the type must be public-key.
function credentialEnvelope(value: unknown): { readonly id: string; readonly response: Readonly<Record<string, unknown>> } {
  const credential = record(value, "credential");
  if (credential["type"] !== "public-key") fail("credential type is not public-key");
  const id = credential["id"];
  if (typeof id !== "string" || credential["rawId"] !== id) fail("credential id and rawId differ");
  bytesMember(credential, "id", MAX_CREDENTIAL_ID_BYTES);
  return { id, response: record(credential["response"], "response") };
}

/**
 * Reads a registration response as `PublicKeyCredential.toJSON()` serialises it (Level 3 §5.1).
 *
 * @param value The parsed request body, untrusted.
 * @returns The decoded parts; nothing has been verified yet.
 * @throws {WebAuthnVerificationError} A member is missing, not canonical base64url, or out of its size bound, or
 *   `id` and `rawId` differ, or the type is not `public-key`.
 */
export function parseRegistrationResponse(value: unknown): RegistrationResponse {
  const { id, response } = credentialEnvelope(value);
  return {
    credentialId: id,
    clientDataJSON: bytesMember(response, "clientDataJSON", MAX_CLIENT_DATA_BYTES),
    attestationObject: bytesMember(response, "attestationObject", MAX_ATTESTATION_OBJECT_BYTES),
  };
}

/**
 * Reads an authentication response as `PublicKeyCredential.toJSON()` serialises it (Level 3 §5.1).
 *
 * @param value The parsed request body, untrusted.
 * @returns The decoded parts; nothing has been verified yet.
 * @throws {WebAuthnVerificationError} As {@link parseRegistrationResponse}, for the authentication members; a
 *   `userHandle` of null or absent is allowed.
 */
export function parseAuthenticationResponse(value: unknown): AuthenticationResponse {
  const { id, response } = credentialEnvelope(value);
  const userHandle = response["userHandle"];
  return {
    credentialId: id,
    clientDataJSON: bytesMember(response, "clientDataJSON", MAX_CLIENT_DATA_BYTES),
    authenticatorData: bytesMember(response, "authenticatorData", MAX_AUTHENTICATOR_DATA_BYTES),
    signature: bytesMember(response, "signature", MAX_SIGNATURE_BYTES),
    userHandle: userHandle === undefined || userHandle === null ? undefined : bytesMember(response, "userHandle", MAX_USER_HANDLE_BYTES),
  };
}

/**
 * Reads the challenge a response claims to answer, so the ceremony can look the stored challenge up.
 *
 * The value is untrusted: it only selects a row, and the verification compares it with that row again.
 *
 * @param clientDataJSON The response's client data.
 * @returns The `challenge` member, or `undefined` when the client data is not JSON or has no string challenge.
 */
export function claimedChallenge(clientDataJSON: Uint8Array): string | undefined {
  try {
    const challenge = (JSON.parse(utf8.decode(clientDataJSON)) as Record<string, unknown> | null)?.["challenge"];
    return typeof challenge === "string" ? challenge : undefined;
  } catch {
    return undefined;
  }
}

// §7.1 steps 5 to 11 and §7.2 steps 10 to 14 (collected client data).
function verifyClientData(bytes: Uint8Array, type: "webauthn.create" | "webauthn.get", challenge: string, rp: RelyingParty): void {
  let data: Readonly<Record<string, unknown>>;
  try {
    data = record(JSON.parse(utf8.decode(bytes)), "clientDataJSON");
  } catch (error) {
    if (error instanceof WebAuthnVerificationError) throw error;
    fail("clientDataJSON is not UTF-8 JSON");
  }
  if (data["type"] !== type) fail("clientDataJSON type is wrong");
  if (data["challenge"] !== challenge) fail("clientDataJSON challenge does not match");
  if (data["origin"] !== rp.origin) fail("clientDataJSON origin is not the issuer");
  // The IdP is never embedded in another site's frame (frame-ancestors 'none'), so a cross-origin ceremony is not
  // the IdP's own page; topOrigin only appears in one.
  if (data["crossOrigin"] === true || data["topOrigin"] !== undefined) fail("clientDataJSON is cross-origin");
}

type AuthenticatorData = {
  readonly flags: number;
  readonly signCount: number;
  readonly attested?: { readonly credentialId: Uint8Array; readonly publicKey: Uint8Array };
};

// §6.1 layout. Extensions are not requested, so an ED payload is parsed only to find the end and then ignored.
function parseAuthenticatorData(bytes: Uint8Array): AuthenticatorData {
  if (bytes.length < 37) fail("authenticator data is truncated");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const flags = bytes[32] ?? 0;
  const signCount = view.getUint32(33);
  let offset = 37;
  let attested: AuthenticatorData["attested"];
  try {
    if (flags & FLAG_AT) {
      if (bytes.length < offset + 18) fail("attested credential data is truncated");
      const idLength = view.getUint16(offset + 16);
      const idStart = offset + 18;
      if (idLength === 0 || idLength > MAX_CREDENTIAL_ID_BYTES || bytes.length < idStart + idLength) fail("credential ID is malformed");
      const keyStart = idStart + idLength;
      const { end } = decodeCborPrefix(bytes, keyStart);
      attested = { credentialId: bytes.slice(idStart, keyStart), publicKey: bytes.slice(keyStart, end) };
      offset = end;
    }
    if (flags & FLAG_ED) offset = decodeCborPrefix(bytes, offset).end;
  } catch (error) {
    if (error instanceof InvalidCborError) fail(`authenticator data is malformed: ${error.message}`);
    throw error;
  }
  if (offset !== bytes.length) fail("authenticator data has trailing bytes");
  return attested === undefined ? { flags, signCount } : { flags, signCount, attested };
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

// §7.1 steps 13 to 16 and §7.2 steps 15 to 18: the checks shared by both ceremonies.
async function verifyFlagsAndRpId(data: Uint8Array, flags: number, rp: RelyingParty): Promise<void> {
  if (!equalBytes(data.subarray(0, 32), await sha256(new TextEncoder().encode(rp.rpId)))) fail("rpIdHash is not the RP ID's");
  if (!(flags & FLAG_UP)) fail("user presence flag is not set");
  if (!(flags & FLAG_UV)) fail("user verification flag is not set");
  if (flags & FLAG_BS && !(flags & FLAG_BE)) fail("backup state is set without backup eligibility");
}

/**
 * Verifies a registration response (Level 3 §7.1) against the stored challenge.
 *
 * The caller still has to make sure the credential ID is not registered to anyone (step 26), which it does in the
 * same statement as the insert.
 *
 * @param response The parsed response.
 * @param expected The challenge issued for this ceremony and the RP.
 * @returns The credential to store.
 * @throws {WebAuthnVerificationError} Any step fails: client data type, challenge, origin, or cross-origin; the
 *   attestation object is not CBOR or has a format other than `none` or packed self attestation, or a statement that
 *   does not verify; the RP ID hash differs; UP or UV is not set; BS is set without BE; no attested credential is
 *   present or its ID differs from the response's; or the public key is not an offered COSE algorithm.
 */
export async function verifyRegistration(
  response: RegistrationResponse,
  expected: { readonly challenge: string; readonly rp: RelyingParty },
): Promise<VerifiedRegistration> {
  verifyClientData(response.clientDataJSON, "webauthn.create", expected.challenge, expected.rp);
  let attestation: unknown;
  try {
    attestation = decodeCbor(response.attestationObject);
  } catch (error) {
    if (error instanceof InvalidCborError) fail(`attestation object is not CBOR: ${error.message}`);
    throw error;
  }
  if (!(attestation instanceof Map)) fail("attestation object is not a map");
  const fmt = attestation.get("fmt");
  const authData = attestation.get("authData");
  const attStmt = attestation.get("attStmt");
  if (!(authData instanceof Uint8Array) || !(attStmt instanceof Map)) fail("attestation object members are malformed");
  const data = parseAuthenticatorData(authData);
  await verifyFlagsAndRpId(authData, data.flags, expected.rp);
  if (data.attested === undefined) fail("no attested credential data");
  // Step 27 (rawId): the stored ID must be the one the authenticator bound into the signed data.
  if (base64urlEncode(data.attested.credentialId) !== response.credentialId) fail("credential ID differs from the attested one");
  let key;
  try {
    key = await importCosePublicKey(data.attested.publicKey);
  } catch (error) {
    if (error instanceof InvalidCoseKeyError) fail(`credential public key is not accepted: ${error.message}`);
    throw error;
  }
  // Steps 19 to 22. attestation "none" asks the client to strip attestation; §5.1.3 lets packed self attestation
  // (no x5c) through untouched, and it is verified with the credential key itself. Nothing else is trusted.
  if (fmt === "none") {
    if (attStmt.size !== 0) fail("none attestation has a statement");
  } else if (fmt === "packed") {
    const alg = attStmt.get("alg");
    const sig = attStmt.get("sig");
    if (attStmt.size !== 2 || alg !== key.alg || !(sig instanceof Uint8Array)) fail("packed attestation is not self attestation");
    const signed = concat(authData, await sha256(response.clientDataJSON));
    if (!(await verifyCoseSignature(key, sig, signed))) fail("self attestation signature does not verify");
  } else {
    fail("attestation format is not accepted");
  }
  return {
    credentialId: response.credentialId,
    publicKey: data.attested.publicKey,
    signCount: data.signCount,
    backupEligible: (data.flags & FLAG_BE) !== 0,
    backupState: (data.flags & FLAG_BS) !== 0,
  };
}

/**
 * Verifies an authentication response (Level 3 §7.2) against the stored challenge and credential.
 *
 * The caller has already looked the credential up by the response's ID (step 7) and checks that it belongs to the
 * expected user (steps 5 and 6) through the row it read.
 *
 * @param response The parsed response.
 * @param expected The challenge, the RP, the stored credential, and whether the user handle must be present (it
 *   must when the user was not identified before the ceremony, as in the discoverable sign-in, step 6).
 * @returns The new sign count and backup state to store.
 * @throws {WebAuthnVerificationError} Any step fails: the user handle is missing when required or differs from the
 *   owner's; client data type, challenge, origin, or cross-origin; the RP ID hash; UP or UV; BS without BE; BE
 *   differs from the stored backup eligibility; attested credential data is present; the signature does not verify;
 *   or the sign count did not increase while either the stored or the new count is non-zero (step 23).
 */
export async function verifyAuthentication(
  response: AuthenticationResponse,
  expected: {
    readonly challenge: string;
    readonly rp: RelyingParty;
    readonly credential: StoredCredential;
    readonly userHandleRequired: boolean;
  },
): Promise<VerifiedAuthentication> {
  if (response.userHandle === undefined) {
    if (expected.userHandleRequired) fail("user handle is missing");
  } else if (!equalBytes(response.userHandle, expected.credential.userHandle)) {
    fail("user handle is not the credential owner's");
  }
  verifyClientData(response.clientDataJSON, "webauthn.get", expected.challenge, expected.rp);
  const data = parseAuthenticatorData(response.authenticatorData);
  await verifyFlagsAndRpId(response.authenticatorData, data.flags, expected.rp);
  if (data.attested !== undefined) fail("assertion carries attested credential data");
  // Step 19: backup eligibility is fixed when the credential is created.
  if (((data.flags & FLAG_BE) !== 0) !== expected.credential.backupEligible) fail("backup eligibility changed");
  let key;
  try {
    key = await importCosePublicKey(expected.credential.publicKey);
  } catch (error) {
    if (error instanceof InvalidCoseKeyError) fail(`stored public key is not usable: ${error.message}`);
    throw error;
  }
  const signed = concat(response.authenticatorData, await sha256(response.clientDataJSON));
  if (!(await verifyCoseSignature(key, response.signature, signed))) fail("assertion signature does not verify");
  // Step 23, made a rejection (docs/design/standards-compliance.md): synced passkeys always report 0, so only a
  // counter that is in use on either side has to grow.
  const stored = expected.credential.signCount;
  if ((stored !== 0 || data.signCount !== 0) && data.signCount <= stored) fail("sign count did not increase");
  return { signCount: data.signCount, backupState: (data.flags & FLAG_BS) !== 0 };
}
