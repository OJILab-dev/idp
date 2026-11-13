// The RFC 9421 verification of the admin requests (docs/design/hosting-modes.md 3.2 to 3.8, items 4 to 9). The
// functions are pure apart from WebCrypto: the admin Worker runs the cheaper checks before them (host, rate limit,
// body size) and stores the nonce after them (item 10, the AdminNonceStore port). Every refusal is reported with a
// reason for the Worker log only; the response is the same forbidden body whatever the reason (3.8).
import { InvalidBase64urlError, base64urlDecode } from "@idp/base64url";
import { verifyDigest } from "@idp/digest-fields";
import { selectSignature, signatureBase, verifyEcdsaP384Sha384 } from "@idp/http-message-signatures";
import { StructuredFieldError, type Dictionary, type InnerList, type Item } from "@idp/structured-fields";
import { parseStrictDictionary } from "./strict-dictionary.js";

/** The application tag every admin signature carries (RFC 9421 §2.3, §7.2.7). */
export const ADMIN_SIGNATURE_TAG = "idp-admin";

/** How far `created` may be from the admin Worker's clock, either way, in seconds (docs/design/hosting-modes.md 3.5). */
export const ADMIN_SIGNATURE_WINDOW_SECONDS = 60;

const NONCE_BYTES = 32;
const SHA256_BYTES = 32;
const KEYID = /^[0-9a-f]{64}$/;
const PARAMETERS = ["created", "nonce", "keyid", "tag"] as const;
// The admin API uses these methods only; anything else cannot be a signed admin request.
const METHODS: ReadonlySet<string> = new Set(["GET", "POST", "PUT", "DELETE"]);

/** An allowlisted admin key: a row of `ADMIN_SIGNING_KEYS` with its public key imported for ECDSA P-384 verification. */
export type AdminSigningKey = {
  /** The SHA-256 of the SPKI DER in lowercase hex (docs/design/hosting-modes.md 3.7). */
  readonly keyid: string;
  /** The admin's name, which the audit log records. */
  readonly name: string;
  readonly publicKey: CryptoKey;
};

/** The parts of a received request the signature covers. */
export type AdminSignatureRequest = {
  readonly method: string;
  /** The request URL as the Worker received it; `@target-uri` is this string unchanged (RFC 9421 §2.2.2). */
  readonly url: string;
  /** The received headers; a repeated header is already joined with ", " (as the Fetch standard does). */
  readonly headers: Headers;
  /** The received body bytes, before any JSON parsing; empty for a request without a body. */
  readonly body: Uint8Array;
};

/**
 * Which check refused a request, for the Worker log only (docs/design/hosting-modes.md 3.8):
 * - `malformed`: item 4, a header is missing or not the one accepted structured-field shape;
 * - `profile`: item 5, the covered components or the parameters differ from 3.2;
 * - `unknown-key`: item 6, the keyid is not allowlisted;
 * - `created`: item 7, `created` is outside the window;
 * - `signature`: item 8, the signature does not verify with the allowlisted key (or that key is not P-384);
 * - `content-digest`: item 9, the body's SHA-256 differs from `Content-Digest`.
 */
export type AdminSignatureRefusal = "malformed" | "profile" | "unknown-key" | "created" | "signature" | "content-digest";

/** A request whose signature passed items 4 to 9; the caller still has to store the nonce (item 10). */
export type VerifiedAdminSignature = {
  readonly ok: true;
  readonly admin: { readonly name: string; readonly keyid: string };
  readonly nonce: string;
  /** `created` plus the window, in UNIX seconds: after it, the window alone refuses the nonce. */
  readonly expiresAt: number;
};

/**
 * The outcome of {@link verifyAdminSignature}. A refusal carries the keyid the request claimed once the profile check
 * passed (so it is 64 lowercase hex), for the Worker log only (docs/design/deployment.md, "ログ").
 */
export type AdminSignatureResult =
  | VerifiedAdminSignature
  | { readonly ok: false; readonly reason: AdminSignatureRefusal; readonly keyid?: string };

type Parsed = {
  readonly label: string;
  readonly input: InnerList;
  readonly signature: Uint8Array;
  readonly digest: Uint8Array;
};

type Profile = {
  readonly components: readonly string[];
  readonly created: number;
  readonly nonce: string;
  readonly keyid: string;
};

class Refusal extends Error {
  constructor(readonly reason: AdminSignatureRefusal) {
    super(reason);
  }
}

/**
 * Verifies the RFC 9421 signature of an admin request (docs/design/hosting-modes.md 3.8, items 4 to 9, in order).
 *
 * The checks are, in order: the strict parse of `Signature-Input`, `Signature`, and `Content-Digest`; the covered
 * components and parameters against the fixed profile; the keyid against the allowlist; `created` against the
 * window; the ECDSA P-384 / SHA-384 signature over the RFC 9421 §2.5 base with the allowlisted key; and the body's
 * SHA-256 against `Content-Digest`, compared in constant time. Nothing is written anywhere: a refused request leaves
 * no trace but the returned reason.
 *
 * @param request The received request.
 * @param keys The allowlist, keyed by keyid.
 * @param now The admin Worker's clock in UNIX seconds.
 * @returns The admin and the nonce to store, or the reason for the refusal. Never rejects.
 */
export async function verifyAdminSignature(
  request: AdminSignatureRequest,
  keys: ReadonlyMap<string, AdminSigningKey>,
  now: number,
): Promise<AdminSignatureResult> {
  let claimed: string | undefined;
  try {
    const parsed = parseHeaders(request.headers);
    const profile = checkProfile(parsed.input, request);
    claimed = profile.keyid;
    const key = keys.get(profile.keyid);
    if (key === undefined) throw new Refusal("unknown-key");
    // Written as "not inside" so that a NaN clock, for which every comparison is false, refuses instead of passing.
    if (!Number.isSafeInteger(now) || !(Math.abs(profile.created - now) <= ADMIN_SIGNATURE_WINDOW_SECONDS)) throw new Refusal("created");
    if (!(await verifySignature(key.publicKey, parsed, profile, request))) throw new Refusal("signature");
    if (!(await verifyDigest("sha-256", parsed.digest, request.body))) throw new Refusal("content-digest");
    return {
      ok: true,
      admin: { name: key.name, keyid: key.keyid },
      nonce: profile.nonce,
      expiresAt: profile.created + ADMIN_SIGNATURE_WINDOW_SECONDS,
    };
  } catch (error) {
    if (error instanceof Refusal) return { ok: false, reason: error.reason, ...(claimed === undefined ? {} : { keyid: claimed }) };
    throw error;
  }
}

// Item 4: each field is a Dictionary of exactly the accepted shape.
function parseHeaders(headers: Headers): Parsed {
  const inputs = onlyMember(headers.get("signature-input"));
  const signatures = onlyMember(headers.get("signature"));
  const [label] = only(inputs);
  const [, signature] = only(signatures);
  const [algorithm, digest] = only(onlyMember(headers.get("content-digest")));
  // The same label in both fields, an inner list, and a byte sequence; a label that differs selects nothing.
  const selected = selectSignature(inputs, signatures, label);
  if (selected === undefined) throw new Refusal("malformed");
  // The profile also refuses parameters on the signature, which RFC 9421 never defines.
  bytesOf(signature);
  const digestBytes = bytesOf(digest);
  // sha-256 only, with a 32-byte value (3.4); any other member or algorithm is refused rather than ignored.
  if (algorithm !== "sha-256" || digestBytes.length !== SHA256_BYTES) throw new Refusal("malformed");
  return { label, input: selected.input, signature: selected.signature, digest: digestBytes };
}

// The field parsed under the profile's strict rules, holding exactly one member.
function onlyMember(value: string | null): Dictionary {
  if (value === null) throw new Refusal("malformed");
  let dictionary: Dictionary;
  try {
    dictionary = parseStrictDictionary(value);
  } catch (error) {
    if (error instanceof StructuredFieldError) throw new Refusal("malformed");
    throw error;
  }
  // One signature only (RFC 9421 §7.2.6): a second one would need rules for which to trust.
  if (dictionary.length !== 1) throw new Refusal("malformed");
  return dictionary;
}

function only(dictionary: Dictionary): Dictionary[number] {
  const [member] = dictionary;
  if (member === undefined) throw new Refusal("malformed");
  return member;
}

function bytesOf(member: Item | InnerList): Uint8Array {
  if (member.kind !== "item" || member.value.type !== "bytes" || member.params.length !== 0) throw new Refusal("malformed");
  return member.value.value;
}

/**
 * The covered components the profile requires for a request, in order (docs/design/hosting-modes.md 3.2):
 * `content-type` exactly when the body is non-empty (a POST or PUT without a body sends no Content-Type), and
 * `idempotency-key` exactly when the header is sent.
 */
function expectedComponents(request: AdminSignatureRequest): readonly string[] {
  const components = ["@method", "@target-uri", "@authority", "content-digest"];
  if (request.body.length > 0) components.push("content-type");
  if (request.headers.has("idempotency-key")) components.push("idempotency-key");
  return components;
}

// Item 5: the covered components and the parameters are exactly the profile's.
function checkProfile(input: InnerList, request: AdminSignatureRequest): Profile {
  if (!METHODS.has(request.method)) throw new Refusal("profile");
  const components = input.items.map((item) => {
    if (item.value.type !== "string" || item.params.length !== 0) throw new Refusal("profile");
    return item.value.value;
  });
  const expected = expectedComponents(request);
  if (components.length !== expected.length || components.some((c, i) => c !== expected[i])) throw new Refusal("profile");
  // Exactly created, nonce, keyid, and tag, in any order: alg, expires, and unknown parameters are refused (3.2).
  const params = new Map(input.params);
  if (input.params.length !== PARAMETERS.length || PARAMETERS.some((name) => !params.has(name))) throw new Refusal("profile");
  const created = params.get("created");
  const nonce = params.get("nonce");
  const keyid = params.get("keyid");
  const tag = params.get("tag");
  if (created?.type !== "integer" || created.value < 0) throw new Refusal("profile");
  if (nonce?.type !== "string" || !isNonce(nonce.value)) throw new Refusal("profile");
  if (keyid?.type !== "string" || !KEYID.test(keyid.value)) throw new Refusal("profile");
  if (tag?.type !== "string" || tag.value !== ADMIN_SIGNATURE_TAG) throw new Refusal("profile");
  return { components, created: created.value, nonce: nonce.value, keyid: keyid.value };
}

function isNonce(value: string): boolean {
  try {
    return base64urlDecode(value).length === NONCE_BYTES;
  } catch (error) {
    if (error instanceof InvalidBase64urlError) return false;
    throw error;
  }
}

// Item 8: the base is rebuilt from the received request and verified with the allowlisted key, never re-signed
// (RFC 9421 §2.5, §7.3.5). A key that is not ECDSA P-384 is a configuration error that the configuration check
// reports; here it only refuses.
async function verifySignature(key: CryptoKey, parsed: Parsed, profile: Profile, request: AdminSignatureRequest): Promise<boolean> {
  const base = signatureBase(request, profile.components, parsed.input);
  if (base === undefined) throw new Refusal("malformed");
  return verifyEcdsaP384Sha384(key, parsed.signature, base);
}
