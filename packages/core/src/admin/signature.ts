// The RFC 9421 verification of the admin requests (docs/design/hosting-modes.md 3.2 to 3.8, items 4 to 9). The
// functions are pure apart from WebCrypto: the admin Worker runs the cheaper checks before them (host, rate limit,
// body size) and stores the nonce after them (item 10, the AdminNonceStore port). Every refusal is reported with a
// reason for the Worker log only; the response is the same forbidden body whatever the reason (3.8).
import { InvalidBase64urlError, base64urlDecode } from "@idp/base64url";
import { StructuredFieldError, serializeInnerList, type Dictionary, type InnerList, type Item } from "@idp/structured-fields";
import { parseStrictDictionary } from "./strict-dictionary.js";

/** The application tag every admin signature carries (RFC 9421 §2.3, §7.2.7). */
export const ADMIN_SIGNATURE_TAG = "idp-admin";

/** How far `created` may be from the admin Worker's clock, either way, in seconds (docs/design/hosting-modes.md 3.5). */
export const ADMIN_SIGNATURE_WINDOW_SECONDS = 60;

/** The length of an ECDSA P-384 signature: r and s as 48-byte big-endian integers, concatenated (RFC 9421 §3.3.5). */
export const ADMIN_SIGNATURE_BYTES = 96;

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
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", request.body));
    if (!constantTimeEqual(digest, parsed.digest)) throw new Refusal("content-digest");
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
  const [label, input] = onlyMember(headers.get("signature-input"));
  const [signatureLabel, signature] = onlyMember(headers.get("signature"));
  const [algorithm, digest] = onlyMember(headers.get("content-digest"));
  // The label carries no meaning (RFC 9421 §7.2.5); it only has to name the same signature in both fields.
  if (label !== signatureLabel) throw new Refusal("malformed");
  if (input.kind !== "inner-list") throw new Refusal("malformed");
  const signatureBytes = bytesOf(signature);
  const digestBytes = bytesOf(digest);
  // sha-256 only, with a 32-byte value (3.4); any other member or algorithm is refused rather than ignored.
  if (algorithm !== "sha-256" || digestBytes.length !== SHA256_BYTES) throw new Refusal("malformed");
  return { label, input, signature: signatureBytes, digest: digestBytes };
}

function onlyMember(value: string | null): Dictionary[number] {
  if (value === null) throw new Refusal("malformed");
  let dictionary: Dictionary;
  try {
    dictionary = parseStrictDictionary(value);
  } catch (error) {
    if (error instanceof StructuredFieldError) throw new Refusal("malformed");
    throw error;
  }
  // One signature only (RFC 9421 §7.2.6): a second one would need rules for which to trust.
  const [member] = dictionary;
  if (dictionary.length !== 1 || member === undefined) throw new Refusal("malformed");
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

/**
 * Builds the signature base of RFC 9421 §2.5 for the profile's components.
 *
 * @param request The received request.
 * @param components The covered components, already checked against the profile.
 * @param input The parsed Signature-Input member, serialized as the `@signature-params` line.
 * @returns The base, or undefined when a covered value cannot be derived (the URL is not absolute).
 */
export function signatureBase(request: AdminSignatureRequest, components: readonly string[], input: InnerList): string | undefined {
  let authority: string;
  try {
    // URL lowercases the host and drops the scheme's default port, which is what @authority requires (§2.2.3).
    authority = new URL(request.url).host;
  } catch {
    return undefined;
  }
  const lines: string[] = [];
  for (const component of components) {
    let value: string | null;
    if (component === "@method") value = request.method;
    else if (component === "@target-uri") value = request.url;
    else if (component === "@authority") value = authority;
    // Headers.get trims and joins repeated fields with ", ", the header value rules of §2.1.
    else value = request.headers.get(component);
    if (value === null) return undefined;
    lines.push(`"${component}": ${value}`);
  }
  lines.push(`"@signature-params": ${serializeInnerList(input)}`);
  return lines.join("\n");
}

// Item 8: the base is built from the request (§2.5) and verified with the allowlisted key, never re-signed (§7.3.5).
async function verifySignature(key: CryptoKey, parsed: Parsed, profile: Profile, request: AdminSignatureRequest): Promise<boolean> {
  const base = signatureBase(request, profile.components, parsed.input);
  if (base === undefined) throw new Refusal("malformed");
  if (parsed.signature.length !== ADMIN_SIGNATURE_BYTES) return false;
  // The algorithm comes from the key, not the request (§3.2.1, §7.3.4); a key of another kind is a configuration
  // error that the configuration check reports, and here it only refuses.
  const algorithm = key.algorithm as { readonly name?: string; readonly namedCurve?: string };
  if (key.type !== "public" || algorithm.name !== "ECDSA" || algorithm.namedCurve !== "P-384") return false;
  try {
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-384" }, key, parsed.signature, new TextEncoder().encode(base));
  } catch {
    // A runtime that throws instead of returning false (a malformed point, for example) still means "not verified".
    return false;
  }
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i += 1) difference |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return difference === 0;
}
