// The verifier's side of HTTP Message Signatures (RFC 9421) for request signatures with ecdsa-p384-sha384: picking
// the signature with a given label out of the parsed `Signature-Input` and `Signature` fields, rebuilding the
// signature base from the received request, and checking the signature with the verifier's own key. The derived
// components supported are `@method`, `@target-uri`, and `@authority`; any other component name is read as a header
// field. Which components and parameters a signature must have is the caller's policy, not this module's.
import type { Dictionary, InnerList } from "@idp/structured-fields";
import { serializeInnerList } from "@idp/structured-fields";

/** The length of an ecdsa-p384-sha384 signature: r and s as 48-byte big-endian integers, concatenated (§3.3.5). */
export const ECDSA_P384_SHA384_SIGNATURE_BYTES = 96;

/** The parts of a received request that a signature base can cover. */
export type SignatureRequest = {
  readonly method: string;
  /** The request URL as received; `@target-uri` is this string unchanged (RFC 9421 §2.2.2). */
  readonly url: string;
  /** The received headers; a repeated header is already joined with ", " (as the Fetch standard does). */
  readonly headers: Headers;
};

/** One signature taken from the `Signature-Input` and `Signature` fields under the same label. */
export type SelectedSignature = {
  /** The covered components and signature parameters (RFC 9421 §4.1). */
  readonly input: InnerList;
  /** The signature bytes (RFC 9421 §4.2). */
  readonly signature: Uint8Array;
};

/**
 * Picks the signature with the given label from both fields, as a verifier does before checking it (RFC 9421 §3.2).
 * The label itself carries no meaning (§7.2.5); it only has to name the same signature in both fields.
 *
 * @param signatureInput The parsed `Signature-Input` field.
 * @param signature The parsed `Signature` field.
 * @param label The label to pick.
 * @returns The signature, or undefined when either field lacks the label, the `Signature-Input` member is not an
 *   inner list, or the `Signature` member is not a byte sequence.
 */
export function selectSignature(signatureInput: Dictionary, signature: Dictionary, label: string): SelectedSignature | undefined {
  const input = signatureInput.find(([key]) => key === label)?.[1];
  const value = signature.find(([key]) => key === label)?.[1];
  if (input?.kind !== "inner-list" || value?.kind !== "item" || value.value.type !== "bytes") return undefined;
  return { input, signature: value.value.value };
}

/**
 * Builds the signature base for the covered components, one `"name": value` line each, ending with the
 * `@signature-params` line (RFC 9421 §2.5).
 *
 * @param request The received request.
 * @param components The covered component names, in the order they are covered.
 * @param input The parsed Signature-Input member, serialized as the `@signature-params` line.
 * @returns The base, or undefined when a covered value cannot be derived (the URL is not absolute, or a covered header
 *   field is absent).
 */
export function signatureBase(request: SignatureRequest, components: readonly string[], input: InnerList): string | undefined {
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

/**
 * Verifies an ecdsa-p384-sha384 signature over a signature base (RFC 9421 §3.3.5). The algorithm comes from the
 * verifier's key, never from the request (§3.2.1, §7.3.4), so a key that is not an ECDSA P-384 public key never
 * verifies anything.
 *
 * @param key The verifier's public key for the signer.
 * @param signature The received signature, r || s.
 * @param base The signature base built from the received request.
 * @returns Whether the signature verifies; a malformed signature or an unsuitable key is false, never an error.
 */
export async function verifyEcdsaP384Sha384(key: CryptoKey, signature: Uint8Array, base: string): Promise<boolean> {
  if (signature.length !== ECDSA_P384_SHA384_SIGNATURE_BYTES) return false;
  const algorithm = key.algorithm as { readonly name?: string; readonly namedCurve?: string };
  if (key.type !== "public" || algorithm.name !== "ECDSA" || algorithm.namedCurve !== "P-384") return false;
  try {
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-384" }, key, new Uint8Array(signature), new TextEncoder().encode(base));
  } catch {
    // A runtime that throws instead of returning false (a malformed point, for example) still means "not verified".
    return false;
  }
}
