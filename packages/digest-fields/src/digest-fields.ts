// Integrity digests of HTTP message content (RFC 9530). A `Content-Digest` field is a structured-field Dictionary
// whose keys name hash algorithms and whose values are the digests as Byte Sequences (RFC 9530 §2); parsing the field
// itself is the job of an RFC 9651 parser. This module knows what the algorithm keys mean, computes the digest of
// some content, and compares a received digest with it without leaking where they differ.

const ALGORITHMS = {
  // The only algorithm supported here: SHA-256 (RFC 9530 §5, registered as "sha-256", status Active).
  "sha-256": "SHA-256",
} as const;

/** A digest algorithm key this module computes, as registered in the Hash Algorithms for HTTP Digest Fields registry. */
export type DigestAlgorithm = keyof typeof ALGORITHMS;

/**
 * Tells whether a `Content-Digest` member key names an algorithm this module computes.
 *
 * @param key The Dictionary key, compared exactly (keys are lowercase in RFC 9651).
 * @returns True for `sha-256`.
 */
export function isDigestAlgorithm(key: string): key is DigestAlgorithm {
  return Object.hasOwn(ALGORITHMS, key);
}

/**
 * Computes the digest of content, the value a sender puts in `Content-Digest` (RFC 9530 §2).
 *
 * @param algorithm The algorithm key.
 * @param content The content bytes exactly as sent, before any parsing.
 * @returns The digest bytes.
 */
export async function computeDigest(algorithm: DigestAlgorithm, content: Uint8Array): Promise<Uint8Array> {
  // Web Crypto takes a view over an ArrayBuffer; a copy also accepts a view over a SharedArrayBuffer.
  return new Uint8Array(await crypto.subtle.digest(ALGORITHMS[algorithm], new Uint8Array(content)));
}

/**
 * Checks a received digest against the content, comparing in constant time so the time taken does not reveal how
 * many leading bytes matched.
 *
 * @param algorithm The algorithm key the digest was received under.
 * @param expected The received digest bytes.
 * @param content The content bytes exactly as received.
 * @returns Whether the digest is the content's; a digest of the wrong length is false, never an error.
 */
export async function verifyDigest(algorithm: DigestAlgorithm, expected: Uint8Array, content: Uint8Array): Promise<boolean> {
  return constantTimeEqual(await computeDigest(algorithm, content), expected);
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i += 1) difference |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return difference === 0;
}
