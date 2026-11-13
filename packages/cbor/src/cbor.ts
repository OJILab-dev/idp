// The subset of CBOR (RFC 8949) that WebAuthn puts on the wire: the attestation object, the COSE public key, and the
// authenticator extensions. CTAP2 requires definite lengths and no floats or tags in these structures, so anything
// outside that subset is rejected rather than decoded, which keeps the parser small enough to review in full.

/** A decoded CBOR value; maps keep integer and text keys apart and reject duplicates. */
export type CborValue =
  | number
  | string
  | boolean
  | null
  | Uint8Array
  | readonly CborValue[]
  | ReadonlyMap<number | string, CborValue>;

/** Thrown when bytes are not CBOR of the subset WebAuthn uses. */
export class InvalidCborError extends Error {
  override readonly name = "InvalidCborError";
}

// Attestation objects nest a few levels (object → attStmt → x5c array); 16 bounds the recursion on hostile input.
const MAX_DEPTH = 16;

// ignoreBOM keeps a leading U+FEFF as text, so a decoded string always has every byte that was signed.
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * Decodes one CBOR item that must span the whole input.
 *
 * @param bytes The encoded item.
 * @returns The value.
 * @throws {InvalidCborError} The input is truncated, has trailing bytes, or uses an indefinite length, a tag, a float,
 *   `undefined`, a reserved additional-information value, an integer beyond 2^53 - 1, invalid UTF-8, a map key that
 *   is not an integer or text, or a duplicate map key.
 */
export function decodeCbor(bytes: Uint8Array): CborValue {
  const { value, end } = decodeCborPrefix(bytes, 0);
  if (end !== bytes.length) throw new InvalidCborError("trailing bytes after the CBOR item");
  return value;
}

/**
 * Decodes one CBOR item starting at `offset` and reports where it ends, for items embedded in a larger structure
 * (the credential public key inside authenticator data is followed by the extensions).
 *
 * @param bytes The buffer.
 * @param offset Where the item starts.
 * @returns The value and the offset just past it.
 * @throws {InvalidCborError} As {@link decodeCbor}, except that bytes after the item are allowed.
 */
export function decodeCborPrefix(bytes: Uint8Array, offset: number): { readonly value: CborValue; readonly end: number } {
  const reader = { bytes, offset };
  const value = readItem(reader, 0);
  return { value, end: reader.offset };
}

type Reader = { readonly bytes: Uint8Array; offset: number };

function take(reader: Reader, length: number): Uint8Array {
  if (length > reader.bytes.length - reader.offset) throw new InvalidCborError("CBOR item is truncated");
  const out = reader.bytes.subarray(reader.offset, reader.offset + length);
  reader.offset += length;
  return out;
}

function readArgument(reader: Reader, info: number): number {
  if (info < 24) return info;
  const size = { 24: 1, 25: 2, 26: 4, 27: 8 }[info];
  if (size === undefined) throw new InvalidCborError("indefinite length or reserved additional information");
  let value = 0n;
  for (const byte of take(reader, size)) value = (value << 8n) | BigInt(byte);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new InvalidCborError("CBOR integer is too large");
  return Number(value);
}

function readItem(reader: Reader, depth: number): CborValue {
  if (depth > MAX_DEPTH) throw new InvalidCborError("CBOR nesting is too deep");
  const [initial] = take(reader, 1);
  const major = (initial ?? 0) >> 5;
  const info = (initial ?? 0) & 0x1f;
  switch (major) {
    case 0:
      return readArgument(reader, info);
    case 1:
      return -1 - readArgument(reader, info);
    case 2:
      return take(reader, readArgument(reader, info)).slice();
    case 3:
      try {
        return utf8.decode(take(reader, readArgument(reader, info)));
      } catch (error) {
        if (error instanceof InvalidCborError) throw error;
        throw new InvalidCborError("CBOR text is not UTF-8");
      }
    case 4: {
      const length = readArgument(reader, info);
      const items: CborValue[] = [];
      for (let i = 0; i < length; i++) items.push(readItem(reader, depth + 1));
      return items;
    }
    case 5: {
      const length = readArgument(reader, info);
      const map = new Map<number | string, CborValue>();
      for (let i = 0; i < length; i++) {
        const key = readItem(reader, depth + 1);
        if (typeof key !== "number" && typeof key !== "string") throw new InvalidCborError("CBOR map key is not an integer or text");
        if (map.has(key)) throw new InvalidCborError("duplicate CBOR map key");
        map.set(key, readItem(reader, depth + 1));
      }
      return map;
    }
    case 6:
      throw new InvalidCborError("CBOR tags are not used by WebAuthn");
    default:
      if (info === 20) return false;
      if (info === 21) return true;
      if (info === 22) return null;
      throw new InvalidCborError("CBOR simple value or float is not used by WebAuthn");
  }
}
