// A minimal CBOR encoder (RFC 8949 §3, definite lengths) for building COSE_Key maps in the tests; the package itself
// only decodes.

/** A value the test encoder can write. */
export type CborInput = number | string | Uint8Array | ReadonlyMap<number | string, CborInput>;

function head(major: number, value: number): Uint8Array {
  if (value < 24) return new Uint8Array([(major << 5) | value]);
  if (value < 0x100) return new Uint8Array([(major << 5) | 24, value]);
  if (value < 0x10000) return new Uint8Array([(major << 5) | 25, value >> 8, value & 0xff]);
  const out = new Uint8Array(5);
  out[0] = (major << 5) | 26;
  new DataView(out.buffer).setUint32(1, value);
  return out;
}

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Encodes a value with definite lengths. */
export function encodeCbor(value: CborInput): Uint8Array {
  if (typeof value === "number") return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    return concat(head(3, bytes.length), bytes);
  }
  if (value instanceof Uint8Array) return concat(head(2, value.length), value);
  return concat(head(5, value.size), ...[...value].flatMap(([k, v]) => [encodeCbor(k), encodeCbor(v)]));
}

/** Converts an ECDSA signature from r || s (IEEE P1363) to DER (RFC 3279 §2.2.3), as WebAuthn §6.5.6 sends it. */
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
