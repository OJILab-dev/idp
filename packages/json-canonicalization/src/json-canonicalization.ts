// The JSON Canonicalization Scheme (RFC 8785): one exact text for a JSON value, so equal data hashes and signs the
// same however it was written. Strings and numbers are written the way ECMAScript's JSON.stringify writes them
// (§3.2.2), object members are sorted by the UTF-16 code units of their names (§3.2.3), and there is no whitespace.
// Input must be I-JSON (RFC 7493), so values JSON cannot carry are refused instead of being written approximately.

/** Thrown when a value is not I-JSON: a non-finite number, a lone surrogate, or something that is not JSON at all. */
export class JsonCanonicalizationError extends Error {
  override readonly name = "JsonCanonicalizationError";
}

/**
 * Writes a JSON value in its canonical form (RFC 8785 §3.2). The caller encodes the text as UTF-8 (§3.2.4).
 *
 * @param value null, a boolean, a finite number, a string, an array, or a plain object of these.
 * @returns The canonical JSON text.
 * @throws {JsonCanonicalizationError} The value or something inside it is NaN or infinite, a string or a member name
 *   with a lone surrogate, undefined, or not a JSON type (a function, a bigint, a symbol, or an object that is not a
 *   plain object or an array).
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new JsonCanonicalizationError("a number that is not finite has no JSON form");
    return JSON.stringify(value);
  }
  if (typeof value === "string") return serializeString(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object" && isPlainObject(value)) {
    const names = Object.keys(value).sort(compareCodeUnits);
    const members = names.map((name) => `${serializeString(name)}:${canonicalize((value as Readonly<Record<string, unknown>>)[name])}`);
    return `{${members.join(",")}}`;
  }
  throw new JsonCanonicalizationError(`a ${typeof value} is not a JSON value`);
}

function isPlainObject(value: object): boolean {
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

// JSON.stringify escapes exactly what §3.2.2.2 requires; a lone surrogate would come out escaped, which I-JSON
// forbids (RFC 7493 §2.1), so it is refused first.
function serializeString(value: string): string {
  if (!value.isWellFormed()) throw new JsonCanonicalizationError("a string with a lone surrogate is not I-JSON");
  return JSON.stringify(value);
}

// The relational operators of ECMAScript compare strings by UTF-16 code units, which is the order §3.2.3 requires.
function compareCodeUnits(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
