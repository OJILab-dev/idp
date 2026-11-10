// A strict parser for the structured fields of the RFC 9421 admin signatures: `Signature-Input`, `Signature`, and
// `Content-Digest` are all Dictionaries (RFC 9421 §4.1, §4.2; RFC 9530 §2), parsed as RFC 9651 §4.2 describes.
// The admin Worker accepts one shape only (docs/design/hosting-modes.md 3.2), so the parser fails rather than
// recovers: a duplicate key, which RFC 9651 resolves by keeping the last value, is an error here, because a runtime
// joins a repeated header into one value and the last-wins rule would silently pick one signature of two.

/** Thrown when a field value is not a valid structured-field Dictionary under the strict rules of this module. */
export class StructuredFieldError extends Error {
  override readonly name = "StructuredFieldError";
}

/** A bare item (RFC 9651 §3.3). Dates and Display Strings are not supported: the profile never uses them. */
export type BareItem =
  | { readonly type: "integer"; readonly value: number }
  | { readonly type: "decimal"; readonly value: number }
  | { readonly type: "string"; readonly value: string }
  | { readonly type: "token"; readonly value: string }
  | { readonly type: "bytes"; readonly value: Uint8Array }
  | { readonly type: "boolean"; readonly value: boolean };

/** Parameters in the order they appeared (RFC 9651 §3.1.2); keys are unique. */
export type Parameters = readonly (readonly [string, BareItem])[];

/** An item with its parameters (RFC 9651 §3.3). */
export type Item = { readonly kind: "item"; readonly value: BareItem; readonly params: Parameters };

/** An inner list with its parameters (RFC 9651 §3.1.1). */
export type InnerList = { readonly kind: "inner-list"; readonly items: readonly Item[]; readonly params: Parameters };

/** A Dictionary's members in the order they appeared (RFC 9651 §3.2); keys are unique. */
export type Dictionary = readonly (readonly [string, Item | InnerList])[];

const KEY_START = /[a-z*]/;
const KEY_CHAR = /[a-z0-9_\-.*]/;
const TOKEN_START = /[A-Za-z*]/;
// tchar (RFC 9110 §5.6.2) plus ":" and "/" (RFC 9651 §3.3.4).
const TOKEN_CHAR = /[!#$%&'*+\-.^_`|~0-9A-Za-z:/]/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

// A cursor over the field value; every parse function advances it or throws.
class Cursor {
  private index = 0;

  constructor(private readonly input: string) {}

  peek(): string {
    return this.input.charAt(this.index);
  }

  next(): string {
    const char = this.input.charAt(this.index);
    this.index += 1;
    return char;
  }

  atEnd(): boolean {
    return this.index >= this.input.length;
  }

  skip(pattern: RegExp): void {
    while (!this.atEnd() && pattern.test(this.peek())) this.index += 1;
  }

  expect(char: string): void {
    if (this.next() !== char) throw new StructuredFieldError(`expected ${JSON.stringify(char)}`);
  }
}

const SP = / /;
const OWS = /[ \t]/;

/**
 * Parses a field value as a structured-field Dictionary (RFC 9651 §4.2, §4.2.2).
 *
 * @param input The field value; a repeated field must already be joined with ", " (as Workers' Headers does).
 * @returns The members in order.
 * @throws {StructuredFieldError} The value is empty, is not a valid Dictionary, repeats a member or parameter key,
 *   or holds a Date or a Display String.
 */
export function parseDictionary(input: string): Dictionary {
  const cursor = new Cursor(input);
  cursor.skip(SP);
  const members: (readonly [string, Item | InnerList])[] = [];
  const seen = new Set<string>();
  while (!cursor.atEnd()) {
    const key = parseKey(cursor);
    if (seen.has(key)) throw new StructuredFieldError(`duplicate dictionary key ${key}`);
    seen.add(key);
    if (cursor.peek() === "=") {
      cursor.next();
      members.push([key, cursor.peek() === "(" ? parseInnerList(cursor) : parseItem(cursor)]);
    } else {
      members.push([key, { kind: "item", value: { type: "boolean", value: true }, params: parseParameters(cursor) }]);
    }
    cursor.skip(OWS);
    if (cursor.atEnd()) break;
    cursor.expect(",");
    cursor.skip(OWS);
    if (cursor.atEnd()) throw new StructuredFieldError("trailing comma");
  }
  // RFC 9651 §4.2 fails an empty Dictionary only when the field is required; every field here is.
  if (members.length === 0) throw new StructuredFieldError("empty dictionary");
  return members;
}

function parseKey(cursor: Cursor): string {
  if (!KEY_START.test(cursor.peek())) throw new StructuredFieldError("invalid key");
  let key = cursor.next();
  while (!cursor.atEnd() && KEY_CHAR.test(cursor.peek())) key += cursor.next();
  return key;
}

function parseInnerList(cursor: Cursor): InnerList {
  cursor.expect("(");
  const items: Item[] = [];
  for (;;) {
    cursor.skip(SP);
    if (cursor.atEnd()) throw new StructuredFieldError("unterminated inner list");
    if (cursor.peek() === ")") {
      cursor.next();
      return { kind: "inner-list", items, params: parseParameters(cursor) };
    }
    items.push(parseItem(cursor));
    if (cursor.peek() !== " " && cursor.peek() !== ")") throw new StructuredFieldError("inner list items need a space");
  }
}

function parseItem(cursor: Cursor): Item {
  const value = parseBareItem(cursor);
  return { kind: "item", value, params: parseParameters(cursor) };
}

function parseParameters(cursor: Cursor): Parameters {
  const params: (readonly [string, BareItem])[] = [];
  const seen = new Set<string>();
  while (cursor.peek() === ";") {
    cursor.next();
    cursor.skip(SP);
    const key = parseKey(cursor);
    if (seen.has(key)) throw new StructuredFieldError(`duplicate parameter key ${key}`);
    seen.add(key);
    let value: BareItem = { type: "boolean", value: true };
    if (cursor.peek() === "=") {
      cursor.next();
      value = parseBareItem(cursor);
    }
    params.push([key, value]);
  }
  return params;
}

function parseBareItem(cursor: Cursor): BareItem {
  const char = cursor.peek();
  if (char === "-" || /[0-9]/.test(char)) return parseNumber(cursor);
  if (char === '"') return parseString(cursor);
  if (TOKEN_START.test(char)) return parseToken(cursor);
  if (char === ":") return parseBytes(cursor);
  if (char === "?") return parseBoolean(cursor);
  throw new StructuredFieldError("unsupported bare item");
}

function parseNumber(cursor: Cursor): BareItem {
  let sign = 1;
  if (cursor.peek() === "-") {
    cursor.next();
    sign = -1;
  }
  let digits = "";
  let decimal = false;
  while (!cursor.atEnd()) {
    const char = cursor.peek();
    if (/[0-9]/.test(char)) {
      digits += cursor.next();
    } else if (char === "." && !decimal) {
      if (digits.length > 12) throw new StructuredFieldError("decimal integer part too long");
      decimal = true;
      digits += cursor.next();
    } else {
      break;
    }
    if (!decimal && digits.length > 15) throw new StructuredFieldError("integer too long");
    if (decimal && digits.length > 16) throw new StructuredFieldError("decimal too long");
  }
  if (digits === "" || digits.startsWith(".")) throw new StructuredFieldError("number without digits");
  if (!decimal) return { type: "integer", value: sign * Number.parseInt(digits, 10) };
  const fraction = digits.slice(digits.indexOf(".") + 1);
  if (fraction.length < 1 || fraction.length > 3) throw new StructuredFieldError("decimal needs 1 to 3 fractional digits");
  return { type: "decimal", value: sign * Number.parseFloat(digits) };
}

function parseString(cursor: Cursor): BareItem {
  cursor.expect('"');
  let value = "";
  for (;;) {
    if (cursor.atEnd()) throw new StructuredFieldError("unterminated string");
    const char = cursor.next();
    if (char === "\\") {
      const escaped = cursor.next();
      if (escaped !== '"' && escaped !== "\\") throw new StructuredFieldError("invalid escape in string");
      value += escaped;
    } else if (char === '"') {
      return { type: "string", value };
    } else {
      const code = char.charCodeAt(0);
      if (code < 0x20 || code > 0x7e) throw new StructuredFieldError("invalid character in string");
      value += char;
    }
  }
}

function parseToken(cursor: Cursor): BareItem {
  let value = cursor.next();
  while (!cursor.atEnd() && TOKEN_CHAR.test(cursor.peek())) value += cursor.next();
  return { type: "token", value };
}

function parseBytes(cursor: Cursor): BareItem {
  cursor.expect(":");
  let encoded = "";
  for (;;) {
    if (cursor.atEnd()) throw new StructuredFieldError("unterminated byte sequence");
    const char = cursor.next();
    if (char === ":") break;
    encoded += char;
  }
  // RFC 9651 §4.2.7 lets a parser accept missing padding; this one requires the canonical form, so a value compared
  // after decoding has exactly one spelling (the same rule as the contract's strict base64url).
  if (!BASE64.test(encoded)) throw new StructuredFieldError("byte sequence is not canonical base64");
  const bytes = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
  if (base64(bytes) !== encoded) throw new StructuredFieldError("byte sequence has non-zero pad bits");
  return { type: "bytes", value: bytes };
}

function parseBoolean(cursor: Cursor): BareItem {
  cursor.expect("?");
  const char = cursor.next();
  if (char === "1") return { type: "boolean", value: true };
  if (char === "0") return { type: "boolean", value: false };
  throw new StructuredFieldError("invalid boolean");
}

function base64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/**
 * Serializes an inner list with its parameters (RFC 9651 §4.1.1.1), the form the `@signature-params` line of the
 * signature base takes (RFC 9421 §2.3).
 *
 * Whitespace the parser allowed is not kept, so the base is the canonical serialization of what was parsed: a signer
 * that signed a non-canonical spelling fails verification, which is the safe side.
 *
 * @param list A parsed inner list.
 * @returns The serialized text.
 */
export function serializeInnerList(list: InnerList): string {
  const items = list.items.map((item) => `${serializeBareItem(item.value)}${serializeParameters(item.params)}`);
  return `(${items.join(" ")})${serializeParameters(list.params)}`;
}

function serializeParameters(params: Parameters): string {
  return params
    .map(([key, value]) => (value.type === "boolean" && value.value ? `;${key}` : `;${key}=${serializeBareItem(value)}`))
    .join("");
}

function serializeBareItem(item: BareItem): string {
  switch (item.type) {
    case "integer":
      return String(item.value);
    case "decimal": {
      // RFC 9651 §4.1.5: round to three fractional digits and drop trailing zeros, keeping at least one digit.
      const [whole, fraction = "0"] = item.value.toFixed(3).split(".");
      return `${whole ?? "0"}.${fraction.replace(/0+$/, "") || "0"}`;
    }
    case "string":
      return `"${item.value.replace(/[\\"]/g, (c) => `\\${c}`)}"`;
    case "token":
      return item.value;
    case "bytes":
      return `:${base64(item.value)}:`;
    case "boolean":
      return item.value ? "?1" : "?0";
  }
}
