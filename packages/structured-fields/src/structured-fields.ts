// Structured Field Values for HTTP (RFC 9651): parsing (§4.2) and serialization (§4.1) of Lists, Dictionaries, and
// Items, with every Bare Item type including Dates and Display Strings. The parser follows the RFC exactly, including
// the cases where the RFC tells a parser to recover rather than fail (a repeated key keeps the last value; a Byte
// Sequence may lack "=" padding or have non-zero pad bits). A caller that must be stricter passes `onRecovery` and
// decides for itself what to refuse; the parser never refuses on the caller's behalf.

/** Thrown when a field value does not parse (RFC 9651 §4.2) or a value cannot be serialized (§4.1). */
export class StructuredFieldError extends Error {
  override readonly name = "StructuredFieldError";
}

/** A Bare Item (RFC 9651 §3.3). */
export type BareItem =
  | { readonly type: "integer"; readonly value: number }
  | { readonly type: "decimal"; readonly value: number }
  | { readonly type: "string"; readonly value: string }
  | { readonly type: "token"; readonly value: string }
  | { readonly type: "bytes"; readonly value: Uint8Array }
  | { readonly type: "boolean"; readonly value: boolean }
  /** Seconds since the UNIX epoch (§3.3.7). */
  | { readonly type: "date"; readonly value: number }
  | { readonly type: "display-string"; readonly value: string };

/** Parameters in order (RFC 9651 §3.1.2); a parsed value has unique keys. */
export type Parameters = readonly (readonly [string, BareItem])[];

/** An Item with its Parameters (RFC 9651 §3.3). */
export type Item = { readonly kind: "item"; readonly value: BareItem; readonly params: Parameters };

/** An Inner List with its Parameters (RFC 9651 §3.1.1). */
export type InnerList = { readonly kind: "inner-list"; readonly items: readonly Item[]; readonly params: Parameters };

/** A List (RFC 9651 §3.1). */
export type List = readonly (Item | InnerList)[];

/** A Dictionary's members in order (RFC 9651 §3.2); a parsed value has unique keys. */
export type Dictionary = readonly (readonly [string, Item | InnerList])[];

/** A place where RFC 9651 tells the parser to recover instead of failing. */
export type Recovery =
  /** A Dictionary key appeared again; the later value replaced the earlier one in its position (RFC 9651 §4.2.2). */
  | { readonly kind: "duplicate-dictionary-key"; readonly key: string }
  /** A parameter key appeared again; the later value replaced the earlier one in its position (RFC 9651 §4.2.3.2). */
  | { readonly kind: "duplicate-parameter-key"; readonly key: string }
  /** A Byte Sequence had missing, partial, or extra "=" padding and was decoded anyway (RFC 9651 §4.2.7). */
  | { readonly kind: "base64-padding" }
  /** A Byte Sequence had non-zero bits in its last character and was decoded anyway (RFC 9651 §4.2.7). */
  | { readonly kind: "base64-pad-bits" };

/** Options for the parse functions. */
export type ParseOptions = {
  /** Called for each recovery, in input order; the parse result is the RFC's either way. */
  readonly onRecovery?: (recovery: Recovery) => void;
};

const DIGIT = /[0-9]/;
const ALPHA = /[A-Za-z]/;
const KEY_START = /[a-z*]/;
const KEY_CHAR = /[a-z0-9_\-.*]/;
const KEY = /^[a-z*][a-z0-9_\-.*]*$/;
// tchar (RFC 9110 §5.6.2) plus ":" and "/" (RFC 9651 §3.3.4).
const TOKEN_CHAR = /[!#$%&'*+\-.^_`|~0-9A-Za-z:/]/;
const TOKEN = /^[A-Za-z*][!#$%&'*+\-.^_`|~0-9A-Za-z:/]*$/;
const BASE64_CHARS = /^[A-Za-z0-9+/=]*$/;
const LOWER_HEX = /^[0-9a-f]{2}$/;
const MAX_INTEGER = 999_999_999_999_999;

// ignoreBOM keeps a leading U+FEFF as content, so a Display String keeps every character that was sent.
const utf8Decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const utf8Encoder = new TextEncoder();

function fail(message: string): never {
  throw new StructuredFieldError(message);
}

// A cursor over the field value; every parse function advances it or throws.
class Cursor {
  private index = 0;

  constructor(
    private readonly input: string,
    readonly onRecovery: (recovery: Recovery) => void,
  ) {}

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

  // The rest of the input up to (not including) `char`, consuming it and `char`; undefined when `char` never comes.
  until(char: string): string | undefined {
    const end = this.input.indexOf(char, this.index);
    if (end < 0) return undefined;
    const text = this.input.slice(this.index, end);
    this.index = end + 1;
    return text;
  }
}

const SP = / /;
const OWS = /[ \t]/;

// The steps every field type shares: refuse non-ASCII input, drop the surrounding spaces, parse the value, and
// refuse anything left over (RFC 9651 §4.2).
function parseField<T>(input: string, options: ParseOptions | undefined, parse: (cursor: Cursor) => T): T {
  // Step 1: a field value that is not ASCII fails.
  for (let i = 0; i < input.length; i++) if (input.charCodeAt(i) > 0x7f) fail("field value is not ASCII");
  const cursor = new Cursor(input, options?.onRecovery ?? (() => undefined));
  cursor.skip(SP);
  const value = parse(cursor);
  cursor.skip(SP);
  if (!cursor.atEnd()) fail("unexpected characters after the value");
  return value;
}

/**
 * Parses a field value as a List (RFC 9651 §4.2, §4.2.1).
 *
 * @param input The field value; a field received in several lines must be joined with ", " first.
 * @param options The recovery observer.
 * @returns The members in order; an empty field is an empty List.
 * @throws {StructuredFieldError} The value is not a valid List.
 */
export function parseList(input: string, options?: ParseOptions): List {
  return parseField(input, options, (cursor) => {
    const members: (Item | InnerList)[] = [];
    while (!cursor.atEnd()) {
      members.push(parseItemOrInnerList(cursor));
      if (!afterMember(cursor)) break;
    }
    return members;
  });
}

/**
 * Parses a field value as a Dictionary (RFC 9651 §4.2, §4.2.2).
 *
 * A repeated key keeps the position of its first occurrence and the value of its last, and is reported to
 * `onRecovery` as `duplicate-dictionary-key`.
 *
 * @param input The field value; a field received in several lines must be joined with ", " first.
 * @param options The recovery observer.
 * @returns The members in order; an empty field is an empty Dictionary.
 * @throws {StructuredFieldError} The value is not a valid Dictionary.
 */
export function parseDictionary(input: string, options?: ParseOptions): Dictionary {
  return parseField(input, options, (cursor) => {
    const members = new Map<string, Item | InnerList>();
    while (!cursor.atEnd()) {
      const key = parseKey(cursor);
      let member: Item | InnerList;
      if (cursor.peek() === "=") {
        cursor.next();
        member = parseItemOrInnerList(cursor);
      } else {
        member = { kind: "item", value: { type: "boolean", value: true }, params: parseParameters(cursor) };
      }
      if (members.has(key)) cursor.onRecovery({ kind: "duplicate-dictionary-key", key });
      members.set(key, member);
      if (!afterMember(cursor)) break;
    }
    return [...members];
  });
}

/**
 * Parses a field value as an Item (RFC 9651 §4.2, §4.2.3).
 *
 * @param input The field value.
 * @param options The recovery observer.
 * @returns The Item.
 * @throws {StructuredFieldError} The value is not a valid Item (an empty field included).
 */
export function parseItem(input: string, options?: ParseOptions): Item {
  return parseField(input, options, parseItemAt);
}

// The separator between List or Dictionary members; false when the input ended after the member.
function afterMember(cursor: Cursor): boolean {
  cursor.skip(OWS);
  if (cursor.atEnd()) return false;
  if (cursor.next() !== ",") fail("members are not separated by a comma");
  cursor.skip(OWS);
  if (cursor.atEnd()) fail("trailing comma");
  return true;
}

function parseItemOrInnerList(cursor: Cursor): Item | InnerList {
  return cursor.peek() === "(" ? parseInnerList(cursor) : parseItemAt(cursor);
}

// Reads a parenthesised, space-separated list of items followed by its parameters (RFC 9651 §4.2.1.2).
function parseInnerList(cursor: Cursor): InnerList {
  cursor.next();
  const items: Item[] = [];
  while (!cursor.atEnd()) {
    cursor.skip(SP);
    if (cursor.peek() === ")") {
      cursor.next();
      return { kind: "inner-list", items, params: parseParameters(cursor) };
    }
    items.push(parseItemAt(cursor));
    if (cursor.peek() !== " " && cursor.peek() !== ")") fail("inner list items are not separated by a space");
  }
  fail("unterminated inner list");
}

// Reads one bare item and the parameters attached to it (RFC 9651 §4.2.3).
function parseItemAt(cursor: Cursor): Item {
  const value = parseBareItem(cursor);
  return { kind: "item", value, params: parseParameters(cursor) };
}

// Reads the ";key" or ";key=value" pairs after an item or inner list; a key without a value is true, and a repeated
// key keeps its first position with its last value (RFC 9651 §4.2.3.2).
function parseParameters(cursor: Cursor): Parameters {
  const params = new Map<string, BareItem>();
  while (cursor.peek() === ";") {
    cursor.next();
    cursor.skip(SP);
    const key = parseKey(cursor);
    let value: BareItem = { type: "boolean", value: true };
    if (cursor.peek() === "=") {
      cursor.next();
      value = parseBareItem(cursor);
    }
    if (params.has(key)) cursor.onRecovery({ kind: "duplicate-parameter-key", key });
    params.set(key, value);
  }
  return [...params];
}

// Reads a key: a lowercase letter or "*", then lowercase letters, digits, "_", "-", ".", or "*" (RFC 9651 §4.2.3.3).
function parseKey(cursor: Cursor): string {
  if (!KEY_START.test(cursor.peek())) fail("invalid key");
  let key = cursor.next();
  while (!cursor.atEnd() && KEY_CHAR.test(cursor.peek())) key += cursor.next();
  return key;
}

// Chooses the bare item type from its first character and reads it (RFC 9651 §4.2.3.1).
function parseBareItem(cursor: Cursor): BareItem {
  const char = cursor.peek();
  if (char === "-" || DIGIT.test(char)) return parseNumber(cursor);
  if (char === '"') return parseString(cursor);
  if (ALPHA.test(char) || char === "*") return parseToken(cursor);
  if (char === ":") return parseByteSequence(cursor);
  if (char === "?") return parseBoolean(cursor);
  if (char === "@") return parseDate(cursor);
  if (char === "%") return parseDisplayString(cursor);
  fail("not a bare item");
}

// Reads an Integer of up to 15 digits, or a Decimal of up to 12 integer and 3 fractional digits (RFC 9651 §4.2.4).
function parseNumber(cursor: Cursor): BareItem {
  let sign = 1;
  if (cursor.peek() === "-") {
    cursor.next();
    sign = -1;
  }
  if (!DIGIT.test(cursor.peek())) fail("number without digits");
  let digits = "";
  let decimal = false;
  while (!cursor.atEnd()) {
    const char = cursor.peek();
    if (DIGIT.test(char)) {
      digits += cursor.next();
    } else if (char === "." && !decimal) {
      if (digits.length > 12) fail("decimal integer part is too long");
      decimal = true;
      digits += cursor.next();
    } else {
      break;
    }
    if (!decimal && digits.length > 15) fail("integer is too long");
    if (decimal && digits.length > 16) fail("decimal is too long");
  }
  if (!decimal) return { type: "integer", value: sign * Number.parseInt(digits, 10) };
  const fraction = digits.slice(digits.indexOf(".") + 1);
  if (fraction.length === 0) fail("decimal ends with a dot");
  if (fraction.length > 3) fail("decimal has more than three fractional digits");
  return { type: "decimal", value: sign * Number.parseFloat(digits) };
}

// Reads a double-quoted String of printable ASCII, where only \" and \\ are escapes (RFC 9651 §4.2.5).
function parseString(cursor: Cursor): BareItem {
  cursor.next();
  let value = "";
  while (!cursor.atEnd()) {
    const char = cursor.next();
    if (char === "\\") {
      if (cursor.atEnd()) fail("unterminated escape");
      const escaped = cursor.next();
      if (escaped !== '"' && escaped !== "\\") fail("invalid escape in string");
      value += escaped;
    } else if (char === '"') {
      return { type: "string", value };
    } else {
      const code = char.charCodeAt(0);
      if (code < 0x20 || code > 0x7e) fail("invalid character in string");
      value += char;
    }
  }
  fail("unterminated string");
}

// Reads a Token: a letter or "*", then token characters, ":" or "/" (RFC 9651 §4.2.6).
function parseToken(cursor: Cursor): BareItem {
  let value = cursor.next();
  while (!cursor.atEnd() && TOKEN_CHAR.test(cursor.peek())) value += cursor.next();
  return { type: "token", value };
}

// Reads base64 between colons. Missing or extra "=" padding and non-zero pad bits are accepted, as the RFC asks,
// and reported to the recovery observer (RFC 9651 §4.2.7).
function parseByteSequence(cursor: Cursor): BareItem {
  cursor.next();
  const content = cursor.until(":");
  if (content === undefined) fail("unterminated byte sequence");
  if (!BASE64_CHARS.test(content)) fail("byte sequence has a character outside base64");
  const data = content.replace(/=+$/, "");
  if (data.includes("=") || data.length % 4 === 1) fail("byte sequence is not base64");
  const padding = (4 - (data.length % 4)) % 4;
  if (content.length - data.length !== padding) cursor.onRecovery({ kind: "base64-padding" });
  // atob is WHATWG's forgiving base64, which discards the pad bits; re-encoding shows whether they were zero.
  const bytes = Uint8Array.from(atob(data + "=".repeat(padding)), (c) => c.charCodeAt(0));
  if (base64(bytes) !== data + "=".repeat(padding)) cursor.onRecovery({ kind: "base64-pad-bits" });
  return { type: "bytes", value: bytes };
}

// Reads "?1" as true and "?0" as false (RFC 9651 §4.2.8).
function parseBoolean(cursor: Cursor): BareItem {
  cursor.next();
  const char = cursor.next();
  if (char === "1") return { type: "boolean", value: true };
  if (char === "0") return { type: "boolean", value: false };
  fail("invalid boolean");
}

// Reads "@" followed by an integer number of seconds since the UNIX epoch; a decimal is refused (RFC 9651 §4.2.9).
function parseDate(cursor: Cursor): BareItem {
  cursor.next();
  const number = parseNumber(cursor);
  if (number.type !== "integer") fail("date is not an integer");
  return { type: "date", value: number.value };
}

// Reads %"..." whose non-ASCII text is percent-encoded UTF-8 with lowercase hex, and decodes it to Unicode
// (RFC 9651 §4.2.10).
function parseDisplayString(cursor: Cursor): BareItem {
  cursor.next();
  if (cursor.next() !== '"') fail("display string does not start with %\"");
  const bytes: number[] = [];
  while (!cursor.atEnd()) {
    const char = cursor.next();
    const code = char.charCodeAt(0);
    if (code < 0x20 || code > 0x7e) fail("invalid character in display string");
    if (char === "%") {
      const hex = cursor.next() + cursor.next();
      if (!LOWER_HEX.test(hex)) fail("invalid percent-encoding in display string");
      bytes.push(Number.parseInt(hex, 16));
    } else if (char === '"') {
      try {
        return { type: "display-string", value: utf8Decoder.decode(Uint8Array.from(bytes)) };
      } catch {
        fail("display string is not UTF-8");
      }
    } else {
      bytes.push(code);
    }
  }
  fail("unterminated display string");
}

function base64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/**
 * Serializes a List (RFC 9651 §4.1.1).
 *
 * @param list The members.
 * @returns The field value; empty for an empty List, which means the field is not sent.
 * @throws {StructuredFieldError} A member holds a value that cannot be serialized.
 */
export function serializeList(list: List): string {
  return list.map((member) => (member.kind === "item" ? serializeItem(member) : serializeInnerList(member))).join(", ");
}

/**
 * Serializes a Dictionary (RFC 9651 §4.1.2).
 *
 * @param dictionary The members.
 * @returns The field value; empty for an empty Dictionary, which means the field is not sent.
 * @throws {StructuredFieldError} A key or a member holds a value that cannot be serialized.
 */
export function serializeDictionary(dictionary: Dictionary): string {
  return dictionary
    .map(([key, member]) => {
      const name = serializeKey(key);
      if (member.kind === "item" && member.value.type === "boolean" && member.value.value) return `${name}${serializeParameters(member.params)}`;
      return `${name}=${member.kind === "item" ? serializeItem(member) : serializeInnerList(member)}`;
    })
    .join(", ");
}

/**
 * Serializes an Item (RFC 9651 §4.1.3).
 *
 * @param item The Item.
 * @returns The serialized text.
 * @throws {StructuredFieldError} The value or a parameter cannot be serialized.
 */
export function serializeItem(item: Item): string {
  return `${serializeBareItem(item.value)}${serializeParameters(item.params)}`;
}

/**
 * Serializes an Inner List with its Parameters (RFC 9651 §4.1.1.1), for example the `@signature-params` line of an
 * RFC 9421 signature base (RFC 9421 §2.3).
 *
 * Whitespace the parser allowed is not kept, so the result is the canonical serialization of what was parsed.
 *
 * @param list The Inner List.
 * @returns The serialized text.
 * @throws {StructuredFieldError} An item or a parameter cannot be serialized.
 */
export function serializeInnerList(list: InnerList): string {
  return `(${list.items.map(serializeItem).join(" ")})${serializeParameters(list.params)}`;
}

// Writes each parameter as ";key=value", or ";key" alone when the value is true (RFC 9651 §4.1.1.2).
function serializeParameters(params: Parameters): string {
  return params
    .map(([key, value]) => (value.type === "boolean" && value.value ? `;${serializeKey(key)}` : `;${serializeKey(key)}=${serializeBareItem(value)}`))
    .join("");
}

// Writes a key, refusing one that the parser could not read back (RFC 9651 §4.1.1.3).
function serializeKey(key: string): string {
  if (!KEY.test(key)) fail("key cannot be serialized");
  return key;
}

// Writes a bare item in the textual form of its type (RFC 9651 §4.1.3.1).
function serializeBareItem(item: BareItem): string {
  switch (item.type) {
    case "integer":
      return serializeInteger(item.value);
    case "decimal":
      return serializeDecimal(item.value);
    case "string":
      return serializeString(item.value);
    case "token":
      if (!TOKEN.test(item.value)) fail("token cannot be serialized");
      return item.value;
    case "bytes":
      return `:${base64(item.value)}:`;
    case "boolean":
      return item.value ? "?1" : "?0";
    case "date":
      return `@${serializeInteger(item.value)}`;
    case "display-string":
      return serializeDisplayString(item.value);
  }
}

// Writes an integer, refusing a fraction or more than 15 digits (RFC 9651 §4.1.4).
function serializeInteger(value: number): string {
  if (!Number.isInteger(value) || Math.abs(value) > MAX_INTEGER) fail("integer cannot be serialized");
  return String(value);
}

// Writes a decimal rounded to three fractional digits, ties to even, working on the number's shortest decimal
// representation rather than its binary value; more than 12 integer digits after rounding is refused (RFC 9651 §4.1.5).
function serializeDecimal(value: number): string {
  if (!Number.isFinite(value)) fail("decimal cannot be serialized");
  const [whole, fraction] = decimalDigits(Math.abs(value));
  let integer = BigInt(whole + fraction.slice(0, 3).padEnd(3, "0"));
  const rest = fraction.slice(3);
  const first = rest.charAt(0);
  if (first > "5" || (first === "5" && (/[1-9]/.test(rest.slice(1)) || integer % 2n === 1n))) integer += 1n;
  const digits = integer.toString().padStart(4, "0");
  const integerPart = digits.slice(0, -3);
  if (integerPart.length > 12) fail("decimal cannot be serialized");
  const fractionPart = digits.slice(-3).replace(/0+$/, "") || "0";
  return `${value < 0 ? "-" : ""}${integerPart}.${fractionPart}`;
}

// The digits of a non-negative finite number's shortest round-trip representation, split at the decimal point.
function decimalDigits(value: number): readonly [string, string] {
  const [mantissa = "0", exponent = "0"] = String(value).split("e");
  const [head = "0", tail = ""] = mantissa.split(".");
  const digits = head + tail;
  const point = head.length + Number(exponent);
  if (point <= 0) return ["0", "0".repeat(-point) + digits];
  if (point >= digits.length) return [digits + "0".repeat(point - digits.length), ""];
  return [digits.slice(0, point).replace(/^0+(?=\d)/, ""), digits.slice(point)];
}

// Writes a double-quoted string, escaping \ and ", and refusing characters outside printable ASCII (RFC 9651 §4.1.6).
function serializeString(value: string): string {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) fail("string cannot be serialized");
  }
  return `"${value.replace(/[\\"]/g, (c) => `\\${c}`)}"`;
}

// Writes %"..." with the UTF-8 bytes of "%", '"', and everything outside printable ASCII percent-encoded in lowercase
// hex (RFC 9651 §4.1.11).
function serializeDisplayString(value: string): string {
  let out = '%"';
  for (const byte of utf8Encoder.encode(value)) {
    if (byte === 0x25 || byte === 0x22 || byte < 0x20 || byte > 0x7e) out += `%${byte.toString(16).padStart(2, "0")}`;
    else out += String.fromCharCode(byte);
  }
  return `${out}"`;
}
