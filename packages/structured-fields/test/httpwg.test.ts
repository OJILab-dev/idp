// The HTTP WG structured-field-tests (https://github.com/httpwg/structured-field-tests), copied into ./httpwg at
// commit 10781e4a59c387853c900cc06cdd8a3fd7ae4134 with their LICENSE.md. The format is described in that
// repository's README: every parse case must parse to `expected` (or fail when `must_fail`; failing is allowed when
// `can_fail`) and serialize back to `canonical` (or `raw`), and every serialisation case must serialize `expected`
// to `canonical` (or fail when `must_fail`).
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  parseDictionary,
  parseItem,
  parseList,
  serializeDictionary,
  serializeItem,
  serializeList,
  type BareItem,
  type Dictionary,
  type InnerList,
  type Item,
  type List,
  type Parameters,
} from "../src/index.js";

type HeaderType = "item" | "list" | "dictionary";

type TestCase = {
  readonly name: string;
  readonly raw?: readonly string[];
  readonly header_type: HeaderType;
  readonly expected?: unknown;
  readonly must_fail?: boolean;
  readonly can_fail?: boolean;
  readonly canonical?: readonly string[];
};

// A JSON number written with a fraction or an exponent is a Decimal; the reviver keeps that distinction, which
// JSON.parse alone loses (1.0 and 1 are the same double).
type DecimalMarker = { readonly decimal: number };

const DIRECTORY = join(import.meta.dirname, "httpwg");

function load(path: string): readonly TestCase[] {
  return JSON.parse(readFileSync(path, "utf8"), (_key, value: unknown, context?: { readonly source?: string }) =>
    typeof value === "number" && /[.eE]/.test(context?.source ?? "") ? { decimal: value } : value,
  ) as readonly TestCase[];
}

function files(directory: string): readonly string[] {
  return readdirSync(directory)
    .filter((name) => name.endsWith(".json"))
    .sort();
}

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(bytes: Uint8Array): string {
  let bits = "";
  for (const byte of bytes) bits += byte.toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; i < bits.length; i += 5) out += BASE32.charAt(Number.parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2));
  return out.padEnd(Math.ceil(out.length / 8) * 8, "=");
}

function base32Decode(encoded: string): Uint8Array {
  let bits = "";
  for (const char of encoded.replace(/=+$/, "")) bits += BASE32.indexOf(char).toString(2).padStart(5, "0");
  return Uint8Array.from(bits.slice(0, bits.length - (bits.length % 8)).match(/.{8}/g) ?? [], (byte) => Number.parseInt(byte, 2));
}

function isDecimal(value: unknown): value is DecimalMarker {
  return typeof value === "object" && value !== null && "decimal" in value;
}

function bareToJson(item: BareItem): unknown {
  switch (item.type) {
    case "integer":
      return item.value === 0 ? 0 : item.value;
    case "decimal":
      return { decimal: item.value === 0 ? 0 : item.value };
    case "string":
    case "boolean":
      return item.value;
    case "token":
      return { __type: "token", value: item.value };
    case "bytes":
      return { __type: "binary", value: base32Encode(item.value) };
    case "date":
      return { __type: "date", value: item.value === 0 ? 0 : item.value };
    case "display-string":
      return { __type: "displaystring", value: item.value };
  }
}

function paramsToJson(params: Parameters): unknown {
  return params.map(([key, value]) => [key, bareToJson(value)]);
}

function memberToJson(member: Item | InnerList): unknown {
  if (member.kind === "item") return [bareToJson(member.value), paramsToJson(member.params)];
  return [member.items.map((item) => memberToJson(item)), paramsToJson(member.params)];
}

function toJson(type: HeaderType, value: Item | List | Dictionary): unknown {
  if (type === "item") return memberToJson(value as Item);
  if (type === "list") return (value as List).map(memberToJson);
  return (value as Dictionary).map(([key, member]) => [key, memberToJson(member)]);
}

function bareFromJson(value: unknown): BareItem {
  if (isDecimal(value)) return { type: "decimal", value: value.decimal };
  if (typeof value === "number") return { type: "integer", value };
  if (typeof value === "string") return { type: "string", value };
  if (typeof value === "boolean") return { type: "boolean", value };
  const typed = value as { readonly __type: string; readonly value: string | number };
  switch (typed.__type) {
    case "token":
      return { type: "token", value: String(typed.value) };
    case "binary":
      return { type: "bytes", value: base32Decode(String(typed.value)) };
    case "date":
      return { type: "date", value: Number(typed.value) };
    case "displaystring":
      return { type: "display-string", value: String(typed.value) };
    default:
      throw new Error(`unknown __type ${typed.__type}`);
  }
}

function paramsFromJson(value: unknown): Parameters {
  return (value as readonly (readonly [string, unknown])[]).map(([key, bare]) => [key, bareFromJson(bare)] as const);
}

function memberFromJson(value: unknown): Item | InnerList {
  const [first, params] = value as readonly [unknown, unknown];
  if (Array.isArray(first)) {
    return { kind: "inner-list", items: first.map((item) => memberFromJson(item) as Item), params: paramsFromJson(params) };
  }
  return { kind: "item", value: bareFromJson(first), params: paramsFromJson(params) };
}

function fromJson(type: HeaderType, value: unknown): Item | List | Dictionary {
  if (type === "item") return memberFromJson(value) as Item;
  if (type === "list") return (value as readonly unknown[]).map(memberFromJson);
  return (value as readonly (readonly [string, unknown])[]).map(([key, member]) => [key, memberFromJson(member)] as const);
}

function parse(type: HeaderType, input: string): Item | List | Dictionary {
  if (type === "item") return parseItem(input);
  if (type === "list") return parseList(input);
  return parseDictionary(input);
}

function serialize(type: HeaderType, value: Item | List | Dictionary): string {
  if (type === "item") return serializeItem(value as Item);
  if (type === "list") return serializeList(value as List);
  return serializeDictionary(value as Dictionary);
}

describe.each(files(DIRECTORY))("httpwg %s", (file) => {
  it.each(load(join(DIRECTORY, file)).map((test) => [test.name, test] as const))("%s", (_name, test) => {
    // A field received in several lines is combined with ", " (RFC 9110 §5.3) before parsing (RFC 9651 §4.2).
    const input = (test.raw ?? []).join(", ");
    if (test.must_fail) {
      expect(() => parse(test.header_type, input)).toThrow();
      return;
    }
    let parsed: Item | List | Dictionary;
    try {
      parsed = parse(test.header_type, input);
    } catch (error) {
      if (test.can_fail) return;
      throw error;
    }
    expect(toJson(test.header_type, parsed)).toEqual(test.expected);
    const canonical = test.canonical ?? test.raw ?? [];
    expect(serialize(test.header_type, parsed)).toBe(canonical.join(", "));
  });
});

describe.each(files(join(DIRECTORY, "serialisation-tests")))("httpwg serialisation-tests/%s", (file) => {
  it.each(load(join(DIRECTORY, "serialisation-tests", file)).map((test) => [test.name, test] as const))("%s", (_name, test) => {
    const value = fromJson(test.header_type, test.expected);
    if (test.must_fail) {
      expect(() => serialize(test.header_type, value)).toThrow();
      return;
    }
    expect(serialize(test.header_type, value)).toBe((test.canonical ?? []).join(", "));
  });
});
