// The admin signature profile's structured-field rules (docs/design/hosting-modes.md 3.2, 3.4): RFC 9651 parsing,
// held to the one shape the admin Worker accepts. The rejections are the ones the IdP has always made; RFC 9651
// itself recovers from some of them (duplicate keys, base64 padding), which the package tests cover.
import { describe, expect, it } from "vitest";
import { StructuredFieldError } from "@idp/structured-fields";
import { parseStrictDictionary } from "../../src/admin/strict-dictionary.js";

describe("parseStrictDictionary", () => {
  it("parses byte sequences in the standard base64 alphabet with padding", () => {
    const [member] = parseStrictDictionary("sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:");
    const value = member?.[1];
    if (value?.kind !== "item" || value.value.type !== "bytes") throw new Error("not bytes");
    expect(Buffer.from(value.value.value).toString("base64")).toBe("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
  });

  it("parses every bare item type the RFC defines that the profile can meet", () => {
    expect(parseStrictDictionary('a=1, b=-2, c=1.5, d="x\\"y\\\\", e=tok/en:1, f=?0, g, h=:AA==:;p')).toEqual([
      ["a", { kind: "item", value: { type: "integer", value: 1 }, params: [] }],
      ["b", { kind: "item", value: { type: "integer", value: -2 }, params: [] }],
      ["c", { kind: "item", value: { type: "decimal", value: 1.5 }, params: [] }],
      ["d", { kind: "item", value: { type: "string", value: 'x"y\\' }, params: [] }],
      ["e", { kind: "item", value: { type: "token", value: "tok/en:1" }, params: [] }],
      ["f", { kind: "item", value: { type: "boolean", value: false }, params: [] }],
      ["g", { kind: "item", value: { type: "boolean", value: true }, params: [] }],
      ["h", { kind: "item", value: { type: "bytes", value: Uint8Array.of(0) }, params: [["p", { type: "boolean", value: true }]] }],
    ]);
  });

  it.each([
    ["an empty field", ""],
    ["a duplicate key (a repeated header joined by the runtime)", "sig1=:AA==:, sig1=:AA==:"],
    ["a duplicate parameter", "a=1;p=1;p=2"],
    ["a duplicate parameter of an inner list item", "a=(1;p 2;p;p);q"],
    ["an uppercase key", "SHA-256=:AA==:"],
    ["a trailing comma", "a=1,"],
    ["text after a member", "a=1 b=2"],
    ["an unterminated string", 'a="x'],
    ["an escape other than \\\" or \\\\", 'a="\\n"'],
    ["a control character in a string", 'a="\u0001"'],
    ["a non-ASCII character in a string", 'a="é"'],
    ["the URL-safe alphabet in a byte sequence", "a=:-_8=:"],
    ["a byte sequence without padding", "a=:AA:"],
    ["a byte sequence with non-zero pad bits", "a=:AB==:"],
    ["an unterminated byte sequence", "a=:AA=="],
    ["an integer of 16 digits", "a=1234567890123456"],
    ["a decimal with 4 fractional digits", "a=1.2345"],
    ["a decimal without fractional digits", "a=1."],
    ["a boolean other than ?0 and ?1", "a=?2"],
    ["a date, which the profile never uses", "a=@1"],
    ["a date parameter", "a=1;p=@1"],
    ["a date inside an inner list", "a=(@1)"],
    ["a display string, which the profile never uses", 'a=%"x"'],
    ["a display string parameter of an inner list", 'a=();p=%"x"'],
    ["an inner list item without a separator", 'a=("x""y")'],
    ["an unterminated inner list", 'a=("x"'],
  ])("rejects %s", (_, input) => {
    expect(() => parseStrictDictionary(input)).toThrow(StructuredFieldError);
  });
});
