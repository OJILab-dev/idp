// The strict structured-field parser behind the RFC 9421 admin signatures (docs/design/hosting-modes.md 3.2, 3.4).
// Cases follow RFC 9651 §4.2; the parser is stricter than the RFC where the profile needs it (duplicate keys).
import { describe, expect, it } from "vitest";
import { StructuredFieldError, parseDictionary, serializeInnerList, type InnerList } from "../../src/admin/structured-fields.js";

function only(input: string): ReturnType<typeof parseDictionary>[number][1] {
  const dictionary = parseDictionary(input);
  expect(dictionary).toHaveLength(1);
  const [member] = dictionary;
  if (member === undefined) throw new Error("unreachable");
  return member[1];
}

describe("parseDictionary", () => {
  it("parses a Signature-Input member: an inner list of strings with parameters, in order", () => {
    const member = only('sig1=("@method" "@target-uri");created=1767225600;nonce="n";keyid="k";tag="idp-admin"');
    expect(member).toEqual({
      kind: "inner-list",
      items: [
        { kind: "item", value: { type: "string", value: "@method" }, params: [] },
        { kind: "item", value: { type: "string", value: "@target-uri" }, params: [] },
      ],
      params: [
        ["created", { type: "integer", value: 1767225600 }],
        ["nonce", { type: "string", value: "n" }],
        ["keyid", { type: "string", value: "k" }],
        ["tag", { type: "string", value: "idp-admin" }],
      ],
    });
  });

  it("parses byte sequences in the standard base64 alphabet with padding", () => {
    const member = only("sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:");
    expect(member.kind).toBe("item");
    if (member.kind !== "item" || member.value.type !== "bytes") throw new Error("not bytes");
    expect(Buffer.from(member.value.value).toString("base64")).toBe("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
  });

  it("parses every bare item type the RFC defines that the profile can meet", () => {
    expect(parseDictionary('a=1, b=-2, c=1.5, d="x\\"y\\\\", e=tok/en:1, f=?0, g, h=:AA==:;p')).toEqual([
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

  it("allows the optional whitespace RFC 9651 allows around members and inside inner lists", () => {
    expect(parseDictionary(' a=1 ,\tb=( 1  2 ) ').map(([key]) => key)).toEqual(["a", "b"]);
  });

  it.each([
    ["an empty field", ""],
    ["a duplicate key (a repeated header joined by the runtime)", "sig1=:AA==:, sig1=:AA==:"],
    ["a duplicate parameter", 'a=1;p=1;p=2'],
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
    ["a date (RFC 9651), which the profile never uses", "a=@1"],
    ["a display string (RFC 9651), which the profile never uses", 'a=%"x"'],
    ["an inner list item without a separator", 'a=("x""y")'],
    ["an unterminated inner list", 'a=("x"'],
  ])("rejects %s", (_, input) => {
    expect(() => parseDictionary(input)).toThrow(StructuredFieldError);
  });
});

describe("serializeInnerList", () => {
  it("serializes the inner list back to the canonical text that the signature base uses (RFC 9421 §2.3)", () => {
    const text = '("@method" "content-digest");created=1767225600;nonce="a\\"b";keyid="k";tag="idp-admin"';
    const member = only(`sig1=${text}`);
    expect(serializeInnerList(member as InnerList)).toBe(text);
  });

  it("collapses the whitespace that the parser allows, so a signer must send the canonical form", () => {
    const member = only('sig1=(  "@method"   "@authority" );created=1');
    expect(serializeInnerList(member as InnerList)).toBe('("@method" "@authority");created=1');
  });

  it("serializes the other bare item types", () => {
    const member = only("x=(tok :AA==: ?1 -3 2.50);a;b=?0");
    expect(serializeInnerList(member as InnerList)).toBe("(tok :AA==: ?1 -3 2.5);a;b=?0");
  });
});
