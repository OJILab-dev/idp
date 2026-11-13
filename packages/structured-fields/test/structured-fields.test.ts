import { describe, expect, it } from "vitest";
import { parseDictionary, parseItem, serializeInnerList, type InnerList, type Recovery } from "../src/index.js";

function only(input: string): ReturnType<typeof parseDictionary>[number][1] {
  const dictionary = parseDictionary(input);
  expect(dictionary).toHaveLength(1);
  const [member] = dictionary;
  if (member === undefined) throw new Error("unreachable");
  return member[1];
}

function recoveries(parse: (onRecovery: (recovery: Recovery) => void) => unknown): readonly Recovery[] {
  const seen: Recovery[] = [];
  parse((recovery) => seen.push(recovery));
  return seen;
}

describe("parseDictionary", () => {
  it("parses an RFC 9421 Signature-Input member: an inner list of strings with parameters, in order", () => {
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

  it("allows the optional whitespace RFC 9651 allows around members and inside inner lists", () => {
    expect(parseDictionary(' a=1 ,\tb=( 1  2 ) ').map(([key]) => key)).toEqual(["a", "b"]);
  });
});

describe("recoveries (RFC 9651 §4.2.2, §4.2.3.2, §4.2.7)", () => {
  it("keeps the last value of a repeated dictionary key in the first key's position and reports it", () => {
    let dictionary: ReturnType<typeof parseDictionary> = [];
    expect(recoveries((onRecovery) => (dictionary = parseDictionary("a=1, b=2, a=3", { onRecovery })))).toEqual([
      { kind: "duplicate-dictionary-key", key: "a" },
    ]);
    expect(dictionary.map(([key, member]) => [key, member.kind === "item" ? member.value.value : undefined])).toEqual([
      ["a", 3],
      ["b", 2],
    ]);
  });

  it("keeps the last value of a repeated parameter and reports it", () => {
    let item: ReturnType<typeof parseItem> | undefined;
    expect(recoveries((onRecovery) => (item = parseItem("1;p=1;q;p=2", { onRecovery })))).toEqual([{ kind: "duplicate-parameter-key", key: "p" }]);
    expect(item?.params).toEqual([
      ["p", { type: "integer", value: 2 }],
      ["q", { type: "boolean", value: true }],
    ]);
  });

  it.each([
    [":aGVsbG8:", "base64-padding"],
    [":aGVsbG8==:", "base64-padding"],
    [":iZ==:", "base64-pad-bits"],
  ] as const)("accepts the byte sequence %s and reports %s", (input, kind) => {
    expect(recoveries((onRecovery) => parseItem(input, { onRecovery }))).toEqual([{ kind }]);
  });

  it("reports nothing for canonical input", () => {
    expect(recoveries((onRecovery) => parseDictionary('a=:aGVsbG8=:;p=1, b=("x");q', { onRecovery }))).toEqual([]);
  });
});

describe("serializeInnerList", () => {
  it("serializes the inner list back to the canonical text that an RFC 9421 signature base uses (§2.3)", () => {
    const text = '("@method" "content-digest");created=1767225600;nonce="a\\"b";keyid="k";tag="idp-admin"';
    const member = only(`sig1=${text}`);
    expect(serializeInnerList(member as InnerList)).toBe(text);
  });

  it("collapses the whitespace that the parser allows", () => {
    const member = only('sig1=(  "@method"   "@authority" );created=1');
    expect(serializeInnerList(member as InnerList)).toBe('("@method" "@authority");created=1');
  });

  it("serializes the other bare item types", () => {
    const member = only("x=(tok :AA==: ?1 -3 2.50);a;b=?0");
    expect(serializeInnerList(member as InnerList)).toBe("(tok :AA==: ?1 -3 2.5);a;b=?0");
  });
});
