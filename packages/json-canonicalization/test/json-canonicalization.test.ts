import { describe, expect, it } from "vitest";
import { JsonCanonicalizationError, canonicalize } from "../src/index.js";

function double(hex: string): number {
  return new DataView(Uint8Array.from(hex.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16)).buffer).getFloat64(0);
}

describe("RFC 8785 §3.2.2 to §3.2.4", () => {
  // The sample of §3.2.2, parsed as JSON, and the canonical form of §3.2.3, checked against the UTF-8 bytes of §3.2.4.
  const SAMPLE = String.raw`{
    "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
    "string": "€$\u000F\u000aA'B"\\\\"\/",
    "literals": [null, true, false]
  }`;
  const UTF8 = [
    "7b 22 6c 69 74 65 72 61 6c 73 22 3a 5b 6e 75 6c 6c 2c 74 72",
    "75 65 2c 66 61 6c 73 65 5d 2c 22 6e 75 6d 62 65 72 73 22 3a",
    "5b 33 33 33 33 33 33 33 33 33 2e 33 33 33 33 33 33 33 2c 31",
    "65 2b 33 30 2c 34 2e 35 2c 30 2e 30 30 32 2c 31 65 2d 32 37",
    "5d 2c 22 73 74 72 69 6e 67 22 3a 22 e2 82 ac 24 5c 75 30 30",
    "30 66 5c 6e 41 27 42 5c 22 5c 5c 5c 5c 5c 22 2f 22 7d",
  ]
    .join(" ")
    .replaceAll(" ", "");

  it("canonicalizes the sample to the bytes of §3.2.4", () => {
    const bytes = new TextEncoder().encode(canonicalize(JSON.parse(SAMPLE)));
    expect(Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")).toBe(UTF8);
  });

  it("sorts the property names of the §3.2.3 test data by UTF-16 code units", () => {
    const data = JSON.parse(String.raw`{
      "€": "Euro Sign",
      "\r": "Carriage Return",
      "דּ": "Hebrew Letter Dalet With Dagesh",
      "1": "One",
      "😀": "Emoji: Grinning Face",
      "\u0080": "Control",
      "ö": "Latin Small Letter O With Diaeresis"
    }`) as Record<string, string>;
    // The names in the order §3.2.3 lists them as sorted; their positions in the output must increase.
    const text = canonicalize(data);
    const positions = ['"\\r"', '"1"', '"\u0080"', '"ö"', '"€"', '"😀"', '"דּ"'].map((key) => text.indexOf(key));
    expect(positions.every((position, i) => position >= 0 && (i === 0 || position > (positions[i - 1] ?? 0)))).toBe(true);
  });
});

describe("RFC 8785 Appendix B", () => {
  it.each([
    ["0000000000000000", "0"],
    ["8000000000000000", "0"],
    ["0000000000000001", "5e-324"],
    ["8000000000000001", "-5e-324"],
    ["7fefffffffffffff", "1.7976931348623157e+308"],
    ["ffefffffffffffff", "-1.7976931348623157e+308"],
    ["4340000000000000", "9007199254740992"],
    ["c340000000000000", "-9007199254740992"],
    ["4430000000000000", "295147905179352830000"],
    ["44b52d02c7e14af5", "9.999999999999997e+22"],
    ["44b52d02c7e14af6", "1e+23"],
    ["44b52d02c7e14af7", "1.0000000000000001e+23"],
    ["444b1ae4d6e2ef4e", "999999999999999700000"],
    ["444b1ae4d6e2ef4f", "999999999999999900000"],
    ["444b1ae4d6e2ef50", "1e+21"],
    ["3eb0c6f7a0b5ed8c", "9.999999999999997e-7"],
    ["3eb0c6f7a0b5ed8d", "0.000001"],
    ["41b3de4355555553", "333333333.3333332"],
    ["41b3de4355555554", "333333333.33333325"],
    ["41b3de4355555555", "333333333.3333333"],
    ["41b3de4355555556", "333333333.3333334"],
    ["41b3de4355555557", "333333333.33333343"],
    ["becbf647612f3696", "-0.0000033333333333333333"],
    ["43143ff3c1cb0959", "1424953923781206.2"],
  ])("serializes the double %s as %s", (hex, expected) => {
    expect(canonicalize(double(hex))).toBe(expected);
  });

  it.each(["7fffffffffffffff", "7ff0000000000000"])("refuses the double %s, which JSON cannot represent", (hex) => {
    expect(() => canonicalize(double(hex))).toThrow(JsonCanonicalizationError);
  });
});

describe("canonicalize: input outside I-JSON (RFC 7493)", () => {
  it.each([
    ["a lone surrogate in a string", "\ud800"],
    ["a lone surrogate in a property name", { "\udc00": 1 }],
    ["undefined", undefined],
    ["an undefined member", { a: undefined }],
    ["a function", () => 1],
    ["a bigint", 1n],
    ["a non-plain object", new Date(0)],
  ])("refuses %s", (_name, value) => {
    expect(() => canonicalize(value)).toThrow(JsonCanonicalizationError);
  });
});
