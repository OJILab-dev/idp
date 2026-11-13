import { describe, expect, it } from "vitest";
import { parseAcceptLanguage } from "../src/index.js";

function ranges(header: string): readonly string[] {
  return parseAcceptLanguage(header).map((preference) => preference.range);
}

describe("RFC 9110 §12.5.4", () => {
  it("orders the example 'da, en-gb;q=0.8, en;q=0.7' by quality", () => {
    expect(parseAcceptLanguage("da, en-gb;q=0.8, en;q=0.7")).toEqual([
      { range: "da", q: 1 },
      { range: "en-gb", q: 0.8 },
      { range: "en", q: 0.7 },
    ]);
  });
});

describe("parseAcceptLanguage", () => {
  it("keeps the header order among equal qualities", () => {
    expect(ranges("fr;q=0.5, de;q=0.5, ja")).toEqual(["ja", "fr", "de"]);
  });

  it("leaves out ranges with quality 0, which mean not acceptable (§12.4.2)", () => {
    expect(ranges("ja;q=0, en")).toEqual(["en"]);
  });

  it.each(["ja;q=2", "ja;q=0.1234", "ja;q=", "ja;q=.5"])("drops the entry %s whose qvalue is malformed (§12.4.2)", (header) => {
    expect(ranges(`${header}, en;q=0.1`)).toEqual(["en"]);
  });

  it("keeps the wildcard range for the caller to interpret", () => {
    expect(ranges("*;q=0.1, ja")).toEqual(["ja", "*"]);
  });
});
