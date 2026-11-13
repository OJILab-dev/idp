import { describe, expect, it } from "vitest";
import { clientSecretBasic, isJson } from "../src/idp.js";

describe("isJson", () => {
  it.each(["application/json; charset=utf-8", "Application/JSON", " application/json ;charset=UTF-8"])("accepts %j", (value) => {
    expect(isJson(value)).toBe(true);
  });

  it.each([null, "application/jsonx", "application/problem+json"])("refuses %j: the media type must be exactly application/json", (value) => {
    expect(isJson(value)).toBe(false);
  });
});

describe("clientSecretBasic", () => {
  it("form-urlencodes both halves before Base64 (RFC 6749 §2.3.1, Appendix B)", () => {
    // Space is "+", and ":" "+" "%" "/" "!" "'" "(" ")" "~" are percent-encoded; "*" "-" "." "_" stay (WHATWG
    // application/x-www-form-urlencoded serializer).
    expect(clientSecretBasic("a:b", "x y+z%/!'()~*-._")).toBe(`Basic ${btoa("a%3Ab:x+y%2Bz%25%2F%21%27%28%29%7E*-._")}`);
  });
});
