import { describe, expect, it } from "vitest";
import { clientSecretBasic, isJson } from "../src/idp.js";

describe("isJson", () => {
  it.each(["application/json", "application/json; charset=utf-8", "Application/JSON", " application/json ;charset=UTF-8"])(
    "accepts %j",
    (value) => {
      expect(isJson(value)).toBe(true);
    },
  );

  it.each([null, "", "application/jsonx", "application/json-seq", "application/jwt", "text/json", "application/problem+json", "text/html"])(
    "refuses %j: the media type must be exactly application/json",
    (value) => {
      expect(isJson(value)).toBe(false);
    },
  );
});

describe("clientSecretBasic", () => {
  function decoded(header: string): string {
    return atob(header.replace(/^Basic /, ""));
  }

  it("is Basic over client_id:secret when nothing needs encoding", () => {
    expect(clientSecretBasic("rp-sample", "abc_DEF-123")).toBe(`Basic ${btoa("rp-sample:abc_DEF-123")}`);
  });

  it("form-urlencodes both halves before Base64 (RFC 6749 §2.3.1, Appendix B)", () => {
    // Space is "+", and ":" "+" "%" "/" "!" "'" "(" ")" "~" are percent-encoded; "*" "-" "." "_" stay (WHATWG
    // application/x-www-form-urlencoded serializer).
    expect(decoded(clientSecretBasic("a:b", "x y+z%/!'()~*-._"))).toBe("a%3Ab:x+y%2Bz%25%2F%21%27%28%29%7E*-._");
  });

  it("encodes non-ASCII as UTF-8 percent-escapes", () => {
    expect(decoded(clientSecretBasic("rp", "秘密"))).toBe("rp:%E7%A7%98%E5%AF%86");
  });
});
