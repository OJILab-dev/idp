import { describe, expect, it } from "vitest";
import { InvalidIssuerError, parseIssuer } from "../src/index.js";
import { vectors } from "../../../contract/test/vectors.js";

describe("parseIssuer", () => {
  it.each(vectors.issuer.valid)("accepts $value", ({ value, rp_id, origin }) => {
    expect(parseIssuer(value)).toEqual({ url: value, rpId: rp_id, origin });
  });

  it.each(vectors.issuer.invalid)("rejects $reason", ({ value }) => {
    expect(() => parseIssuer(value)).toThrow(InvalidIssuerError);
  });

  it("rejects an unset value", () => {
    expect(() => parseIssuer(undefined)).toThrow(InvalidIssuerError);
  });
});
