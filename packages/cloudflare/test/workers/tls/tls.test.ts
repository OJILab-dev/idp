import { describe, expect, it } from "vitest";
import { isAcceptedTlsVersion } from "../../../src/workers/tls/index.js";

describe("isAcceptedTlsVersion", () => {
  it.each(["TLSv1.2", "TLSv1.3"])("accepts %s", (tlsVersion) => {
    expect(isAcceptedTlsVersion({ tlsVersion })).toBe(true);
  });

  // RFC 8996 §§4-5: TLS 1.0 and 1.1 must not be used, and an unknown spelling is not guessed at.
  it.each([
    ["TLS 1.0", { tlsVersion: "TLSv1" }],
    ["TLS 1.1", { tlsVersion: "TLSv1.1" }],
    ["an empty value (plain HTTP)", { tlsVersion: "" }],
    ["a different case", { tlsVersion: "tlsv1.3" }],
    ["a non-string", { tlsVersion: 1.3 }],
    ["a null cf", null],
    ["a string cf", "TLSv1.3"],
  ])("refuses %s", (_name, cf) => {
    expect(isAcceptedTlsVersion(cf)).toBe(false);
  });
});
