import { describe, expect, it } from "vitest";
import { isAcceptedTlsVersion } from "../src/shared/index.js";

describe("isAcceptedTlsVersion", () => {
  it.each(["TLSv1.2", "TLSv1.3"])("accepts %s", (tlsVersion) => {
    expect(isAcceptedTlsVersion({ tlsVersion })).toBe(true);
  });

  // RFC 8996 §§4-5: TLS 1.0 and 1.1 must not be used, and an unknown spelling is not guessed at.
  it.each([
    ["TLS 1.0", { tlsVersion: "TLSv1" }],
    ["TLS 1.0 spelled with a minor", { tlsVersion: "TLSv1.0" }],
    ["TLS 1.1", { tlsVersion: "TLSv1.1" }],
    ["SSL 3", { tlsVersion: "SSLv3" }],
    ["an empty value (plain HTTP)", { tlsVersion: "" }],
    ["a different case", { tlsVersion: "tlsv1.3" }],
    ["surrounding spaces", { tlsVersion: " TLSv1.3" }],
    ["a future version", { tlsVersion: "TLSv1.4" }],
    ["a non-string", { tlsVersion: 1.3 }],
    ["no tlsVersion", {}],
    ["a null cf", null],
    ["no cf", undefined],
    ["a string cf", "TLSv1.3"],
  ])("refuses %s", (_name, cf) => {
    expect(isAcceptedTlsVersion(cf)).toBe(false);
  });
});
