import { describe, expect, it } from "vitest";
import { classifyRedirectUriForm, isRegisteredRedirectUri, matchesRegisteredRedirectUri } from "../src/index.js";

// The example redirect URIs of RFC 8252 §7.1 and §7.3, registered without the run-time port.
const CUSTOM_SCHEME = "com.example.app:/oauth2redirect/example-provider";
const LOOPBACK_V4 = "http://127.0.0.1/oauth2redirect/example-provider";
const LOOPBACK_V6 = "http://[::1]/oauth2redirect/example-provider";

describe("classifyRedirectUriForm (RFC 8252 §7)", () => {
  it.each([
    [CUSTOM_SCHEME, "custom-scheme"],
    [LOOPBACK_V4, "loopback"],
    [LOOPBACK_V6, "loopback"],
    ["https://app.example.com/oauth2redirect/example-provider", "https"],
  ] as const)("classifies %s as %s", (value, kind) => {
    expect(classifyRedirectUriForm(value)).toBe(kind);
  });

  it.each([
    ["localhost (§8.3)", "http://localhost/cb"],
    ["a name under localhost over https", "https://app.localhost/cb"],
    ["a loopback URI with a registered port (§7.3)", "http://127.0.0.1:51004/cb"],
    ["plain http to a non-loopback host", "http://app.example.com/cb"],
    ["a private-use scheme that is not a reverse domain name (§7.1)", "myapp:/cb"],
    ["a fragment", "https://app.example.com/cb#x"],
    ["userinfo", "https://user@app.example.com/cb"],
    ["a non-canonical spelling", "HTTPS://app.example.com/cb"],
  ])("rejects %s", (_name, value) => {
    expect(classifyRedirectUriForm(value)).toBeNull();
  });
});

describe("matchesRegisteredRedirectUri (RFC 8252 §7.3, RFC 9700 §2.1)", () => {
  it.each([
    [LOOPBACK_V4, "http://127.0.0.1:51004/oauth2redirect/example-provider"],
    [LOOPBACK_V6, "http://[::1]:61023/oauth2redirect/example-provider"],
  ])("ignores the run-time port of the §7.3 example for %s", (registered, requested) => {
    expect(matchesRegisteredRedirectUri(registered, requested)).toBe(true);
  });

  it.each([
    ["another path on the loopback host", LOOPBACK_V4, "http://127.0.0.1:51004/other"],
    ["a non-canonical loopback spelling", LOOPBACK_V4, "http://127.0.0.1:51004/oauth2redirect/./example-provider"],
    ["another port on an https URI", "https://app.example.com/cb", "https://app.example.com:8443/cb"],
    ["a different case", "https://app.example.com/cb", "https://app.example.com/CB"],
  ])("rejects %s", (_name, registered, requested) => {
    expect(matchesRegisteredRedirectUri(registered, requested)).toBe(false);
  });

  it("matches when any registered value matches", () => {
    expect(isRegisteredRedirectUri([CUSTOM_SCHEME, LOOPBACK_V4], "http://127.0.0.1:1/oauth2redirect/example-provider")).toBe(true);
  });
});
