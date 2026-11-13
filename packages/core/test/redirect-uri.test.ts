import { describe, expect, it } from "vitest";
import { classifyRedirectUri, isRedirectUriAllowed } from "../src/clients/index.js";
import { matchesRegisteredRedirectUri } from "@idp/oauth-native-apps";
import { vectors } from "./vectors.js";

describe("matchesRegisteredRedirectUri (contract vectors)", () => {
  it.each(vectors.redirect_uri_match)("$case", ({ registered, requested, matches }) => {
    expect(matchesRegisteredRedirectUri(registered, requested)).toBe(matches);
  });
});

describe("redirect URI registration rules", () => {
  it.each(vectors.redirect_uri.valid)("classifies $value as $kind", ({ value, kind }) => {
    expect(classifyRedirectUri(value)).toBe(kind);
    expect(isRedirectUriAllowed(value, "public")).toBe(true);
  });

  it.each(vectors.redirect_uri.invalid)("rejects '$value' ($reason)", ({ value }) => {
    expect(classifyRedirectUri(value)).toBeNull();
    expect(isRedirectUriAllowed(value, "public")).toBe(false);
    expect(isRedirectUriAllowed(value, "confidential")).toBe(false);
  });

  it.each(vectors.redirect_uri.confidential_rejects)("allows %s only for public clients", (value) => {
    expect(isRedirectUriAllowed(value, "public")).toBe(true);
    expect(isRedirectUriAllowed(value, "confidential")).toBe(false);
  });

  it("allows https for both client types", () => {
    expect(isRedirectUriAllowed("https://app.example.com/cb", "confidential")).toBe(true);
  });

  it("rejects a URI longer than 2000 characters", () => {
    expect(classifyRedirectUri(`https://app.example.com/${"a".repeat(2000)}`)).toBeNull();
  });

  // A registrable URI must match itself, or a client could register a redirect it can never use.
  it.each(vectors.redirect_uri.valid)("lets $value match itself once registered", ({ value }) => {
    expect(matchesRegisteredRedirectUri(value, value)).toBe(true);
  });
});
