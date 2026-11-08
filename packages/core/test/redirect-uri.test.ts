import { describe, expect, it } from "vitest";
import { classifyRedirectUri, isRedirectUriAllowed } from "../src/shared/index.js";
import { vectors } from "./vectors.js";

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
});
