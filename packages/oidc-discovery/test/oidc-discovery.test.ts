import { describe, expect, it } from "vitest";
import { openIdConfigurationUrl } from "../src/index.js";

describe("openIdConfigurationUrl (OpenID Connect Discovery 1.0 §4.1)", () => {
  it("appends the well-known path to the issuer of the §4.1 example", () => {
    expect(openIdConfigurationUrl("https://example.com/issuer1")).toBe("https://example.com/issuer1/.well-known/openid-configuration");
  });

  it("removes a trailing slash of the issuer before appending", () => {
    expect(openIdConfigurationUrl("https://example.com/")).toBe("https://example.com/.well-known/openid-configuration");
  });
});
