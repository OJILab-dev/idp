import { describe, expect, it } from "vitest";
import type { Config } from "../src/config.js";
import { clientSecretBasic, createIdpClient, isJson, type Fetcher } from "../src/idp.js";

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

// The IdpError's message is what Workers Logs records for a failed back-channel fetch (src/app.ts onError).
describe("back-channel failure messages", () => {
  const config = { issuer: "https://idp.team-1.workers.dev", clientId: "rp-sample" } as Config;

  async function discoveryFailure(fetcher: Fetcher): Promise<unknown> {
    return createIdpClient(fetcher, () => 0)(config)
      .discover()
      .then(
        () => undefined,
        (error: unknown) => error,
      );
  }

  it("names the endpoint and the status when the IdP host refuses, without the body", async () => {
    const error = await discoveryFailure(() => Promise.resolve(new Response("<html>error code: 1042</html>", { status: 404, headers: { "content-type": "text/html" } })));
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toBe("discovery: status 404");
  });

  it("names the endpoint and the kind of failure when the fetch itself throws, without its message", async () => {
    const error = await discoveryFailure(() => Promise.reject(new TypeError("secret-looking detail")));
    expect((error as Error).message).toBe("discovery: request failed (TypeError)");
  });
});
