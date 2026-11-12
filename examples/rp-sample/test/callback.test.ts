import { describe, expect, it } from "vitest";
import { CallbackError, checkAuthorizationResponse } from "../src/callback.js";
import { ISSUER } from "./support/fake-idp.js";

const STATE = "state-1";

function check(query: Record<string, string>): string {
  try {
    return checkAuthorizationResponse(new URLSearchParams(query), STATE, ISSUER).code;
  } catch (error) {
    if (error instanceof CallbackError) return `refused:${error.reason}`;
    throw error;
  }
}

describe("checkAuthorizationResponse", () => {
  it("returns the code when state and iss match", () => {
    expect(check({ code: "c", state: STATE, iss: ISSUER })).toBe("c");
  });

  it.each<[string, Record<string, string>, string]>([
    ["another state", { code: "c", state: "state-2", iss: ISSUER }, "refused:state"],
    ["no state", { code: "c", iss: ISSUER }, "refused:state"],
    // RFC 9207 §2.4: the IdP advertises authorization_response_iss_parameter_supported, so a response without iss
    // is refused, and iss is compared by simple string comparison (no normalisation).
    ["no iss", { code: "c", state: STATE }, "refused:iss"],
    ["another iss (a mix-up)", { code: "c", state: STATE, iss: "https://evil.example" }, "refused:iss"],
    ["an iss with a trailing slash", { code: "c", state: STATE, iss: `${ISSUER}/` }, "refused:iss"],
    ["no code", { state: STATE, iss: ISSUER }, "refused:code"],
    ["an empty code", { code: "", state: STATE, iss: ISSUER }, "refused:code"],
    ["an error from the IdP", { error: "access_denied", state: STATE, iss: ISSUER }, "refused:idp_error"],
    // An error is believed only after state and iss: an attacker's error must not pass as the IdP's.
    ["an error with another iss", { error: "access_denied", state: STATE, iss: "https://evil.example" }, "refused:iss"],
    ["an error with another state", { error: "access_denied", state: "x", iss: ISSUER }, "refused:state"],
  ])("refuses %s", (_name, query, expected) => {
    expect(check(query)).toBe(expected);
  });

  it("ignores a repeated parameter it does not use (RFC 6749 §4.1.2: unrecognized parameters are ignored)", () => {
    const params = new URLSearchParams([
      ["code", "c"],
      ["state", STATE],
      ["iss", ISSUER],
      ["session_state", "a"],
      ["session_state", "b"],
    ]);
    expect(checkAuthorizationResponse(params, STATE, ISSUER).code).toBe("c");
  });

  it.each(["state", "code", "error"])("refuses a repeated %s, which could be read differently by different parsers", (name) => {
    const params = new URLSearchParams([
      ["code", "c"],
      ["state", STATE],
      ["iss", ISSUER],
      [name, name === "state" ? STATE : "x"],
    ]);
    expect(() => checkAuthorizationResponse(params, STATE, ISSUER)).toThrow(CallbackError);
  });

  it("refuses a repeated iss", () => {
    const params = new URLSearchParams([
      ["code", "c"],
      ["state", STATE],
      ["iss", ISSUER],
      ["iss", "https://evil.example"],
    ]);
    expect(() => checkAuthorizationResponse(params, STATE, ISSUER)).toThrow(CallbackError);
  });

  it("keeps the IdP's error code only when it is a plain OAuth error code", () => {
    try {
      checkAuthorizationResponse(new URLSearchParams({ error: "<script>", state: STATE, iss: ISSUER }), STATE, ISSUER);
    } catch (error) {
      expect(error).toBeInstanceOf(CallbackError);
      expect((error as CallbackError).idpError).toBeUndefined();
    }
    try {
      checkAuthorizationResponse(new URLSearchParams({ error: "login_required", state: STATE, iss: ISSUER }), STATE, ISSUER);
    } catch (error) {
      expect((error as CallbackError).idpError).toBe("login_required");
    }
  });
});
