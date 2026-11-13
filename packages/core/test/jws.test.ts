import { describe, expect, it } from "vitest";
import { createJwsSignature } from "@idp/jws";
import { loadSigningKeys } from "../src/user/index.js";
import { vectors } from "./vectors.js";

// The contract's JWS vectors, signed with a key loaded the way the Worker loads its Secret
// (docs/design/packages.md, coupling 10). The JWS behaviour itself is tested in packages/jws.
describe("createJwsSignature", () => {
  it.each(vectors.jws_ed25519)("matches $source", async ({ jwk, signing_input, signature }) => {
    const loaded = await loadSigningKeys({ ed25519Current: JSON.stringify({ ...jwk, use: "sig", alg: "Ed25519" }) });
    expect(await createJwsSignature(loaded.ed25519, signing_input)).toBe(signature);
  });
});
