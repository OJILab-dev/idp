// Scenario 9: the admin Worker's IDP Service Binding reaches the IdP Worker's IdpInternal entrypoint on a real workerd
// (idpctl.md, RS256 enablement). A binding call carries no request.cf and no client IP, so it must not go through
// the public fetch path, whose TLS and rate-limit checks would refuse it and turn RS256 off for good.
import { expect, test } from "../support/fixtures.js";
import { ISSUER } from "../support/idp.js";

test("the internal entrypoint returns the issuer's discovery document over a Service Binding", async ({ idp }) => {
  const document = (await idp.internalDiscovery()) as Record<string, unknown>;
  expect(document["issuer"]).toBe(ISSUER);
  // The local IdP has only the Ed25519 key, so RS256 is not advertised; the RSA case is covered by the unit test
  // apps/admin-worker/test/rs256-idp.test.ts.
  expect(document["id_token_signing_alg_values_supported"]).toEqual(["Ed25519"]);
});
