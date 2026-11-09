// Scenario 4: an authorization request whose client or redirect URI cannot be trusted gets the error page and is
// never redirected (authentication.md, step 1).
import { expect, test } from "../support/fixtures.js";
import { ISSUER } from "../support/idp.js";
import { RP_HOST, authorizeFlow } from "../support/rp.js";
import type { SeededClient } from "../support/seed.js";

const UNKNOWN: SeededClient = { clientId: "no-such-client", type: "confidential" };

test("an unknown client, a foreign redirect URI, and a disabled client each get the error page", async ({ page, admin }) => {
  const user = await admin.createUser("Alice");
  const client = await admin.createClient("confidential", user.userId);
  const disabled = await admin.createClient("confidential", user.userId);
  await admin.disableClient(disabled.clientId);
  const toRp: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).hostname === RP_HOST) toRp.push(request.url());
  });

  const cases = [
    { url: authorizeFlow(UNKNOWN).url, reason: "invalid_client" },
    { url: authorizeFlow(client, { redirect_uri: "https://evil.test/callback" }).url, reason: "invalid_redirect_uri" },
    { url: authorizeFlow(disabled).url, reason: "invalid_client" },
  ] as const;
  for (const { url, reason } of cases) {
    const response = await page.goto(url);
    expect(response?.status(), reason).toBe(400);
    await expect(page).toHaveURL((current) => current.origin === ISSUER && current.pathname === "/authorize");
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("Sign-in could not continue");
    await expect(page.locator("code")).toHaveText(reason);
  }
  expect(toRp).toEqual([]);
});
