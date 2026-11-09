// Scenario 5: the account page lists the user's passkeys, adds one after re-authentication, revokes one, and never
// revokes the last (authentication.md, "アカウントページ", "パスキーの追加", "パスキーの失効").
import { en } from "../../apps/worker/pages/locales/en.js";
import { expect, test } from "../support/fixtures.js";
import { enrolledUser, finishCodeFlow } from "../support/flows.js";
import { ISSUER } from "../support/idp.js";
import { authorizeFlow } from "../support/rp.js";

function base64url(base64: string): string {
  return Buffer.from(base64, "base64").toString("base64url");
}

test("the account page adds a second passkey, revokes it, and keeps the last one", async ({ page, admin, authenticators, idp }) => {
  const user = await enrolledUser(admin, page, authenticators);
  const [first] = await authenticators.credentials(user.authenticatorId);
  const firstId = base64url(first?.credentialId ?? "");
  const client = await admin.createClient("confidential", user.userId);
  const flow = authorizeFlow(client);
  await page.goto(flow.url);
  await finishCodeFlow(page, idp, client, flow);

  await page.goto(`${ISSUER}/account`);
  const rows = page.getByRole("listitem");
  await expect(rows).toHaveCount(1);
  await expect(rows.getByRole("button", { name: en.account_revoke })).toBeDisabled();

  // The add ceremony re-authenticates with the first passkey, then creates the second on another device: the first
  // device is taken away once its assertion is sent, as the creation excludes the credentials it already holds.
  let secondDevice: string | undefined;
  await page.route("**/webauthn/add/options", async (route) => {
    await authenticators.remove(user.authenticatorId);
    secondDevice = await authenticators.add();
    await route.continue();
  });
  // The page reloads the list once the passkey is added; that response says which row is which.
  const listed = page.waitForResponse((response) => new URL(response.url()).pathname === "/webauthn/credentials");
  await page.getByRole("button", { name: en.account_add }).click();
  const list = (await (await listed).json()) as { readonly credentials: readonly { readonly credential_id: string }[] };
  await expect(rows).toHaveCount(2);
  await page.unroute("**/webauthn/add/options");
  const [second] = await authenticators.credentials(secondDevice ?? "");
  const secondId = base64url(second?.credentialId ?? "");
  const stored = await idp.db.prepare("SELECT id, created_via FROM credentials WHERE user_id = ? ORDER BY created_via").bind(user.userId).all();
  expect(stored.results).toEqual([
    { id: firstId, created_via: "enroll" },
    { id: secondId, created_via: "self" },
  ]);

  // The list is ordered by creation time, then ID, and both passkeys can share a second, so the row is found by ID.
  // Revoking it re-authenticates with it, and the session, made with the first, survives.
  const secondRow = list.credentials.findIndex((row) => row.credential_id === secondId);
  expect(secondRow).toBeGreaterThanOrEqual(0);
  await rows.nth(secondRow).getByRole("button", { name: en.account_revoke }).click();
  await expect(rows).toHaveCount(1);
  await expect(page.getByRole("alert")).toBeHidden();
  await expect(rows.getByRole("button", { name: en.account_revoke })).toBeDisabled();
  const remaining = await idp.db.prepare("SELECT id FROM credentials WHERE user_id = ?").bind(user.userId).all();
  expect(remaining.results).toEqual([{ id: firstId }]);

  // The disabled button is not the only guard: the Worker refuses to start revoking the last passkey.
  const refusal = await page.evaluate(async (credentialId) => {
    const response = await fetch("/webauthn/revoke/begin", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ credential_id: credentialId }),
    });
    return { status: response.status, body: (await response.json()) as unknown };
  }, firstId);
  expect(refusal).toEqual({ status: 409, body: { error: "last_passkey" } });
});
