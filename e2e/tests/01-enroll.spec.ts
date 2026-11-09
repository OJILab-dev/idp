// Scenario 1: enrollment through an enroll link (authentication.md, "パスキーの登録"; security-checklist.md, the token
// removed from the address bar).
import { en } from "../../apps/worker/pages/locales/en.js";
import { expect, test } from "../support/fixtures.js";
import { IDP_HOST, ISSUER } from "../support/idp.js";

test("an enroll link registers a passkey and its token leaves the address bar at once", async ({ page, admin, authenticators, idp }) => {
  const user = await admin.createUser("Alice");
  const authenticatorId = await authenticators.add();

  await page.goto(user.enrollLink);
  // Removed before the user does anything, so it is in neither the address bar nor the history entry.
  await expect(page).toHaveURL(`${ISSUER}/enroll`);
  expect(await page.evaluate("location.hash")).toBe("");

  await page.getByRole("button", { name: en.enroll_button }).click();
  await expect(page.getByRole("status")).toHaveText(en.enroll_done);

  const [credential, ...others] = await authenticators.credentials(authenticatorId);
  expect(others).toHaveLength(0);
  expect(credential).toMatchObject({ isResidentCredential: true, rpId: IDP_HOST });
  const rows = await idp.db.prepare("SELECT id, created_via FROM credentials WHERE user_id = ?").bind(user.userId).all();
  expect(rows.results).toEqual([{ id: Buffer.from(credential?.credentialId ?? "", "base64").toString("base64url"), created_via: "enroll" }]);

  // The link is single-use: opening it again is refused before any ceremony.
  await page.goto("about:blank");
  await page.goto(user.enrollLink);
  await page.getByRole("button", { name: en.enroll_button }).click();
  await expect(page.getByRole("alert")).toHaveText(en.enroll_invalid);
  expect(await authenticators.credentials(authenticatorId)).toHaveLength(1);
});
