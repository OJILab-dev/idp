import { describe, expect, it } from "vitest";
import { AdminProblem, ENROLL_LINK_TTL_SECONDS } from "../../src/domain/index.js";
import { enrollLinkIssue, passkeyRevoke } from "../../src/domain/passkeys.js";
import { userCreate, userDisable } from "../../src/domain/users.js";
import { sha256Base64url } from "@idp/jwk-thumbprint";
import { MAX_PASSKEYS_PER_USER } from "@idp/core/passkeys";
import { isRandomTokenFormat, randomToken } from "@idp/core/identifiers";
import { T0, auditRows, query, run, seedPasskey, seedSession, useHarness } from "./harness.js";

const h = useHarness();
const MISSING = "0f8fad5b-d9cb-469f-a165-70867728950e";

async function expectProblem(promise: Promise<unknown>, kind: string): Promise<void> {
  await expect(promise).rejects.toSatisfy((error) => error instanceof AdminProblem && error.kind === kind);
}

async function createUser(): Promise<string> {
  return (await run(h(), userCreate, { name: "Alice" })).body.user_id;
}

function tokenOf(link: string): string {
  return link.slice(link.indexOf("#") + 1);
}

describe("enroll_link_issue", () => {
  it("issues a 10-minute link with the token in the fragment and stores only its hash", async () => {
    const id = await createUser();
    const outcome = await run(h(), enrollLinkIssue, { user_id: id });
    expect(outcome.status).toBe(201);
    const { enrollment_link: link, expires_at: expiresAt } = outcome.body;
    expect(link.startsWith("https://idp.example.com/enroll#")).toBe(true);
    const token = tokenOf(link);
    expect(isRandomTokenFormat(token)).toBe(true);
    expect(expiresAt).toBe(T0 + ENROLL_LINK_TTL_SECONDS);
    expect(await query(h(), "SELECT token_hash, user_id, expires_at FROM enroll_tokens")).toEqual([
      { token_hash: await sha256Base64url(token), user_id: id, expires_at: T0 + 600 },
    ]);
    const rows = await auditRows(h());
    expect(rows.at(-1)).toMatchObject({ operation: "enroll_link_issue", target: `user:${id}`, detail: { expires_at: T0 + 600 } });
    // Neither the token nor its hash is logged or kept for replay.
    const kept = JSON.stringify([rows, await query(h(), "SELECT * FROM idempotency_keys")]);
    expect(kept).not.toContain(token);
    expect(kept).not.toContain(await sha256Base64url(token));
  });

  it("keeps at most one live link per user: issuing again replaces the unused token", async () => {
    const id = await createUser();
    const other = await createUser();
    await run(h(), enrollLinkIssue, { user_id: other });
    await run(h(), enrollLinkIssue, { user_id: id });
    const second = await run(h(), enrollLinkIssue, { user_id: id });
    const hashes = await query(h(), "SELECT user_id, token_hash FROM enroll_tokens WHERE user_id = ?", id);
    expect(hashes).toEqual([{ user_id: id, token_hash: await sha256Base64url(tokenOf(second.body.enrollment_link)) }]);
    expect(await query(h(), "SELECT COUNT(*) AS n FROM enroll_tokens WHERE user_id = ?", other)).toEqual([{ n: 1 }]);
  });

  it("deletes other users' expired tokens in the same batch", async () => {
    const id = await createUser();
    const other = await createUser();
    await run(h(), enrollLinkIssue, { user_id: other });
    h().clock = T0 + ENROLL_LINK_TTL_SECONDS;
    await run(h(), enrollLinkIssue, { user_id: id });
    expect(await query(h(), "SELECT user_id FROM enroll_tokens")).toEqual([{ user_id: id }]);
  });

  it("deletes the challenges bound to a replaced token", async () => {
    const id = await createUser();
    const first = await run(h(), enrollLinkIssue, { user_id: id });
    await query(
      h(),
      "INSERT INTO challenges (challenge, purpose, user_id, enroll_token_hash, expires_at) VALUES ('c', 'enroll', ?, ?, ?)",
      id,
      await sha256Base64url(tokenOf(first.body.enrollment_link)),
      T0 + 600,
    );
    await run(h(), enrollLinkIssue, { user_id: id });
    expect(await query(h(), "SELECT COUNT(*) AS n FROM challenges")).toEqual([{ n: 0 }]);
  });

  it("refuses a user at the passkey limit with limit-reached, keeping the existing link", async () => {
    const id = await createUser();
    await run(h(), enrollLinkIssue, { user_id: id });
    for (let i = 0; i < MAX_PASSKEYS_PER_USER - 1; i++) await seedPasskey(h(), id);
    await expect(run(h(), enrollLinkIssue, { user_id: id })).resolves.toMatchObject({ status: 201 });
    await seedPasskey(h(), id);
    await expectProblem(run(h(), enrollLinkIssue, { user_id: id }), "limit-reached");
    expect(await query(h(), "SELECT COUNT(*) AS n FROM enroll_tokens")).toEqual([{ n: 1 }]);
    expect((await auditRows(h())).at(-1)).toMatchObject({ result: "failure", target: `user:${id}`, detail: { problem: "limit-reached" } });
  });

  it("refuses a disabled user with state-conflict and a missing user with not-found", async () => {
    const id = await createUser();
    await run(h(), userDisable, { user_id: id });
    await expectProblem(run(h(), enrollLinkIssue, { user_id: id }), "state-conflict");
    await expectProblem(run(h(), enrollLinkIssue, { user_id: MISSING }), "not-found");
    expect(await query(h(), "SELECT COUNT(*) AS n FROM enroll_tokens")).toEqual([{ n: 0 }]);
  });

  it("answers a replay with secret-not-replayable, and a retry with a new key replaces the link", async () => {
    const id = await createUser();
    const key = randomToken();
    await run(h(), enrollLinkIssue, { user_id: id }, key);
    await expectProblem(run(h(), enrollLinkIssue, { user_id: id }, key), "secret-not-replayable");
    const retry = await run(h(), enrollLinkIssue, { user_id: id });
    expect(await query(h(), "SELECT token_hash FROM enroll_tokens")).toEqual([
      { token_hash: await sha256Base64url(tokenOf(retry.body.enrollment_link)) },
    ]);
  });
});

describe("passkey_revoke", () => {
  it("revokes one passkey and only the sessions signed in with it", async () => {
    const id = await createUser();
    const keep = await seedPasskey(h(), id);
    const lost = await seedPasskey(h(), id);
    await seedSession(h(), id, keep);
    await seedSession(h(), id, lost);
    await expect(run(h(), passkeyRevoke, { user_id: id, credential_id: lost }, null)).resolves.toMatchObject({
      status: 200,
      body: { user_id: id, credential_id: lost },
    });
    expect(await query(h(), "SELECT id FROM credentials")).toEqual([{ id: keep }]);
    expect(await query(h(), "SELECT credential_id FROM sessions")).toEqual([{ credential_id: keep }]);
    expect((await auditRows(h())).at(-1)).toMatchObject({ operation: "passkey_revoke", target: `user:${id}`, detail: { credential_id: lost } });
  });

  it("refuses the last passkey with last-passkey and keeps it", async () => {
    const id = await createUser();
    const only = await seedPasskey(h(), id);
    await expectProblem(run(h(), passkeyRevoke, { user_id: id, credential_id: only }, null), "last-passkey");
    expect(await query(h(), "SELECT id FROM credentials")).toEqual([{ id: only }]);
  });

  it("never leaves zero passkeys, even when revoking down from two at once", async () => {
    const id = await createUser();
    const a = await seedPasskey(h(), id);
    const b = await seedPasskey(h(), id);
    const results = await Promise.allSettled([
      run(h(), passkeyRevoke, { user_id: id, credential_id: a }, null),
      run(h(), passkeyRevoke, { user_id: id, credential_id: b }, null),
    ]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(await query(h(), "SELECT COUNT(*) AS n FROM credentials")).toEqual([{ n: 1 }]);
  });

  it("is not-found for another user's passkey, a missing passkey, or a missing user", async () => {
    const alice = await createUser();
    const bob = await createUser();
    await seedPasskey(h(), alice);
    const bobKey = await seedPasskey(h(), bob);
    await seedPasskey(h(), bob);
    await expectProblem(run(h(), passkeyRevoke, { user_id: alice, credential_id: bobKey }, null), "not-found");
    await expectProblem(run(h(), passkeyRevoke, { user_id: alice, credential_id: "AAAA" }, null), "not-found");
    await expectProblem(run(h(), passkeyRevoke, { user_id: MISSING, credential_id: bobKey }, null), "not-found");
    expect(await query(h(), "SELECT COUNT(*) AS n FROM credentials")).toEqual([{ n: 3 }]);
  });

  it("rejects a malformed credential ID with validation-failed", async () => {
    const id = await createUser();
    await expect(run(h(), passkeyRevoke, { user_id: id, credential_id: "not base64url!" }, null)).rejects.toMatchObject({
      kind: "validation-failed",
      pointers: ["/credential_id"],
    });
  });

  it("revokes a disabled user's passkey too", async () => {
    const id = await createUser();
    const a = await seedPasskey(h(), id);
    await seedPasskey(h(), id);
    await run(h(), userDisable, { user_id: id });
    await expect(run(h(), passkeyRevoke, { user_id: id, credential_id: a }, null)).resolves.toMatchObject({ status: 200 });
  });
});
