// Conformance of the D1 nonce store to the AdminNonceStore port (packages/core/src/admin/nonces.ts), against a real
// local D1 with every migration applied (docs/design/hosting-modes.md 3.6).
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AdminNonceStoreError, type AdminNonceStore } from "@idp/core/admin";
import { createTestD1, type TestD1 } from "../../../contract/test/d1.js";
import { createD1AdminNonceStore } from "../src/admin.js";

const NOW = 1_767_225_600;
const NONCE = "DeSswvZ-qFqcZhVfI2rcdFVorRiuH6QVrl8Hy7i2liM";

let t: TestD1;
let store: AdminNonceStore;

beforeEach(async () => {
  t = await createTestD1();
  store = createD1AdminNonceStore(t.db);
});

afterEach(async () => {
  await t.dispose();
});

async function rows(): Promise<readonly unknown[]> {
  return (await t.db.prepare("SELECT nonce, expires_at FROM admin_request_nonces ORDER BY nonce").all()).results;
}

describe("createD1AdminNonceStore", () => {
  it("stores a new nonce with its expiry and reports it fresh", async () => {
    await expect(store.claim(NONCE, NOW + 60, NOW)).resolves.toBe("fresh");
    expect(await rows()).toEqual([{ nonce: NONCE, expires_at: NOW + 60 }]);
  });

  it("reports the second claim of the same nonce as a replay and keeps the first row", async () => {
    await store.claim(NONCE, NOW + 60, NOW);
    await expect(store.claim(NONCE, NOW + 61, NOW + 1)).resolves.toBe("replayed");
    expect(await rows()).toEqual([{ nonce: NONCE, expires_at: NOW + 60 }]);
  });

  it("deletes the rows that expired before now in the same batch, and keeps the row expiring now", async () => {
    await store.claim("expired", NOW - 1, NOW - 61);
    await store.claim("edge", NOW, NOW - 60);
    await store.claim(NONCE, NOW + 60, NOW);
    expect(await rows()).toEqual([
      { nonce: NONCE, expires_at: NOW + 60 },
      { nonce: "edge", expires_at: NOW },
    ]);
  });

  it("fails closed with AdminNonceStoreError when D1 fails for another reason", async () => {
    await t.db.prepare("DROP TABLE admin_request_nonces").run();
    await expect(store.claim(NONCE, NOW + 60, NOW)).rejects.toThrow(AdminNonceStoreError);
  });
});
