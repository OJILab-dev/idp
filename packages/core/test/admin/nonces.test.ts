// The admin nonce store (src/admin/nonces.ts) on a Database over a real local D1 with every migration applied
// (docs/design/hosting-modes.md 3.6).
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AdminNonceStoreError, createAdminNonceStore, type AdminNonceStore } from "../../src/admin/index.js";
import { createD1Database } from "../../../cloudflare/src/d1/index.js";
import { createTestD1, type TestD1 } from "../../../../contract/test/d1.js";

const NOW = 1_767_225_600;
const NONCE = "DeSswvZ-qFqcZhVfI2rcdFVorRiuH6QVrl8Hy7i2liM";

let t: TestD1;
let store: AdminNonceStore;

beforeEach(async () => {
  t = await createTestD1();
  store = createAdminNonceStore(createD1Database(t.db));
});

afterEach(async () => {
  await t.dispose();
});

async function rows(): Promise<readonly unknown[]> {
  return (await t.db.prepare("SELECT nonce, expires_at FROM admin_request_nonces ORDER BY nonce").all()).results;
}

describe("createAdminNonceStore", () => {
  it("stores a new nonce with its expiry and reports it fresh", async () => {
    await expect(store.claim(NONCE, NOW + 60, NOW)).resolves.toBe("fresh");
    expect(await rows()).toEqual([{ nonce: NONCE, expires_at: NOW + 60 }]);
  });

  it("reports the second claim of the same nonce as a replay and keeps the first row", async () => {
    await store.claim(NONCE, NOW + 60, NOW);
    await expect(store.claim(NONCE, NOW + 61, NOW + 1)).resolves.toBe("replayed");
    expect(await rows()).toEqual([{ nonce: NONCE, expires_at: NOW + 60 }]);
  });

  it("deletes only the rows that expired more than one window before now, in the same batch", async () => {
    await store.claim("expired", NOW - 61, NOW - 121);
    await store.claim("edge", NOW - 60, NOW - 120);
    await store.claim(NONCE, NOW + 60, NOW);
    expect(await rows()).toEqual([
      { nonce: NONCE, expires_at: NOW + 60 },
      { nonce: "edge", expires_at: NOW - 60 },
    ]);
  });

  it("does not let a later claim's sweep free a nonce that a replay verified at the window's end can still claim", async () => {
    // L was accepted with created = c; its replay L' verifies at now = c + 60, the last second of the window.
    const c = NOW;
    await expect(store.claim(NONCE, c + 60, c)).resolves.toBe("fresh");
    // Another admin request is claimed first, one second later, while L' is still in flight.
    await expect(store.claim("other", c + 121, c + 61)).resolves.toBe("fresh");
    await expect(store.claim(NONCE, c + 60, c + 60)).resolves.toBe("replayed");
  });

  it.each([
    ["now is NaN", NOW + 60, Number.NaN],
    ["now is not an integer", NOW + 60, NOW + 0.5],
    ["expiresAt is NaN", Number.NaN, NOW],
  ])("fails closed with AdminNonceStoreError when %s, writing nothing", async (_, expiresAt, now) => {
    await expect(store.claim(NONCE, expiresAt, now)).rejects.toThrow(AdminNonceStoreError);
    expect(await rows()).toEqual([]);
  });

  it("fails closed with AdminNonceStoreError when D1 fails for another reason", async () => {
    await t.db.prepare("DROP TABLE admin_request_nonces").run();
    await expect(store.claim(NONCE, NOW + 60, NOW)).rejects.toThrow(AdminNonceStoreError);
  });
});
