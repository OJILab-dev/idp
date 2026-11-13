// A Worker for admin-signature-vectors.test.ts: it runs the shared core's verifier and the admin nonce store inside
// workerd on the request workerd received, so @target-uri is built from the URL the runtime hands a Worker. It
// stands in for the admin Worker's gate until plan step 6 wires the verifier there (docs/design/hosting-modes.md 10).
import { verifyAdminSignature, type AdminSigningKey } from "../../../src/domain/signature.js";
import { createAdminNonceStore } from "../../../src/domain/nonces.js";
import { createD1Database } from "../../../../../packages/cloudflare/src/d1/index.js";

type Env = {
  readonly DB: D1Database;
  /** The verifier's clock, fixed by the vectors. */
  readonly NOW: string;
  /** The allowlist as `admin_signing_keys` writes it: keyid, name, and base64 SPKI DER. */
  readonly KEYS: string;
};

type KeyRow = { readonly keyid: string; readonly name: string; readonly public_key: string };

async function importKeys(json: string): Promise<ReadonlyMap<string, AdminSigningKey>> {
  const keys = new Map<string, AdminSigningKey>();
  for (const row of JSON.parse(json) as readonly KeyRow[]) {
    const spki = Uint8Array.from(atob(row.public_key), (c) => c.charCodeAt(0));
    const publicKey = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-384" }, false, ["verify"]);
    keys.set(row.keyid, { keyid: row.keyid, name: row.name, publicKey });
  }
  return keys;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const now = Number(env.NOW);
    const result = await verifyAdminSignature(
      { method: request.method, url: request.url, headers: request.headers, body: new Uint8Array(await request.arrayBuffer()) },
      await importKeys(env.KEYS),
      now,
    );
    // Item 10 of 3.8: only a verified request reaches the nonce store.
    const claim = result.ok ? await createAdminNonceStore(createD1Database(env.DB)).claim(result.nonce, result.expiresAt, now) : null;
    return Response.json({ url: request.url, result, claim });
  },
};
