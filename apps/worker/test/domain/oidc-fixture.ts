// A local D1 with migration 0001 applied, seeded through plain SQL, plus a settable clock and a counting random
// source, so the OIDC use cases run against the real schema and every token they mint is predictable.
import { createD1Database } from "@idp/cloudflare/d1";
import { createTestD1, type TestD1 } from "../../../../contract/test/d1.js";
import { base64urlEncode } from "@idp/base64url";
import { sha256Base64url } from "@idp/jwk-thumbprint";
import { parseIssuer } from "@idp/core/issuer";
import type { Database, SqlStatement, SqlValue } from "@idp/core/db";
import { loadSigningKeys, type Clock, type OidcDeps, type RandomSource, type SigningKeySet } from "../../src/domain/index.js";
import { generateEd25519Jwk, generateRsaJwk } from "./keys.js";
import { vectors } from "../../../../packages/core/test/vectors.js";

export const NOW = 1_800_000_000;
export const issuer = parseIssuer("https://idp.example.com");

/** A clock the test moves by hand. */
export class FakeClock implements Clock {
  constructor(private current: number) {}
  now(): number {
    return this.current;
  }
  advance(seconds: number): void {
    this.current += seconds;
  }
}

/** Tokens 1, 2, 3, … as 32 big-endian bytes, so each call is distinct and the sequence repeats across runs. */
export class CountingRandom implements RandomSource {
  private counter = 0;
  token(): string {
    this.counter += 1;
    const bytes = new Uint8Array(32);
    new DataView(bytes.buffer).setUint32(28, this.counter);
    return base64urlEncode(bytes);
  }
}

let edOnlyKeys: Promise<SigningKeySet> | undefined;
let rsaKeys: Promise<SigningKeySet> | undefined;

/** One Ed25519-only key set per test file; generating keys is slower than the tests that use them. */
export function sharedEd25519Keys(): Promise<SigningKeySet> {
  edOnlyKeys ??= generateEd25519Jwk().then((jwk) => loadSigningKeys({ ed25519Current: JSON.stringify(jwk) }));
  return edOnlyKeys;
}

/** One Ed25519 + RSA key set per test file. */
export function sharedRsaKeys(): Promise<SigningKeySet> {
  rsaKeys ??= Promise.all([generateEd25519Jwk(), generateRsaJwk()]).then(([ed, rsa]) =>
    loadSigningKeys({ ed25519Current: JSON.stringify(ed), rsaCurrent: JSON.stringify(rsa) }),
  );
  return rsaKeys;
}

export type ClientSeed = {
  readonly id: string;
  readonly type?: "confidential" | "public";
  readonly secret?: string;
  readonly redirectUris?: readonly string[];
  /** Left at the column default (an empty list) when omitted, as a Worker before migration 0005 would write it. */
  readonly postLogoutRedirectUris?: readonly string[];
  readonly alg?: "Ed25519" | "RS256";
  readonly enabled?: boolean | "no-row";
};

export type Fixture = {
  readonly t: TestD1;
  readonly db: Database;
  readonly clock: FakeClock;
  readonly random: CountingRandom;
  readonly deps: OidcDeps;
  readonly run: (sql: string, ...params: SqlValue[]) => Promise<void>;
  readonly query: (sql: string, ...params: SqlValue[]) => Promise<readonly Readonly<Record<string, SqlValue>>[]>;
  readonly addUser: (id: string, options?: { readonly name?: string; readonly enabled?: boolean | "no-row" }) => Promise<void>;
  readonly addCredential: (id: string, userId: string) => Promise<void>;
  readonly addClient: (seed: ClientSeed) => Promise<void>;
  readonly grant: (principalId: string, clientId: string) => Promise<void>;
  readonly setUserEnabled: (userId: string, enabled: boolean) => Promise<void>;
  readonly setClientEnabled: (clientId: string, enabled: boolean) => Promise<void>;
  /** Inserts a session row and returns the plaintext token the cookie would carry. */
  readonly addSession: (userId: string, credentialId: string, authTime?: number) => Promise<string>;
  readonly dispose: () => Promise<void>;
};

export const CONFIDENTIAL_SECRET = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3I";

/**
 * Creates a fixture database and the dependencies the use cases take.
 *
 * @param keys The signing keys; Ed25519-only unless a test needs RS256.
 */
export async function createFixture(keys?: SigningKeySet): Promise<Fixture> {
  const t = await createTestD1();
  const db = createD1Database(t.db);
  const clock = new FakeClock(NOW);
  const random = new CountingRandom();
  const deps: OidcDeps = { db, issuer, keys: keys ?? (await sharedEd25519Keys()), clock, random };
  let sessionCounter = 0;
  let eventTime = NOW - 1000;

  async function run(sql: string, ...params: SqlValue[]): Promise<void> {
    await db.batch([{ sql, params }]);
  }
  async function query(sql: string, ...params: SqlValue[]): Promise<readonly Readonly<Record<string, SqlValue>>[]> {
    const [result] = await db.batch([{ sql, params }]);
    return result?.rows ?? [];
  }
  function enablementEvent(table: string, column: string, id: string, enabled: boolean): SqlStatement {
    eventTime += 1;
    return {
      sql: `INSERT INTO ${table} (${column}, enablement, occurred_at) VALUES (?, ?, ?)`,
      params: [id, enabled ? "enabled" : "disabled", eventTime],
    };
  }

  return {
    t,
    db,
    clock,
    random,
    deps,
    run,
    query,
    async addUser(id, options = {}) {
      const handle = new Uint8Array(64);
      handle.set(new TextEncoder().encode(id).subarray(0, 64));
      const statements: SqlStatement[] = [
        { sql: "INSERT INTO principals (id, kind) VALUES (?, 'user')", params: [id] },
        {
          sql: "INSERT INTO users (id, user_handle, name, created_at) VALUES (?, ?, ?, ?)",
          params: [id, handle, options.name ?? "Alice", NOW - 5000],
        },
      ];
      const enabled = options.enabled ?? true;
      if (enabled !== "no-row") statements.push(enablementEvent("user_enablement_events", "user_id", id, enabled));
      await db.batch(statements);
    },
    async addCredential(id, userId) {
      await run(
        `INSERT INTO credentials (id, user_id, public_key, sign_count, backup_eligible, backup_state, created_at, created_via)
         VALUES (?, ?, ?, 0, 1, 1, ?, 'enroll')`,
        id,
        userId,
        new Uint8Array([1, 2, 3]),
        NOW - 4000,
      );
    },
    async addClient(seed) {
      const type = seed.type ?? "confidential";
      const secretHash = type === "confidential" ? await sha256Base64url(seed.secret ?? CONFIDENTIAL_SECRET) : null;
      const statements: SqlStatement[] = [
        {
          sql: `INSERT INTO clients (id, name, client_type, secret_hash, redirect_uris_json, id_token_signed_response_alg, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)`,
          params: [
            seed.id,
            seed.id,
            type,
            secretHash,
            JSON.stringify(seed.redirectUris ?? ["https://app.example.com/callback"]),
            seed.alg ?? "Ed25519",
            NOW - 5000,
          ],
        },
      ];
      if (seed.postLogoutRedirectUris !== undefined) {
        statements.push({
          sql: "UPDATE clients SET post_logout_redirect_uris_json = ? WHERE id = ?",
          params: [JSON.stringify(seed.postLogoutRedirectUris), seed.id],
        });
      }
      const enabled = seed.enabled ?? true;
      if (enabled !== "no-row") statements.push(enablementEvent("client_enablement_events", "client_id", seed.id, enabled));
      await db.batch(statements);
    },
    async grant(principalId, clientId) {
      await run("INSERT INTO client_access (principal_id, client_id, created_at) VALUES (?, ?, ?)", principalId, clientId, NOW - 3000);
    },
    async setUserEnabled(userId, enabled) {
      await db.batch([enablementEvent("user_enablement_events", "user_id", userId, enabled)]);
    },
    async setClientEnabled(clientId, enabled) {
      await db.batch([enablementEvent("client_enablement_events", "client_id", clientId, enabled)]);
    },
    async addSession(userId, credentialId, authTime = clock.now() - 60) {
      sessionCounter += 1;
      const bytes = new Uint8Array(32).fill(0xa0);
      bytes[31] = sessionCounter;
      const token = base64urlEncode(bytes);
      await run(
        "INSERT INTO sessions (token_hash, user_id, credential_id, auth_time, expires_at) VALUES (?, ?, ?, ?, ?)",
        await sha256Base64url(token),
        userId,
        credentialId,
        authTime,
        authTime + 3600,
      );
      return token;
    },
    dispose: () => t.dispose(),
  };
}

/** The PKCE pair used by the tests: the contract vector from RFC 7636 Appendix B. */
export const PKCE = {
  verifier: vectors.pkce_s256[0]?.verifier ?? "",
  challenge: vectors.pkce_s256[0]?.challenge ?? "",
} as const;
