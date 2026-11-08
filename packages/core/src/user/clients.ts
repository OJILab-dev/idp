// Reading a registered client. The IdP Worker only compares against stored values; the admin Worker validated them on
// write, so a row that does not have the contract's shape is corruption and is rejected, never repaired.
import type { Database } from "../shared/index.js";
import type { JwsAlgorithm } from "./signing-keys.js";

/** A client as the user-facing use cases see it. */
export type RegisteredClient = {
  readonly id: string;
  /** The RFC 6749 §2.1 client type; it fixes the token endpoint authentication (docs/design/clients.md). */
  readonly clientType: "confidential" | "public";
  /** The SHA-256 of the secret; present exactly for confidential clients. */
  readonly secretHash: string | null;
  readonly redirectUris: readonly string[];
  readonly idTokenAlg: JwsAlgorithm;
  /** Whether the latest `client_enablement_events` row is `enabled`; false when there is none (fail-closed). */
  readonly enabled: boolean;
};

/** Thrown when a stored row does not have the shape the schema and the contract promise. */
export class CorruptRowError extends Error {
  override readonly name = "CorruptRowError";
}

/**
 * Loads a client and its current enablement.
 *
 * @param db The database.
 * @param clientId A well-formed client ID.
 * @returns The client, or `undefined` when no such client exists.
 * @throws {CorruptRowError} The row's type, secret, redirect URIs, or algorithm is malformed.
 * @throws {DatabaseError} The read failed.
 */
export async function loadClient(db: Database, clientId: string): Promise<RegisteredClient | undefined> {
  const [result] = await db.batch([
    {
      sql: `SELECT c.id, c.client_type, c.secret_hash, c.redirect_uris_json, c.id_token_signed_response_alg,
                   (SELECT ce.enablement FROM client_enablement ce WHERE ce.client_id = c.id) AS enablement
            FROM clients c WHERE c.id = ?`,
      params: [clientId],
    },
  ]);
  const row = result?.rows[0];
  if (row === undefined) return undefined;
  const clientType = row["client_type"];
  const secretHash = row["secret_hash"];
  const alg = row["id_token_signed_response_alg"];
  if (clientType !== "confidential" && clientType !== "public") throw new CorruptRowError("client_type is malformed");
  if (clientType === "confidential" ? typeof secretHash !== "string" : secretHash !== null) {
    throw new CorruptRowError("secret_hash does not match client_type");
  }
  if (alg !== "Ed25519" && alg !== "RS256") throw new CorruptRowError("id_token_signed_response_alg is malformed");
  return {
    id: clientId,
    clientType,
    secretHash: secretHash as string | null,
    redirectUris: parseRedirectUris(row["redirect_uris_json"]),
    idTokenAlg: alg,
    enabled: row["enablement"] === "enabled",
  };
}

function parseRedirectUris(value: unknown): readonly string[] {
  if (typeof value !== "string") throw new CorruptRowError("redirect_uris_json is not text");
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch (cause) {
    throw new CorruptRowError("redirect_uris_json is not JSON", { cause });
  }
  if (!Array.isArray(parsed) || !parsed.every((uri): uri is string => typeof uri === "string" && uri !== "")) {
    throw new CorruptRowError("redirect_uris_json is not an array of URIs");
  }
  return parsed;
}
