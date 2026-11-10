// The D1 adapters of the admin-only ports. A separate entry point (`@idp/d1-adapter/admin`) from the Database
// adapter, because the IdP Worker imports the package too and must never bundle the admin modules of the core
// (eslint.config.js bans this entry from the IdP Worker).
import { AdminNonceStoreError, adminNonceClaimStatements, type AdminNonceClaim, type AdminNonceStore } from "@idp/core/admin";
import { DatabaseError } from "@idp/core/shared";
import { createD1Database } from "./d1.js";

/**
 * Wraps a D1 binding as the core's {@link AdminNonceStore}.
 *
 * The sweep and the insert of {@link adminNonceClaimStatements} run as one D1 batch, so they commit together.
 *
 * @param binding The D1 binding from the admin Worker's environment.
 * @returns An {@link AdminNonceStore} whose `claim` rejects only with {@link AdminNonceStoreError}.
 */
export function createD1AdminNonceStore(binding: D1Database): AdminNonceStore {
  const db = createD1Database(binding);
  return {
    async claim(nonce: string, expiresAt: number, now: number): Promise<AdminNonceClaim> {
      let changes: number | undefined;
      try {
        changes = (await db.batch(adminNonceClaimStatements(nonce, expiresAt, now)))[1]?.changes;
      } catch (cause) {
        if (cause instanceof DatabaseError) throw new AdminNonceStoreError(`nonce claim failed: ${cause.message}`, { cause });
        throw cause;
      }
      if (changes === 1) return "fresh";
      if (changes === 0) return "replayed";
      // Any other count means the statement did not do what the core wrote; refuse rather than guess.
      throw new AdminNonceStoreError(`nonce insert changed ${String(changes)} rows`);
    },
  };
}
