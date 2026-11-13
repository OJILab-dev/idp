// The user × client pairs a write newly enables (docs/design/authorization.md, "権限の広がりを見せる"). Each query
// runs in the write's batch, before the write, and returns the pairs that effective_access will gain: the pairs the
// write makes reachable, counted only through enabled users, groups, and clients, minus the pairs already allowed.
import type { SqlStatement } from "@idp/core/db";

/** One newly enabled pair. */
export type AccessPair = { readonly user_id: string; readonly client_id: string };

/**
 * Builds the query of the pairs `group_member_add(group, user)` enables: the group's enabled clients for the user,
 * when both the user and the group are enabled and the user cannot already use the client.
 *
 * @param groupId The group.
 * @param userId The user joining it.
 * @returns A SELECT of `user_id, client_id`, ordered by client ID.
 */
export function pairsEnabledByMembership(groupId: string, userId: string): SqlStatement {
  return {
    sql:
      "SELECT ? AS user_id, a.client_id FROM client_access a " +
      "JOIN client_enablement ce ON ce.client_id = a.client_id AND ce.enablement = 'enabled' " +
      "WHERE a.principal_id = ? " +
      "AND EXISTS (SELECT 1 FROM user_enablement WHERE user_id = ? AND enablement = 'enabled') " +
      "AND EXISTS (SELECT 1 FROM group_enablement WHERE group_id = ? AND enablement = 'enabled') " +
      "AND NOT EXISTS (SELECT 1 FROM effective_access e WHERE e.user_id = ? AND e.client_id = a.client_id) " +
      "ORDER BY a.client_id",
    params: [userId, groupId, userId, groupId, userId],
  };
}

/**
 * Builds the query of the pairs `grant_add(principal, client)` enables: the user itself, or every member of the
 * group, counted only when the user, the group, and the client are enabled and the pair is not already allowed.
 *
 * @param principal The grantee.
 * @param clientId The client.
 * @returns A SELECT of `user_id, client_id`, ordered by user ID.
 */
export function pairsEnabledByGrant(principal: Principal, clientId: string): SqlStatement {
  const tail =
    "AND EXISTS (SELECT 1 FROM user_enablement ue WHERE ue.user_id = m.user_id AND ue.enablement = 'enabled') " +
    "AND EXISTS (SELECT 1 FROM client_enablement WHERE client_id = ? AND enablement = 'enabled') " +
    "AND NOT EXISTS (SELECT 1 FROM effective_access e WHERE e.user_id = m.user_id AND e.client_id = ?) ORDER BY m.user_id";
  if (principal.kind === "user") {
    return {
      sql: `SELECT m.user_id, ? AS client_id FROM (SELECT id AS user_id FROM users WHERE id = ?) m WHERE 1 ${tail}`,
      params: [clientId, principal.id, clientId, clientId],
    };
  }
  return {
    sql:
      "SELECT m.user_id, ? AS client_id FROM group_members m WHERE m.group_id = ? " +
      `AND EXISTS (SELECT 1 FROM group_enablement WHERE group_id = ? AND enablement = 'enabled') ${tail}`,
    params: [clientId, principal.id, principal.id, clientId, clientId],
  };
}

/** A grantee: a user or a group, by ID (docs/design/authorization.md). */
export type Principal = { readonly kind: "user" | "group"; readonly id: string };

/**
 * Wraps a pairs query as the JSON array the audit row's `newly_enabled` member holds.
 *
 * @param pairs A query from this module.
 * @returns A SELECT of one JSON array of `{user_id, client_id}`; `[]` when there are none.
 */
export function pairsAsJson(pairs: SqlStatement): SqlStatement {
  return {
    sql: `SELECT json_group_array(json_object('user_id', user_id, 'client_id', client_id)) FROM (${pairs.sql})`,
    params: pairs.params,
  };
}

/**
 * Reads pairs from the rows of a pairs query.
 *
 * @param rows The rows.
 * @returns The pairs, in row order.
 */
export function toPairs(rows: readonly Readonly<Record<string, unknown>>[]): readonly AccessPair[] {
  return rows.map((row) => ({ user_id: row["user_id"] as string, client_id: row["client_id"] as string }));
}
