// The user × client pairs a write newly enables (docs/design/authorization.md, "権限の広がりを見せる"). Each query
// runs in the write's batch, before the write, and returns the pairs that effective_access will gain: the pairs the
// write makes reachable, counted only through enabled users, groups, and clients, minus the pairs already allowed.
import type { SqlStatement } from "../shared/index.js";

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
