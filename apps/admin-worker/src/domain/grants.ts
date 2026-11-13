// Access management (docs/design/authorization.md, docs/design/idpctl.md): grant_add, grant_remove, grants_list, and
// access_check. A grant is principal × client, the same for users and groups; effective_access is the only judge.
import { accessCheckOutput, grantAddOutput, grantRemoveOutput, grantsListOutput } from "./outputs.js";
import { z } from "zod";
import { isUuidV4 } from "@idp/identifiers";
import type { SqlRow } from "@idp/db";
import { pairsAsJson, pairsEnabledByGrant, toPairs, type AccessPair, type Principal } from "./access.js";
import { currentEnablementSql, type Enablement } from "./enablement.js";
import type { ReadOperation, WriteOperation } from "./operation.js";
import { readPage, type Page, type PageQuery } from "./paging.js";
import { AdminProblem } from "./problem.js";
import { clientIdSchema, pageInputShape, uuidSchema, type PageInput } from "./schemas.js";

/** A principal written as `user:<id>` or `group:<id>`, the form the API path and the audit log use. */
export type PrincipalRef = `user:${string}` | `group:${string}`;

const principalSchema = z
  .string()
  .refine(
    (value) => {
      const [kind, id, ...rest] = value.split(":");
      return rest.length === 0 && (kind === "user" || kind === "group") && id !== undefined && isUuidV4(id);
    },
    { message: "must be user:<id> or group:<id>" },
  )
  .transform((value): Principal => {
    const [kind, id] = value.split(":") as ["user" | "group", string];
    return { kind, id };
  });

function principalRef(principal: Principal): PrincipalRef {
  return `${principal.kind}:${principal.id}`;
}

type GrantInput = { readonly client_id: string; readonly principal: Principal };

// The prefix must match principals.kind: a group ID written as user:<id> names no grantee (idpctl.md).
function principalExists(principal: Principal): { readonly sql: string; readonly params: readonly string[] } {
  return { sql: "EXISTS (SELECT 1 FROM principals WHERE id = ? AND kind = ?)", params: [principal.id, principal.kind] };
}

/** The result of grant_add. */
export type GrantAddResult = { readonly client_id: string; readonly principal: PrincipalRef; readonly newly_enabled: readonly AccessPair[] };

/**
 * grant_add: grants a user or a group a client, and returns and records the user × client pairs this newly enables.
 * An existing grant succeeds without writing; a missing client or principal is not-found.
 */
export const grantAdd: WriteOperation<GrantInput, GrantAddResult> = {
  name: "grant_add",
  class: { access: "write", concern: "access" },
  establishesIdentity: false,
  idempotent: false,
  target: { kind: "client", field: "client_id" },
  input: z.strictObject({ client_id: clientIdSchema, principal: principalSchema }),
  http: { method: "PUT", path: "/v1/clients/{id}/grants/{principal}", status: 200 },
  output: grantAddOutput,
  async plan(ctx, input) {
    const { client_id: clientId, principal } = input;
    const exists = principalExists(principal);
    const guard = {
      sql:
        `EXISTS (SELECT 1 FROM clients WHERE id = ?) AND ${exists.sql} ` +
        "AND NOT EXISTS (SELECT 1 FROM client_access WHERE principal_id = ? AND client_id = ?)",
      params: [clientId, ...exists.params, principal.id, clientId],
    };
    const pairs = pairsEnabledByGrant(principal, clientId);
    return {
      target: `client:${clientId}`,
      probe: {
        sql:
          `SELECT EXISTS (SELECT 1 FROM clients WHERE id = ?) AS client_found, ${exists.sql} AS principal_found, ` +
          "EXISTS (SELECT 1 FROM client_access WHERE principal_id = ? AND client_id = ?) AS granted",
        params: [clientId, ...exists.params, principal.id, clientId],
      },
      guard,
      writes: [
        { sql: `SELECT * FROM (${pairs.sql}) WHERE ${guard.sql}`, params: [...pairs.params, ...guard.params] },
        {
          sql: `INSERT INTO client_access (principal_id, client_id, created_at) SELECT ?, ?, ? WHERE ${guard.sql}`,
          params: [principal.id, clientId, ctx.now(), ...guard.params],
        },
      ],
      detail: { principal: principalRef(principal) },
      computed: [{ key: "newly_enabled", ...pairsAsJson(pairs) }],
      settle(probe) {
        if (probe["client_found"] !== 1) throw new AdminProblem("not-found", "The client does not exist");
        if (probe["principal_found"] !== 1) throw new AdminProblem("not-found", `The ${principal.kind} does not exist`);
        return probe["granted"] === 1 ? "noop" : "write";
      },
      result: (writes) => ({ client_id: clientId, principal: principalRef(principal), newly_enabled: toPairs(writes[0]?.rows ?? []) }),
    };
  },
};

/** The result of grant_remove. */
export type GrantRemoveResult = { readonly client_id: string; readonly principal: PrincipalRef };

/** grant_remove: deletes a grant; a grant that does not exist (including a mismatched prefix) is not-found. */
export const grantRemove: WriteOperation<GrantInput, GrantRemoveResult> = {
  name: "grant_remove",
  class: { access: "write", concern: "access" },
  establishesIdentity: false,
  idempotent: false,
  target: { kind: "client", field: "client_id" },
  input: z.strictObject({ client_id: clientIdSchema, principal: principalSchema }),
  http: { method: "DELETE", path: "/v1/clients/{id}/grants/{principal}", status: 200 },
  output: grantRemoveOutput,
  async plan(_ctx, input) {
    const { client_id: clientId, principal } = input;
    const exists = principalExists(principal);
    const guard = {
      sql: `${exists.sql} AND EXISTS (SELECT 1 FROM client_access WHERE principal_id = ? AND client_id = ?)`,
      params: [...exists.params, principal.id, clientId],
    };
    return {
      target: `client:${clientId}`,
      probe: { sql: `SELECT ${guard.sql} AS granted`, params: guard.params },
      guard,
      writes: [{ sql: `DELETE FROM client_access WHERE principal_id = ? AND client_id = ? AND ${guard.sql}`, params: [principal.id, clientId, ...guard.params] }],
      detail: { principal: principalRef(principal) },
      settle(probe) {
        if (probe["granted"] !== 1) throw new AdminProblem("not-found", "The grant does not exist");
        return "write";
      },
      result: () => ({ client_id: clientId, principal: principalRef(principal) }),
    };
  },
};

/** One grant in grants_list. */
export type GrantSummary = { readonly principal: PrincipalRef; readonly client_id: string; readonly created_at: number };

type GrantsListInput = PageInput & { readonly client_id?: string | undefined; readonly principal?: Principal | undefined };

function grantsPage(input: GrantsListInput): PageQuery {
  const filters = [];
  if (input.client_id !== undefined) filters.push({ sql: "a.client_id = ?", params: [input.client_id] });
  if (input.principal !== undefined) filters.push({ sql: "a.principal_id = ? AND p.kind = ?", params: [input.principal.id, input.principal.kind] });
  return {
    columns: "a.principal_id, p.kind, a.client_id, a.created_at",
    from: "client_access a JOIN principals p ON p.id = a.principal_id",
    filters,
    key: [
      { sql: "a.created_at", column: "created_at", type: "integer" },
      { sql: "a.principal_id", column: "principal_id", type: "text" },
      { sql: "a.client_id", column: "client_id", type: "text" },
    ],
    order: "asc",
  };
}

function toGrantSummary(row: SqlRow): GrantSummary {
  return {
    principal: `${row["kind"] as "user" | "group"}:${row["principal_id"] as string}`,
    client_id: row["client_id"] as string,
    created_at: row["created_at"] as number,
  };
}

/** grants_list: grants in creation order, optionally for one client or one principal. */
export const grantsList: ReadOperation<GrantsListInput, Page<GrantSummary>> = {
  name: "grants_list",
  class: { access: "read" },
  establishesIdentity: false,
  input: z.strictObject({ ...pageInputShape, client_id: clientIdSchema.optional(), principal: principalSchema.optional() }),
  http: { method: "GET", path: "/v1/grants", status: 200 },
  output: grantsListOutput,
  read: (ctx, input) => readPage(ctx.db, grantsPage(input), input, toGrantSummary),
};

/** One grant that could let the user use the client, and whether it counts now. */
export type AccessGrant =
  | { readonly via: "direct"; readonly principal: PrincipalRef; readonly counts: boolean }
  | { readonly via: "group"; readonly principal: PrincipalRef; readonly group_enablement: Enablement; readonly counts: boolean };

/** Why a denied pair is denied. */
export type AccessDenialReason = "user-disabled" | "client-disabled" | "no-grant" | "group-disabled";

/** The result of access_check. */
export type AccessCheckResult = {
  readonly user_id: string;
  readonly client_id: string;
  readonly allowed: boolean;
  readonly user_enablement: Enablement;
  readonly client_enablement: Enablement;
  /** The direct grant and the grants through the user's groups, in that order. */
  readonly grants: readonly AccessGrant[];
  /** Empty when allowed. */
  readonly denied_because: readonly AccessDenialReason[];
};

/**
 * access_check(user, client): whether effective_access allows the pair, and why: the matching grants (direct or
 * through which group) or what is missing, disabled users, clients, and groups included. The verdict is read from
 * the view itself; the explanation is rebuilt from the same snapshot and must agree with it.
 */
export const accessCheck: ReadOperation<{ readonly user: string; readonly client: string }, AccessCheckResult> = {
  name: "access_check",
  class: { access: "read" },
  establishesIdentity: false,
  input: z.strictObject({ user: uuidSchema, client: clientIdSchema }),
  http: { method: "GET", path: "/v1/access", status: 200 },
  output: accessCheckOutput,
  async read(ctx, input) {
    const { user, client } = input;
    const [head, grants] = await ctx.db.batch([
      {
        sql:
          "SELECT EXISTS (SELECT 1 FROM users WHERE id = ?) AS user_found, EXISTS (SELECT 1 FROM clients WHERE id = ?) AS client_found, " +
          `${currentEnablementSql("user")} AS user_enablement, ${currentEnablementSql("client")} AS client_enablement, ` +
          "EXISTS (SELECT 1 FROM effective_access WHERE user_id = ? AND client_id = ?) AS allowed",
        params: [user, client, user, client, user, client],
      },
      {
        sql:
          "SELECT 'direct' AS via, a.principal_id, NULL AS group_enablement FROM client_access a WHERE a.principal_id = ? AND a.client_id = ? " +
          `UNION ALL SELECT 'group', m.group_id, ${currentEnablementSql("group", "m.group_id")} FROM group_members m ` +
          "JOIN client_access a ON a.principal_id = m.group_id AND a.client_id = ? WHERE m.user_id = ? ORDER BY 1, 2",
        params: [user, client, client, user],
      },
    ]);
    const row = head?.rows[0];
    if (row?.["user_found"] !== 1) throw new AdminProblem("not-found", "The user does not exist");
    if (row["client_found"] !== 1) throw new AdminProblem("not-found", "The client does not exist");
    const userEnabled = row["user_enablement"] === "enabled";
    const clientEnabled = row["client_enablement"] === "enabled";
    const matched: AccessGrant[] = (grants?.rows ?? []).map((g) => {
      if (g["via"] === "direct") return { via: "direct", principal: `user:${g["principal_id"] as string}`, counts: userEnabled && clientEnabled };
      const groupEnablement = g["group_enablement"] as Enablement;
      return {
        via: "group",
        principal: `group:${g["principal_id"] as string}`,
        group_enablement: groupEnablement,
        counts: userEnabled && clientEnabled && groupEnablement === "enabled",
      };
    });
    const allowed = row["allowed"] === 1;
    // The view decides; a disagreement means this explanation no longer mirrors effective_access.
    if (allowed !== matched.some((g) => g.counts)) {
      throw new AdminProblem("internal", "access_check explanation disagrees with effective_access");
    }
    const reasons: AccessDenialReason[] = [];
    if (!allowed) {
      if (!userEnabled) reasons.push("user-disabled");
      if (!clientEnabled) reasons.push("client-disabled");
      if (matched.length === 0) reasons.push("no-grant");
      else if (matched.every((g) => g.via === "group" && g.group_enablement !== "enabled")) reasons.push("group-disabled");
    }
    return {
      user_id: user,
      client_id: client,
      allowed,
      user_enablement: row["user_enablement"] as Enablement,
      client_enablement: row["client_enablement"] as Enablement,
      grants: matched,
      denied_because: reasons,
    };
  },
};
