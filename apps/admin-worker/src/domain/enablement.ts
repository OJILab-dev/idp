// Enabling and disabling users, clients, and groups: one appended row in the resource's enablement events, only
// when the state differs (docs/design/data-model.md, "有効・無効と削除しない行"). A resource without any event row
// counts as disabled (fail-closed), so the same rule is spelled as COALESCE(..., 'disabled') in SQL and here.
import { enablementOutput } from "./outputs.js";
import { z } from "zod";
import type { SqlCondition, SqlRow, SqlStatement } from "@idp/db";
import type { Concern, OperationName, WriteOperation } from "./operation.js";
import { AdminProblem } from "./problem.js";
import { clientIdSchema, uuidSchema } from "./schemas.js";

/** An enablement state. */
export type Enablement = "enabled" | "disabled";

/** The resources with an enablement event table. */
export type EnablementResource = "user" | "client" | "group";

type ResourceTables = {
  readonly table: string;
  readonly events: string;
  readonly view: string;
  readonly column: "user_id" | "client_id" | "group_id";
  readonly concern: Concern;
  readonly path: string;
};

const RESOURCES: Readonly<Record<EnablementResource, ResourceTables>> = {
  user: {
    table: "users",
    events: "user_enablement_events",
    view: "user_enablement",
    column: "user_id",
    concern: "user",
    path: "/v1/users/{id}/enablement-events",
  },
  client: {
    table: "clients",
    events: "client_enablement_events",
    view: "client_enablement",
    column: "client_id",
    concern: "rp",
    path: "/v1/clients/{id}/enablement-events",
  },
  group: {
    table: "groups",
    events: "group_enablement_events",
    view: "group_enablement",
    column: "group_id",
    concern: "user",
    path: "/v1/groups/{id}/enablement-events",
  },
};

/**
 * Builds the SQL expression of a resource's current state.
 *
 * @param resource The resource kind.
 * @param idExpression The SQL expression of the resource ID; a `?` placeholder by default.
 * @returns The expression; 'disabled' when no event row exists.
 */
export function currentEnablementSql(resource: EnablementResource, idExpression = "?"): string {
  const r = RESOURCES[resource];
  return `COALESCE((SELECT enablement FROM ${r.view} WHERE ${r.column} = ${idExpression}), 'disabled')`;
}

/**
 * Builds the first `enabled` event that every creation writes in its batch.
 *
 * @param resource The resource kind.
 * @param id The new resource's ID.
 * @param now The current time in UNIX seconds.
 * @param condition The condition under which the creation happened.
 * @returns The guarded INSERT.
 */
export function initialEnablementStatement(resource: EnablementResource, id: string, now: number, condition: SqlCondition): SqlStatement {
  const r = RESOURCES[resource];
  return {
    sql: `INSERT INTO ${r.events} (${r.column}, enablement, occurred_at) SELECT ?, 'enabled', ? WHERE ${condition.sql}`,
    params: [id, now, ...condition.params],
  };
}

/**
 * Names the operation an enablement event performs; the admin API's `*_enablement_switch` endpoint calls this with
 * the body's value, and the name it returns is what the use case, the audit log, and idempotency_keys record.
 *
 * @param resource The resource kind of the endpoint.
 * @param enablement The `enablement` member of the request body.
 * @returns `user_enable`, `user_disable`, and so on.
 */
export function enablementOperationName(resource: EnablementResource, enablement: Enablement): OperationName {
  return `${resource}_${enablement === "enabled" ? "enable" : "disable"}`;
}

/**
 * The body of `POST /v1/{users|clients|groups}/{id}/enablement-events`. Its value picks the operation through
 * {@link enablementOperationName}; the operation's own input holds only the ID, so the request hash still covers the
 * path and the operation name tells enable from disable.
 */
export const enablementEventSchema = z.strictObject({ enablement: z.enum(["enabled", "disabled"]) });

/** The result of an enablement change. */
export type EnablementResult = {
  readonly id: string;
  readonly enablement: Enablement;
  readonly occurred_at: number;
};

type IdInput = { readonly id: string };

/**
 * Builds the `<resource>_enable` or `<resource>_disable` operation.
 *
 * The guard is "exists and the current state differs", put in the same statement as the append, so two concurrent
 * changes cannot append the same state twice. Disabling a user also deletes all of that user's sessions in the same
 * batch, before the append, while the guard still holds.
 *
 * @param resource The resource kind.
 * @param enablement The state to move to.
 * @returns The operation.
 */
export function enablementOperation(resource: EnablementResource, enablement: Enablement): WriteOperation<IdInput, EnablementResult> {
  const r = RESOURCES[resource];
  const idSchema = resource === "client" ? clientIdSchema : uuidSchema;
  const name = enablementOperationName(resource, enablement);
  return {
    name,
    class: { access: "write", concern: r.concern },
    establishesIdentity: false,
    idempotent: true,
    target: { kind: resource, field: r.column } as WriteOperation<IdInput, EnablementResult>["target"],
    input: z.strictObject({ [r.column]: idSchema }).transform((value): IdInput => ({ id: value[r.column] as string })),
    http: { method: "POST", path: r.path, status: 201 },
    output: enablementOutput,
    async plan(ctx, input) {
      const now = ctx.now();
      const id = input.id;
      const guard: SqlCondition = {
        sql: `EXISTS (SELECT 1 FROM ${r.table} WHERE id = ?) AND ${currentEnablementSql(resource)} <> ?`,
        params: [id, id, enablement],
      };
      const writes: SqlStatement[] = [];
      const disablingUser = resource === "user" && enablement === "disabled";
      if (disablingUser) {
        writes.push({ sql: `DELETE FROM sessions WHERE user_id = ? AND ${guard.sql}`, params: [id, ...guard.params] });
      }
      writes.push({
        sql: `INSERT INTO ${r.events} (${r.column}, enablement, occurred_at) SELECT ?, ?, ? WHERE ${guard.sql}`,
        params: [id, enablement, now, ...guard.params],
      });
      const result: EnablementResult = { id, enablement, occurred_at: now };
      return {
        target: `${resource}:${id}`,
        probe: {
          sql: `SELECT EXISTS (SELECT 1 FROM ${r.table} WHERE id = ?) AS found, ${currentEnablementSql(resource)} AS enablement`,
          params: [id, id],
        },
        guard,
        writes,
        detail: { enablement },
        ...(disablingUser ? { computed: [{ key: "sessions_deleted", sql: "SELECT COUNT(*) FROM sessions WHERE user_id = ?", params: [id] }] } : {}),
        settle(probe: SqlRow) {
          if (probe["found"] !== 1) throw new AdminProblem("not-found", `The ${resource} does not exist`);
          if (probe["enablement"] === enablement) throw new AdminProblem("state-conflict", `The ${resource} is already ${enablement}`);
          return "write";
        },
        result: () => result,
      };
    },
  };
}
