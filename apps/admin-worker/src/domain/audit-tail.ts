// audit_tail (docs/design/idpctl.md): the audit log, newest first, filtered by target, operation, and time. Admins
// read the user's own passkey additions and revocations here, in place of a notification to the user.
import { auditTailOutput } from "./outputs.js";
import { z } from "zod";
import { isAuditTarget, type AuditTarget } from "@idp/core/audit";
import type { SqlCondition, SqlRow } from "@idp/core/db";
import type { ReadOperation } from "./operation.js";
import { readPage, type Page, type PageQuery } from "./paging.js";
import { pageInputShape, type PageInput } from "./schemas.js";

/** One audit row as audit_tail returns it; `detail` is detail_json parsed. */
export type AuditEvent = {
  readonly id: number;
  readonly occurred_at: number;
  readonly actor: "admin" | "user" | "break_glass";
  readonly admin_name: string | null;
  readonly admin_cert_sha256: string | null;
  readonly writer_version: string;
  readonly operation: string;
  readonly target: AuditTarget;
  readonly result: "success" | "failure";
  readonly detail: Readonly<Record<string, unknown>>;
};

// Query parameters arrive as strings and a JSON body as numbers, as for limit.
const unixSecondsSchema = z.union([z.int().min(0), z.string().regex(/^(?:0|[1-9][0-9]{0,15})$/).transform(Number)]).pipe(z.int().min(0).max(Number.MAX_SAFE_INTEGER));

type AuditTailInput = PageInput & {
  readonly target?: AuditTarget | undefined;
  readonly operation?: string | undefined;
  readonly since?: number | undefined;
  readonly until?: number | undefined;
};

function auditPage(input: AuditTailInput): PageQuery {
  const filters: SqlCondition[] = [];
  if (input.target !== undefined) filters.push({ sql: "target = ?", params: [input.target] });
  if (input.operation !== undefined) filters.push({ sql: "operation = ?", params: [input.operation] });
  if (input.since !== undefined) filters.push({ sql: "occurred_at >= ?", params: [input.since] });
  if (input.until !== undefined) filters.push({ sql: "occurred_at < ?", params: [input.until] });
  return {
    columns: "id, occurred_at, actor, admin_name, admin_cert_sha256, writer_version, operation, target, result, detail_json",
    from: "audit_log",
    filters,
    key: [{ sql: "id", column: "id", type: "integer" }],
    order: "desc",
  };
}

function toAuditEvent(row: SqlRow): AuditEvent {
  return {
    id: row["id"] as number,
    occurred_at: row["occurred_at"] as number,
    actor: row["actor"] as AuditEvent["actor"],
    admin_name: row["admin_name"] as string | null,
    admin_cert_sha256: row["admin_cert_sha256"] as string | null,
    writer_version: row["writer_version"] as string,
    operation: row["operation"] as string,
    target: row["target"] as AuditTarget,
    result: row["result"] as AuditEvent["result"],
    detail: JSON.parse(row["detail_json"] as string) as Record<string, unknown>,
  };
}

/** audit_tail: audit rows newest first; `since` is inclusive and `until` exclusive, both UNIX seconds. */
export const auditTail: ReadOperation<AuditTailInput, Page<AuditEvent>> = {
  name: "audit_tail",
  class: { access: "read" },
  establishesIdentity: false,
  input: z.strictObject({
    ...pageInputShape,
    target: z.string().refine(isAuditTarget, { message: "must be user:<id>, client:<id>, group:<id>, schema, or none" }).optional(),
    operation: z.string().regex(/^[a-z]+(?:_[a-z0-9]+)*$/).optional(),
    since: unixSecondsSchema.optional(),
    until: unixSecondsSchema.optional(),
  }),
  http: { method: "GET", path: "/v1/audit-events", status: 200 },
  output: auditTailOutput,
  read: (ctx, input) => readPage(ctx.db, auditPage(input as AuditTailInput), input, toAuditEvent),
};
