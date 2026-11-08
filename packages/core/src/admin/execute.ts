// Runs an admin operation: validation, Idempotency-Key, the guarded batch with its success audit row, and the
// failure audit row after a rollback (docs/design/data-model.md, the audit_log rules).
import {
  DatabaseError,
  auditFailureStatement,
  auditSuccessStatement,
  type AuditTarget,
  type SqlRow,
  type SqlStatement,
} from "../shared/index.js";
import {
  idempotencyCleanupStatement,
  idempotencyInsertStatement,
  idempotencyLookupStatement,
  replayStored,
  requestHash,
  requireIdempotencyKey,
} from "./idempotency.js";
import type { AdminContext, AdminOperation, OperationOutcome, WriteOperation } from "./operation.js";
import { AdminProblem } from "./problem.js";
import { clientIdSchema, parseInput, uuidSchema } from "./schemas.js";

/** Request metadata outside the input. */
export type ExecuteOptions = {
  /** The Idempotency-Key header; required by idempotent operations and ignored by the others. */
  readonly idempotencyKey?: string | undefined;
  /**
   * A problem the HTTP layer found before the input could be assembled (a body that is not JSON, a repeated query
   * parameter). The operation does not run; a write still records the failure row, as for any other rejection after
   * the allowlist resolved the admin.
   */
  readonly rejection?: AdminProblem | undefined;
};

/**
 * Runs one admin operation.
 *
 * A write runs as one batch: the probe, the success audit row and the idempotency row under the plan's guard, then
 * the writes. Any failure of a write operation, including validation and Idempotency-Key problems, is recorded
 * afterwards as a failure audit row in a separate write, since the batch itself rolled back. Reads write nothing.
 *
 * @param ctx The caller's context, with the admin the allowlist resolved.
 * @param operation The operation from the registry.
 * @param input The untrusted input (path parameters, query, and body merged by the HTTP layer).
 * @param options The Idempotency-Key, and a rejection the HTTP layer already decided.
 * @returns The success status and body, or a replayed stored response.
 * @throws {AdminProblem} A rule rejected the request; any other error, including {@link DatabaseError}, is
 *   wrapped as `internal` with the original as `cause`.
 */
export async function executeOperation<I, R>(
  ctx: AdminContext,
  operation: AdminOperation<I, R>,
  input: unknown,
  options: ExecuteOptions = {},
): Promise<OperationOutcome<R>> {
  const now = ctx.now();
  if ("read" in operation) {
    if (options.rejection !== undefined) throw options.rejection;
    try {
      const body = await operation.read(ctx, parseInput(operation.input, input));
      return { status: operation.http.status, body, replayed: false };
    } catch (error) {
      throw toProblem(error);
    }
  }
  try {
    if (options.rejection !== undefined) throw options.rejection;
    return await runWrite(ctx, operation, input, options, now);
  } catch (error) {
    const problem = toProblem(error);
    await writeFailureRow(ctx, operation, input, problem, now);
    throw problem;
  }
}

function toProblem(error: unknown): AdminProblem {
  if (error instanceof AdminProblem) return error;
  return new AdminProblem("internal", "The operation failed", { cause: error });
}

async function runWrite<I, R>(
  ctx: AdminContext,
  operation: WriteOperation<I, R>,
  rawInput: unknown,
  options: ExecuteOptions,
  now: number,
): Promise<OperationOutcome<R>> {
  const input = parseInput(operation.input, rawInput);
  let idempotency: { readonly key: string; readonly hash: string } | undefined;
  if (operation.idempotent) {
    const key = requireIdempotencyKey(options.idempotencyKey);
    const hash = await requestHash(input);
    const stored = await lookup(ctx, key, now);
    if (stored !== undefined) return replayStored<R>(stored, operation.name, hash);
    idempotency = { key, hash };
  }

  const plan = await operation.plan(ctx, input);
  // An idempotent result must not depend on the batch, so it can be computed now and stored in the same batch.
  const early = operation.idempotent ? plan.result([]) : undefined;
  const audit = auditSuccessStatement({
    occurredAt: now,
    actor: { kind: "admin", name: ctx.admin.name, certSha256: ctx.admin.certSha256 },
    writerVersion: ctx.writerVersion,
    operation: operation.name,
    target: plan.target,
    detail: plan.detail,
    guard: plan.guard,
    ...(plan.computed === undefined ? {} : { computed: plan.computed }),
  });
  const head: SqlStatement[] = [];
  const tail: SqlStatement[] = [];
  if (idempotency !== undefined) {
    head.push(idempotencyCleanupStatement(now));
    tail.push(
      idempotencyInsertStatement({
        adminName: ctx.admin.name,
        key: idempotency.key,
        operation: operation.name,
        requestHash: idempotency.hash,
        response: plan.secret === true ? null : { status: operation.http.status, body: early },
        now,
        guard: plan.guard,
      }),
    );
  }
  const statements = [...head, plan.probe, audit, ...tail, ...plan.writes];

  let results;
  try {
    results = await ctx.db.batch(statements);
  } catch (error) {
    // A concurrent request with the same key won the primary key; answer as its replay.
    if (idempotency !== undefined && error instanceof DatabaseError) {
      const stored = await lookup(ctx, idempotency.key, now);
      if (stored !== undefined) return replayStored<R>(stored, operation.name, idempotency.hash);
    }
    throw error;
  }

  const probeRow = results[head.length]?.rows[0];
  const audited = results[head.length + 1]?.changes === 1;
  if (probeRow === undefined) throw new AdminProblem("internal", `${operation.name} probe returned no row`);
  let outcome;
  try {
    outcome = plan.settle(probeRow);
  } catch (error) {
    if (audited) throw new AdminProblem("internal", `${operation.name} wrote under a guard that settle rejected`, { cause: error });
    throw error;
  }
  if (audited !== (outcome === "write")) {
    throw new AdminProblem("internal", `${operation.name} guard and settle disagree`);
  }
  const writes = results.slice(head.length + 2 + tail.length);
  return { status: operation.http.status, body: early ?? plan.result(writes), replayed: false };
}

async function lookup(ctx: AdminContext, key: string, now: number): Promise<SqlRow | undefined> {
  const [result] = await ctx.db.batch([idempotencyLookupStatement(ctx.admin.name, key, now)]);
  return result?.rows[0];
}

// The failure row names the target only when its ID passed validation (data-model.md); a malformed value, which
// may be a name typed into an ID field, is never written.
function failureTarget(operation: WriteOperation<unknown, unknown>, input: unknown): AuditTarget {
  const spec = operation.target;
  if (spec === "none" || typeof input !== "object" || input === null) return "none";
  const value = (input as Record<string, unknown>)[spec.field];
  const schema = spec.kind === "client" ? clientIdSchema : uuidSchema;
  const parsed = schema.safeParse(value);
  return parsed.success ? `${spec.kind}:${parsed.data}` : "none";
}

async function writeFailureRow<I, R>(
  ctx: AdminContext,
  operation: WriteOperation<I, R>,
  input: unknown,
  problem: AdminProblem,
  now: number,
): Promise<void> {
  try {
    await ctx.db.batch([
      auditFailureStatement({
        occurredAt: now,
        actor: { kind: "admin", name: ctx.admin.name, certSha256: ctx.admin.certSha256 },
        writerVersion: ctx.writerVersion,
        operation: operation.name,
        target: failureTarget(operation as WriteOperation<unknown, unknown>, input),
        problem: problem.kind,
      }),
    ]);
  } catch (error) {
    ctx.onFailureAuditError(error);
  }
}
