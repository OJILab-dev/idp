// The shape of an admin operation: its classification metadata, its input schema, and how it runs
// (docs/design/idpctl.md, "操作の一覧" and "操作の分類"). Every idpctl operation is one value of these types.
import type { z } from "zod";
import type {
  AuditComputedMember,
  AuditDetail,
  AuditTarget,
  Database,
  Issuer,
  SqlCondition,
  SqlRow,
  SqlStatement,
  SqlStatementResult,
} from "../shared/index.js";

/** Every idpctl operation name: the CLI subcommand, the use case, the OpenAPI operationId, and audit_log.operation. */
export const OPERATION_NAMES = [
  "users_list",
  "user_get",
  "clients_list",
  "groups_list",
  "grants_list",
  "access_check",
  "audit_tail",
  "user_create",
  "user_rename",
  "user_disable",
  "user_enable",
  "enroll_link_issue",
  "passkey_revoke",
  "session_revoke",
  "group_create",
  "group_rename",
  "group_disable",
  "group_enable",
  "group_member_add",
  "group_member_remove",
  "client_create",
  "client_rename",
  "client_set_redirects",
  "client_rotate_secret",
  "client_set_id_token_alg",
  "client_disable",
  "client_enable",
  "grant_add",
  "grant_remove",
] as const;

/** One idpctl operation name. */
export type OperationName = (typeof OPERATION_NAMES)[number];

/**
 * The management concern of a write (docs/design/authorization.md, "管理の関心事"): whether it changes facts about
 * people (`user`), a relying party (`rp`), or who may use which relying party (`access`).
 */
export type Concern = "user" | "rp" | "access";

/** Whether an operation reads or writes; only writes have a concern and an audit row. */
export type OperationClass = { readonly access: "read" } | { readonly access: "write"; readonly concern: Concern };

/** The REST mapping of an operation (docs/design/idpctl.md, "管理 API の形"), for the HTTP layer and the OpenAPI spec. */
export type HttpMapping = {
  readonly method: "GET" | "POST" | "PUT" | "DELETE";
  readonly path: string;
  /** The status of a success response. */
  readonly status: 200 | 201;
};

/** The admin the allowlist resolved from the client certificate; the caller (the admin Worker) supplies it. */
export type AdminIdentity = {
  readonly name: string;
  /** The certificate's SHA-256 fingerprint, lowercase hex. */
  readonly certSha256: string;
};

/** Everything an operation needs from its caller. */
export type AdminContext = {
  readonly db: Database;
  readonly admin: AdminIdentity;
  /** The admin Worker's version, written to audit_log.writer_version. */
  readonly writerVersion: string;
  /** The current time in UNIX seconds; read once per operation. */
  readonly now: () => number;
  /**
   * Whether RS256 ID tokens are enabled. The caller derives it from the IdP Worker's discovery and passes false when
   * it cannot tell (fail-closed, docs/design/idpctl.md).
   */
  readonly rs256Enabled: boolean;
  /** The issuer, from which enrollment links are built. */
  readonly issuer: Issuer;
  /**
   * Receives an error raised while writing a failure audit row. The original problem is still thrown to the caller;
   * this hook lets the Worker log the lost row instead of hiding it.
   */
  readonly onFailureAuditError: (error: unknown) => void;
};

/** Which validated input field names the audit target, so a failure row can name it even when the operation fails. */
export type TargetSpec =
  | { readonly kind: "user"; readonly field: "user_id" }
  | { readonly kind: "group"; readonly field: "group_id" }
  | { readonly kind: "client"; readonly field: "client_id" }
  | "none";

/** What the probe row says the guarded writes did. */
export type PlanOutcome = "write" | "noop";

/**
 * A write planned as one batch: `[probe, audit row, idempotency row, ...writes]`.
 *
 * The audit and idempotency rows are inserted with `guard`, before the writes, so they exist exactly when the writes
 * happen (docs/design/data-model.md). Every write repeats a condition equivalent to the guard itself, evaluated
 * before the state it changes; a write after the state change uses a condition that only the earlier guarded write
 * can make true (such as the existence of a freshly generated ID).
 */
export interface WritePlan<R> {
  /** The audit target of the success row; a creation names the ID it just generated. Never null. */
  readonly target: AuditTarget;
  /** A read run first in the batch, returning exactly one row; {@link WritePlan.settle} receives that row. */
  readonly probe: SqlStatement;
  /** The condition under which the writes happen; the audit and idempotency rows are inserted under it. */
  readonly guard: SqlCondition;
  /** The writes, in order, each guarded as described above; may include reads whose rows `result` needs. */
  readonly writes: readonly SqlStatement[];
  /** The static detail_json members of the success row; validated by the audit-row builder. */
  readonly detail: AuditDetail;
  /** The detail_json members computed by SQL in the same statement; absent when there are none. */
  readonly computed?: readonly AuditComputedMember[];
  /** Whether the result carries an IdP-issued secret; such a response is never stored (replayable = 0). */
  readonly secret?: boolean;
  /**
   * Decides, from the probe row, whether the guarded writes ran or which rule rejected them. Must agree with
   * `guard`; the framework reports `internal` when the audit row's presence contradicts the outcome. Pure.
   *
   * @param probe The single row of `probe`.
   * @returns `write` when the guard held, `noop` when it did not and the request still succeeds (a PUT that changes
   *   nothing).
   * @throws {AdminProblem} The guard did not hold because a rule rejected the request (not-found, state-conflict).
   */
  settle(probe: SqlRow): PlanOutcome;
  /**
   * Builds the success result. An idempotent operation's result must not read `writes`: the framework calls it with
   * an empty list before the batch to obtain the response it stores in that same batch. Pure; never throws.
   *
   * @param writes The results of `writes`, in order (empty for the pre-batch call of an idempotent operation).
   * @returns The JSON-serialisable response body.
   */
  result(writes: readonly SqlStatementResult[]): R;
}

/** The metadata every operation carries next to its use case (docs/design/idpctl.md, "操作の分類"). */
export interface OperationBase<I> {
  /** The operation name; unique in the registry. */
  readonly name: OperationName;
  /** True only for enroll_link_issue; an entry point other than the CLI must never expose such an operation. */
  readonly establishesIdentity: boolean;
  /** The input schema; the same schema validates the request and generates the admin API's OpenAPI spec. */
  readonly input: z.ZodType<I>;
  /** The REST mapping of the operation. */
  readonly http: HttpMapping;
}

/** A read operation (a use case of the admin API): no audit row, no Idempotency-Key. */
export interface ReadOperation<I, R> extends OperationBase<I> {
  /** Always a read. */
  readonly class: { readonly access: "read" };
  /**
   * Runs the read in one batch, so every list and count in the result comes from one snapshot. Idempotent.
   *
   * @param ctx The caller's context.
   * @param input The validated input.
   * @returns The JSON-serialisable response body.
   * @throws {AdminProblem} A rule rejected the request, such as not-found or an invalid cursor.
   * @throws {DatabaseError} The database failed.
   */
  read(ctx: AdminContext, input: I): Promise<R>;
}

/** A write operation (a use case of the admin API), planned as one guarded batch with its audit row. */
export interface WriteOperation<I, R> extends OperationBase<I> {
  /** Always a write, with its management concern. */
  readonly class: { readonly access: "write"; readonly concern: Concern };
  /** Which input field names the target of a failure row. */
  readonly target: TargetSpec;
  /** Whether the operation is a creating or appending POST that requires an Idempotency-Key. */
  readonly idempotent: boolean;
  /**
   * Plans the batch. May read the database for facts the guard cannot express (such as a client's type), but never
   * writes, so a rejection here leaves no trace except the failure row.
   *
   * @param ctx The caller's context.
   * @param input The validated input.
   * @returns The plan the framework runs as one batch.
   * @throws {AdminProblem} A rule rejected the request before any write (such as algorithm-disabled).
   * @throws {DatabaseError} The database failed.
   */
  plan(ctx: AdminContext, input: I): Promise<WritePlan<R>>;
}

/** Any operation, as kept in the registry. */
export type AdminOperation<I = unknown, R = unknown> = ReadOperation<I, R> | WriteOperation<I, R>;

/** The outcome of a successful operation, ready for the HTTP layer. */
export type OperationOutcome<R> = {
  readonly status: 200 | 201;
  readonly body: R;
  /** Whether the body is a stored response replayed for a repeated Idempotency-Key. */
  readonly replayed: boolean;
};
