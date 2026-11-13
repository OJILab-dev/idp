// The database port. The core writes SQL against the D1 schema (contract/migrations) but never touches the D1
// binding: each Worker passes an adapter, so the rules stay testable without workerd.

/** A value bound to a `?` placeholder or read from a column; BLOBs (COSE keys, credential IDs) are bytes. */
export type SqlValue = string | number | null | Uint8Array;

/** One parameterised statement; `params` bind to the `?` placeholders in order. */
export type SqlStatement = {
  readonly sql: string;
  readonly params: readonly SqlValue[];
};

/** One result row, keyed by column name. */
export type SqlRow = Readonly<Record<string, SqlValue>>;

/** A boolean SQL expression and its parameters, evaluated in the WHERE of a guarded statement. */
export type SqlCondition = {
  readonly sql: string;
  readonly params: readonly SqlValue[];
};

/** What one statement of a batch returned. */
export type SqlStatementResult = {
  /** The rows the statement returned, in order; empty for statements that return none. */
  readonly rows: readonly SqlRow[];
  /** The rows the statement inserted, updated, or deleted; 0 for a read. */
  readonly changes: number;
};

/** Thrown when the database rejects or fails a batch (see {@link Database.batch} for what took effect). */
export class DatabaseError extends Error {
  override readonly name = "DatabaseError";
}

/** Runs SQL against the IdP's database. Implemented by an adapter per Worker; the core holds only this contract. */
export interface Database {
  /**
   * Runs the statements in order as one transaction: either every statement takes effect or none does.
   *
   * Statements see the writes of the earlier statements in the same batch. Not idempotent: the caller makes a
   * retried write safe (for example with a unique key), because the batch may have committed before the error.
   *
   * @param statements The statements to run; an empty list resolves to an empty list without touching the database.
   * @returns One result per statement, in the same order and of the same length; never null.
   * @throws {DatabaseError} A statement failed (including a constraint violation), and the batch was rolled back;
   *   or the database became unreachable, in which case whether the batch committed is unknown.
   */
  batch(statements: readonly SqlStatement[]): Promise<readonly SqlStatementResult[]>;
}
