// The D1 adapter for the core's Database port. It only translates between the port's types and the D1 binding:
// the SQL, the transaction boundaries, and every rule stay in the core (docs/design/technology.md).
import {
  DatabaseError,
  type Database,
  type SqlRow,
  type SqlStatement,
  type SqlStatementResult,
  type SqlValue,
} from "@idp/db";

/**
 * Wraps a D1 binding as the core's {@link Database}.
 *
 * Every batch goes through `D1Database.batch`, which D1 runs as one transaction, so the port's all-or-nothing
 * contract holds without the adapter opening transactions itself.
 *
 * @param binding The D1 binding from the Worker's environment.
 * @returns A {@link Database} whose `batch` rejects only with {@link DatabaseError}.
 */
export function createD1Database(binding: D1Database): Database {
  return {
    async batch(statements: readonly SqlStatement[]): Promise<readonly SqlStatementResult[]> {
      // The port promises that an empty batch never reaches the database; D1 would also reject an empty list.
      if (statements.length === 0) return [];
      let results: readonly D1Result[];
      try {
        results = await binding.batch(statements.map((s) => binding.prepare(s.sql).bind(...s.params.map(toD1Param))));
      } catch (cause) {
        throw new DatabaseError(`D1 batch failed: ${describe(cause)}`, { cause });
      }
      // A short or long result list would misalign results with statements; never hand the core partial results.
      if (results.length !== statements.length) {
        throw new DatabaseError(`D1 returned ${results.length} results for ${statements.length} statements`);
      }
      return results.map(toStatementResult);
    },
  };
}

function toD1Param(value: SqlValue): unknown {
  // D1 binds an ArrayBuffer as a BLOB. Copying the view's own range also keeps a subarray from leaking the rest of
  // its underlying buffer into the column.
  if (value instanceof Uint8Array) return value.slice().buffer;
  return value;
}

function toStatementResult(result: D1Result): SqlStatementResult {
  const changes = result.meta.changes;
  if (!Number.isSafeInteger(changes) || changes < 0) {
    throw new DatabaseError(`D1 returned an invalid change count: ${String(changes)}`);
  }
  return { rows: result.results.map(toRow), changes };
}

function toRow(row: unknown): SqlRow {
  if (typeof row !== "object" || row === null) throw new DatabaseError("D1 returned a row that is not an object");
  const out: Record<string, SqlValue> = {};
  for (const [column, value] of Object.entries(row)) out[column] = toSqlValue(column, value);
  return out;
}

function toSqlValue(column: string, value: unknown): SqlValue {
  if (value === null || typeof value === "string" || typeof value === "number") return value;
  // D1 hands BLOB columns back as an ArrayBuffer, a typed array, or a plain array of bytes depending on the runtime
  // path (the Workers binding or miniflare's proxy); the port always sees a Uint8Array.
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  if (Array.isArray(value) && value.every(isByte)) return Uint8Array.from(value);
  // SQLite has no other storage class, so anything else means the binding changed; fail rather than guess.
  throw new DatabaseError(`D1 returned an unsupported value in column ${column}`);
}

function isByte(value: unknown): value is number {
  return Number.isInteger(value) && (value as number) >= 0 && (value as number) <= 255;
}

function describe(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}
