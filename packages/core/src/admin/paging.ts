// Cursor paging for the five admin lists (docs/design/idpctl.md, "一覧のページング"). A cursor is the direction and
// the sort key of the boundary row, as base64url JSON. It is not signed: it holds no secret, and a forged cursor can
// only move the window over rows the admin may already list. Offsets are avoided because D1 counts skipped rows as
// reads and an insert shifts offset pages.
import { InvalidBase64urlError, base64urlDecode, base64urlEncode } from "@idp/base64url";
import type { Database, SqlCondition, SqlRow, SqlStatement } from "../db/index.js";
import { AdminProblem } from "./problem.js";
import type { PageInput } from "./schemas.js";

/** A sort key: one value per key column, in column order. */
export type CursorKey = readonly (string | number)[];

/** A decoded cursor. `next` holds the last row of a page, `prev` the first row. */
export type Cursor = {
  readonly direction: "next" | "prev";
  readonly key: CursorKey;
};

/** One key column: the SQL expression it sorts by, the result column it reads back, and its type. */
export type KeyColumn = {
  readonly sql: string;
  readonly column: string;
  readonly type: "integer" | "text";
};

/** A page of a list, the response body shape of every list. */
export type Page<T> = {
  readonly items: readonly T[];
  readonly next_cursor: string | null;
  readonly prev_cursor: string | null;
};

/** What to page over. */
export type PageQuery = {
  /** The selected columns, which must include every key column's result column. */
  readonly columns: string;
  /** The FROM clause, joins included. */
  readonly from: string;
  /** Filters ANDed with the cursor condition. */
  readonly filters: readonly SqlCondition[];
  /** The sort key, most significant first; it must be unique per row. */
  readonly key: readonly KeyColumn[];
  /** The order of the first page: `asc` for creation order, `desc` for newest first. */
  readonly order: "asc" | "desc";
};

/**
 * Encodes a cursor.
 *
 * @param cursor The direction and boundary key.
 * @returns Unpadded base64url of the UTF-8 JSON `{"d":"next"|"prev","k":[...]}`.
 */
export function encodeCursor(cursor: Cursor): string {
  return base64urlEncode(new TextEncoder().encode(JSON.stringify({ d: cursor.direction, k: cursor.key })));
}

function invalidCursor(cause?: unknown): AdminProblem {
  return new AdminProblem("validation-failed", "The cursor is not valid for this list", { pointers: ["/cursor"], cause });
}

/**
 * Decodes and validates a cursor against the key columns of the list it is used with.
 *
 * @param value The untrusted cursor.
 * @param key The list's key columns.
 * @returns The cursor.
 * @throws {AdminProblem} `validation-failed` at `/cursor`: not canonical base64url, not UTF-8 JSON, not the
 *   `{d, k}` shape, or a key whose length or value types do not match the columns.
 */
export function decodeCursor(value: string, key: readonly KeyColumn[]): Cursor {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(base64urlDecode(value)));
  } catch (error) {
    if (error instanceof InvalidBase64urlError || error instanceof SyntaxError || error instanceof TypeError) {
      throw invalidCursor(error);
    }
    throw error;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw invalidCursor();
  const { d, k, ...rest } = parsed as Record<string, unknown>;
  if (Object.keys(rest).length > 0 || (d !== "next" && d !== "prev") || !Array.isArray(k) || k.length !== key.length) {
    throw invalidCursor();
  }
  const values = k as readonly unknown[];
  const valid = key.every((column, i) => {
    const v = values[i];
    return column.type === "integer" ? Number.isSafeInteger(v) : typeof v === "string";
  });
  if (!valid) throw invalidCursor();
  return { direction: d, key: values as CursorKey };
}

/**
 * Builds the statement that reads one page, plus one row to tell whether another page follows.
 *
 * @param query What to page over.
 * @param input The validated limit and the untrusted cursor.
 * @returns The statement and the decoded cursor (undefined for the first page).
 * @throws {AdminProblem} `validation-failed` for an invalid cursor.
 */
export function pageStatement(query: PageQuery, input: PageInput): { readonly statement: SqlStatement; readonly cursor: Cursor | undefined } {
  const cursor = input.cursor === undefined ? undefined : decodeCursor(input.cursor, query.key);
  const backward = cursor?.direction === "prev";
  // Walking backwards flips both the comparison and the order; the rows are reversed again in toPage.
  const ascending = (query.order === "asc") !== backward;
  const conditions = [...query.filters];
  if (cursor !== undefined) {
    const tuple = query.key.map((k) => k.sql).join(", ");
    const placeholders = query.key.map(() => "?").join(", ");
    conditions.push({ sql: `(${tuple}) ${ascending ? ">" : "<"} (${placeholders})`, params: cursor.key });
  }
  const where = conditions.length === 0 ? "1" : conditions.map((c) => `(${c.sql})`).join(" AND ");
  const orderBy = query.key.map((k) => `${k.sql} ${ascending ? "ASC" : "DESC"}`).join(", ");
  return {
    statement: {
      sql: `SELECT ${query.columns} FROM ${query.from} WHERE ${where} ORDER BY ${orderBy} LIMIT ?`,
      params: [...conditions.flatMap((c) => c.params), input.limit + 1],
    },
    cursor,
  };
}

/**
 * Turns the rows of {@link pageStatement} into a page.
 *
 * The first page has no `prev_cursor`, and the last page in the walking direction has no cursor that way. An empty
 * page (a cursor past the end) has neither, since it has no boundary row to point at.
 *
 * @param rows The statement's rows, in statement order.
 * @param query The same query.
 * @param input The same input.
 * @param cursor The cursor {@link pageStatement} decoded.
 * @param toItem Maps a row to a response item.
 * @returns The page in the list's order.
 */
export function toPage<T>(
  rows: readonly SqlRow[],
  query: PageQuery,
  input: PageInput,
  cursor: Cursor | undefined,
  toItem: (row: SqlRow) => T,
): Page<T> {
  const more = rows.length > input.limit;
  const window = rows.slice(0, input.limit);
  const ordered = cursor?.direction === "prev" ? [...window].reverse() : window;
  function keyOf(row: SqlRow): CursorKey {
    return query.key.map((k) => row[k.column] as string | number);
  }
  const first = ordered[0];
  const last = ordered[ordered.length - 1];
  let next: string | null = null;
  let prev: string | null = null;
  if (first !== undefined && last !== undefined) {
    const hasNext = cursor?.direction === "prev" ? true : more;
    const hasPrev = cursor === undefined ? false : cursor.direction === "next" ? true : more;
    if (hasNext) next = encodeCursor({ direction: "next", key: keyOf(last) });
    if (hasPrev) prev = encodeCursor({ direction: "prev", key: keyOf(first) });
  }
  return { items: ordered.map(toItem), next_cursor: next, prev_cursor: prev };
}

/**
 * Reads one page of a list.
 *
 * @param db The database.
 * @param query What to page over.
 * @param input The validated limit and the untrusted cursor.
 * @param toItem Maps a row to a response item.
 * @returns The page.
 * @throws {AdminProblem} `validation-failed` for an invalid cursor.
 * @throws {DatabaseError} The database failed.
 */
export async function readPage<T>(db: Database, query: PageQuery, input: PageInput, toItem: (row: SqlRow) => T): Promise<Page<T>> {
  const { statement, cursor } = pageStatement(query, input);
  const [result] = await db.batch([statement]);
  return toPage(result?.rows ?? [], query, input, cursor, toItem);
}
