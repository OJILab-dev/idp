import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Miniflare } from "miniflare";
import type { D1Database } from "@cloudflare/workers-types";

const migrationsDir = join(import.meta.dirname, "..", "migrations");

/** A local D1 database with every migration applied, and a way to shut it down. */
export type TestD1 = {
  readonly db: D1Database;
  readonly dispose: () => Promise<void>;
};

/**
 * Splits a migration into statements for `D1Database.batch`.
 *
 * Line comments are dropped first. A `;` ends a statement except inside a
 * `CREATE TRIGGER … BEGIN … END;` body, whose inner statements also end in `;`.
 * The migrations contain no string literal with `--` or `;`, which is what makes
 * this simple split safe; the schema test fails if that ever stops being true.
 */
export function splitStatements(sql: string): readonly string[] {
  const withoutComments = sql
    .split("\n")
    .map((line) => line.replace(/--.*$/, ""))
    .join("\n");
  const statements: string[] = [];
  let buffer = "";
  for (const chunk of withoutComments.split(";")) {
    buffer += `${chunk};`;
    const isOpenTrigger = /CREATE\s+TRIGGER/i.test(buffer) && !/\bEND\s*;$/i.test(buffer.trim());
    if (isOpenTrigger) continue;
    if (buffer.replace(/;/g, "").trim() !== "") statements.push(buffer.trim());
    buffer = "";
  }
  if (buffer.replace(/;/g, "").trim() !== "") throw new Error("unterminated statement in migration");
  return statements;
}

/** Reads a migration file from `contract/migrations`. */
export function readMigration(name: string): string {
  return readFileSync(join(migrationsDir, name), "utf8");
}

/**
 * Starts an in-memory D1 (workerd's SQLite, the engine `cf dev` uses) and applies the migrations.
 *
 * Each call gets its own empty database, so tests do not share state.
 */
export async function createTestD1(): Promise<TestD1> {
  const mf = new Miniflare({
    workers: [
      {
        config: {
          name: "schema-test",
          compatibilityDate: "2026-10-01",
          manifest: {
            mainModule: "index.js",
            modules: {
              "index.js": {
                type: "esm",
                contents: "export default { fetch() { return new Response(null, { status: 404 }); } };",
              },
            },
          },
          env: { DB: { type: "d1", name: crypto.randomUUID() } },
        },
      },
    ],
  });
  const db = (await mf.getD1Database("DB")) as unknown as D1Database;
  const statements = splitStatements(readMigration("0001_init.sql"));
  await db.batch(statements.map((s) => db.prepare(s)));
  return { db, dispose: () => mf.dispose() };
}
