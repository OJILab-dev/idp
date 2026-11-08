// User management (docs/design/idpctl.md): create, rename, enable and disable, list, get, and revoke sessions.
// Users are never deleted; disabling ends access and keeps the row (data-model.md).
import { z } from "zod";
import { newUuidV4, type SqlRow } from "../shared/index.js";
import { currentEnablementSql, enablementOperation, initialEnablementStatement, type Enablement } from "./enablement.js";
import type { ReadOperation, WriteOperation } from "./operation.js";
import { readPage, type Page, type PageQuery } from "./paging.js";
import { AdminProblem } from "./problem.js";
import { nameSchema, pageInputShape, uuidSchema, type PageInput } from "./schemas.js";

// WebAuthn's user.id (user_handle): 64 random bytes, the maximum of WebAuthn §5.4.3, carrying no personal data.
const USER_HANDLE_BYTES = 64;

/** The result of user_create. */
export type UserCreateResult = { readonly user_id: string };

/** user_create: a user with a fresh UUIDv4, a random user handle, and the first `enabled` event. */
export const userCreate: WriteOperation<{ readonly name: string }, UserCreateResult> = {
  name: "user_create",
  class: { access: "write", concern: "user" },
  establishesIdentity: false,
  idempotent: true,
  target: "none",
  input: z.strictObject({ name: nameSchema }),
  http: { method: "POST", path: "/v1/users", status: 201 },
  async plan(ctx, input) {
    const now = ctx.now();
    const id = newUuidV4();
    // The ID is fresh, so its principal exists exactly when the first insert ran; later inserts key off that.
    const created = { sql: "EXISTS (SELECT 1 FROM principals WHERE id = ?)", params: [id] };
    return {
      target: `user:${id}`,
      probe: { sql: "SELECT 1 AS ok", params: [] },
      guard: { sql: "1", params: [] },
      writes: [
        { sql: "INSERT INTO principals (id, kind) VALUES (?, 'user')", params: [id] },
        {
          sql: "INSERT INTO users (id, user_handle, name, created_at) VALUES (?, ?, ?, ?)",
          params: [id, crypto.getRandomValues(new Uint8Array(USER_HANDLE_BYTES)), input.name, now],
        },
        initialEnablementStatement("user", id, now, created),
      ],
      detail: {},
      settle: () => "write",
      result: () => ({ user_id: id }),
    };
  },
};

/** The result of user_rename. */
export type UserRenameResult = { readonly user_id: string; readonly name: string };

/** user_rename: changes the display name; the audit row records only that a rename happened, never the names. */
export const userRename: WriteOperation<{ readonly user_id: string; readonly name: string }, UserRenameResult> = {
  name: "user_rename",
  class: { access: "write", concern: "user" },
  establishesIdentity: false,
  idempotent: false,
  target: { kind: "user", field: "user_id" },
  input: z.strictObject({ user_id: uuidSchema, name: nameSchema }),
  http: { method: "PUT", path: "/v1/users/{id}/name", status: 200 },
  async plan(_ctx, input) {
    const guard = { sql: "EXISTS (SELECT 1 FROM users WHERE id = ? AND name IS NOT ?)", params: [input.user_id, input.name] };
    return {
      target: `user:${input.user_id}`,
      probe: {
        sql: "SELECT EXISTS (SELECT 1 FROM users WHERE id = ?) AS found, EXISTS (SELECT 1 FROM users WHERE id = ? AND name = ?) AS same",
        params: [input.user_id, input.user_id, input.name],
      },
      guard,
      writes: [{ sql: "UPDATE users SET name = ? WHERE id = ? AND name IS NOT ?", params: [input.name, input.user_id, input.name] }],
      detail: {},
      settle(probe) {
        if (probe["found"] !== 1) throw new AdminProblem("not-found", "The user does not exist");
        return probe["same"] === 1 ? "noop" : "write";
      },
      result: () => ({ user_id: input.user_id, name: input.name }),
    };
  },
};

/** user_disable: appends `disabled` and deletes every session of the user in the same batch. */
export const userDisable = enablementOperation("user", "disabled");

/** user_enable: appends `enabled`. */
export const userEnable = enablementOperation("user", "enabled");

/** The result of session_revoke. */
export type SessionRevokeResult = { readonly user_id: string; readonly sessions_deleted: number };

/**
 * session_revoke: deletes every session of an existing user, even zero of them, and records the count. A missing
 * user is not-found, so a mistyped ID does not succeed silently (idpctl.md).
 */
export const sessionRevoke: WriteOperation<{ readonly user_id: string }, SessionRevokeResult> = {
  name: "session_revoke",
  class: { access: "write", concern: "user" },
  establishesIdentity: false,
  idempotent: false,
  target: { kind: "user", field: "user_id" },
  input: z.strictObject({ user_id: uuidSchema }),
  http: { method: "DELETE", path: "/v1/users/{id}/sessions", status: 200 },
  async plan(_ctx, input) {
    const guard = { sql: "EXISTS (SELECT 1 FROM users WHERE id = ?)", params: [input.user_id] };
    return {
      target: `user:${input.user_id}`,
      probe: { sql: "SELECT EXISTS (SELECT 1 FROM users WHERE id = ?) AS found", params: [input.user_id] },
      guard,
      writes: [{ sql: `DELETE FROM sessions WHERE user_id = ? AND ${guard.sql}`, params: [input.user_id, ...guard.params] }],
      detail: {},
      computed: [{ key: "sessions_deleted", sql: "SELECT COUNT(*) FROM sessions WHERE user_id = ?", params: [input.user_id] }],
      settle(probe) {
        if (probe["found"] !== 1) throw new AdminProblem("not-found", "The user does not exist");
        return "write";
      },
      result: (writes) => ({ user_id: input.user_id, sessions_deleted: writes[0]?.changes ?? 0 }),
    };
  },
};

/** One user in users_list. */
export type UserSummary = {
  readonly user_id: string;
  readonly name: string;
  readonly enablement: Enablement;
  readonly created_at: number;
  readonly passkey_count: number;
};

const USERS_PAGE: PageQuery = {
  columns:
    "u.id, u.name, u.created_at, COALESCE(ue.enablement, 'disabled') AS enablement, " +
    "(SELECT COUNT(*) FROM credentials c WHERE c.user_id = u.id) AS passkey_count",
  from: "users u LEFT JOIN user_enablement ue ON ue.user_id = u.id",
  filters: [],
  key: [
    { sql: "u.created_at", column: "created_at", type: "integer" },
    { sql: "u.id", column: "id", type: "text" },
  ],
  order: "asc",
};

function toUserSummary(row: SqlRow): UserSummary {
  return {
    user_id: row["id"] as string,
    name: row["name"] as string,
    enablement: row["enablement"] as Enablement,
    created_at: row["created_at"] as number,
    passkey_count: row["passkey_count"] as number,
  };
}

/** users_list: users in creation order, with their state and passkey count. */
export const usersList: ReadOperation<PageInput, Page<UserSummary>> = {
  name: "users_list",
  class: { access: "read" },
  establishesIdentity: false,
  input: z.strictObject(pageInputShape),
  http: { method: "GET", path: "/v1/users", status: 200 },
  read: (ctx, input) => readPage(ctx.db, USERS_PAGE, input, toUserSummary),
};

/** One passkey in user_get. */
export type PasskeySummary = {
  readonly credential_id: string;
  readonly created_at: number;
  readonly last_used_at: number | null;
  readonly created_via: "enroll" | "self";
  /** The WebAuthn backup eligibility flag: whether the passkey is a synced (multi-device) credential. */
  readonly backup_eligible: boolean;
  /** The WebAuthn backup state flag at the last ceremony. */
  readonly backup_state: boolean;
};

/** The result of user_get. */
export type UserDetail = Omit<UserSummary, "passkey_count"> & { readonly passkeys: readonly PasskeySummary[] };

/** user_get: one user with the list of their passkeys (idpctl.md), read in one snapshot. */
export const userGet: ReadOperation<{ readonly user_id: string }, UserDetail> = {
  name: "user_get",
  class: { access: "read" },
  establishesIdentity: false,
  input: z.strictObject({ user_id: uuidSchema }),
  http: { method: "GET", path: "/v1/users/{id}", status: 200 },
  async read(ctx, input) {
    const [user, passkeys] = await ctx.db.batch([
      { sql: `SELECT id, name, created_at, ${currentEnablementSql("user")} AS enablement FROM users WHERE id = ?`, params: [input.user_id, input.user_id] },
      {
        sql:
          "SELECT id, created_at, last_used_at, created_via, backup_eligible, backup_state FROM credentials " +
          "WHERE user_id = ? ORDER BY created_at, id",
        params: [input.user_id],
      },
    ]);
    const row = user?.rows[0];
    if (row === undefined) throw new AdminProblem("not-found", "The user does not exist");
    return {
      user_id: row["id"] as string,
      name: row["name"] as string,
      enablement: row["enablement"] as Enablement,
      created_at: row["created_at"] as number,
      passkeys: (passkeys?.rows ?? []).map((p) => ({
        credential_id: p["id"] as string,
        created_at: p["created_at"] as number,
        last_used_at: p["last_used_at"] as number | null,
        created_via: p["created_via"] as "enroll" | "self",
        backup_eligible: p["backup_eligible"] === 1,
        backup_state: p["backup_state"] === 1,
      })),
    };
  },
};
