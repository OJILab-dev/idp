// Group management (docs/design/idpctl.md, docs/design/authorization.md): create, rename, enable and disable, add
// and remove members, and list. Groups are named by ID, never by name, since names change.
import { groupCreateOutput, groupMemberAddOutput, groupMemberRemoveOutput, groupRenameOutput, groupsListOutput } from "./outputs.js";
import { z } from "zod";
import { newUuidV4 } from "../identifiers/index.js";
import type { SqlRow } from "../db/index.js";
import { pairsAsJson, pairsEnabledByMembership, toPairs, type AccessPair } from "./access.js";
import { enablementOperation, initialEnablementStatement, type Enablement } from "./enablement.js";
import type { ReadOperation, WriteOperation } from "./operation.js";
import { readPage, type Page, type PageQuery } from "./paging.js";
import { AdminProblem } from "./problem.js";
import { nameSchema, pageInputShape, uuidSchema, type PageInput } from "./schemas.js";

/** The result of group_create. */
export type GroupCreateResult = { readonly group_id: string };

/** group_create: a group with no members and no grants, and its first `enabled` event. Names are unique. */
export const groupCreate: WriteOperation<{ readonly name: string }, GroupCreateResult> = {
  name: "group_create",
  class: { access: "write", concern: "user" },
  establishesIdentity: false,
  idempotent: true,
  target: "none",
  input: z.strictObject({ name: nameSchema }),
  http: { method: "POST", path: "/v1/groups", status: 201 },
  output: groupCreateOutput,
  async plan(ctx, input) {
    const now = ctx.now();
    const id = newUuidV4();
    const guard = { sql: "NOT EXISTS (SELECT 1 FROM groups WHERE name = ?)", params: [input.name] };
    // The guard turns false once the group row exists, so the later inserts key off the fresh principal instead.
    const created = { sql: "EXISTS (SELECT 1 FROM principals WHERE id = ?)", params: [id] };
    return {
      target: `group:${id}`,
      probe: { sql: "SELECT EXISTS (SELECT 1 FROM groups WHERE name = ?) AS taken", params: [input.name] },
      guard,
      writes: [
        { sql: `INSERT INTO principals (id, kind) SELECT ?, 'group' WHERE ${guard.sql}`, params: [id, ...guard.params] },
        {
          sql: `INSERT INTO groups (id, name, created_at) SELECT ?, ?, ? WHERE ${created.sql}`,
          params: [id, input.name, now, ...created.params],
        },
        initialEnablementStatement("group", id, now, created),
      ],
      detail: {},
      settle(probe) {
        if (probe["taken"] === 1) throw new AdminProblem("already-exists", "A group with this name already exists");
        return "write";
      },
      result: () => ({ group_id: id }),
    };
  },
};

/** The result of group_rename. */
export type GroupRenameResult = { readonly group_id: string; readonly name: string };

/** group_rename: changes the name; the ID, members, and grants stay. A name another group holds is already-exists. */
export const groupRename: WriteOperation<{ readonly group_id: string; readonly name: string }, GroupRenameResult> = {
  name: "group_rename",
  class: { access: "write", concern: "user" },
  establishesIdentity: false,
  idempotent: false,
  target: { kind: "group", field: "group_id" },
  input: z.strictObject({ group_id: uuidSchema, name: nameSchema }),
  http: { method: "PUT", path: "/v1/groups/{id}/name", status: 200 },
  output: groupRenameOutput,
  async plan(_ctx, input) {
    const id = input.group_id;
    const guard = {
      sql:
        "EXISTS (SELECT 1 FROM groups WHERE id = ? AND name IS NOT ?) " +
        "AND NOT EXISTS (SELECT 1 FROM groups WHERE name = ? AND id <> ?)",
      params: [id, input.name, input.name, id],
    };
    return {
      target: `group:${id}`,
      probe: {
        sql:
          "SELECT EXISTS (SELECT 1 FROM groups WHERE id = ?) AS found, " +
          "EXISTS (SELECT 1 FROM groups WHERE id = ? AND name = ?) AS same, " +
          "EXISTS (SELECT 1 FROM groups WHERE name = ? AND id <> ?) AS taken",
        params: [id, id, input.name, input.name, id],
      },
      guard,
      writes: [{ sql: `UPDATE groups SET name = ? WHERE id = ? AND ${guard.sql}`, params: [input.name, id, ...guard.params] }],
      detail: {},
      settle(probe) {
        if (probe["found"] !== 1) throw new AdminProblem("not-found", "The group does not exist");
        if (probe["same"] === 1) return "noop";
        if (probe["taken"] === 1) throw new AdminProblem("already-exists", "Another group already has this name");
        return "write";
      },
      result: () => ({ group_id: id, name: input.name }),
    };
  },
};

/** group_disable: appends `disabled`; grants through the group stop counting, membership and grants stay. */
export const groupDisable = enablementOperation("group", "disabled");

/** group_enable: appends `enabled`. */
export const groupEnable = enablementOperation("group", "enabled");

type MembershipInput = { readonly group_id: string; readonly user_id: string };

/** The result of group_member_add. */
export type GroupMemberAddResult = MembershipInput & { readonly newly_enabled: readonly AccessPair[] };

/**
 * group_member_add: adds a user to a group and returns, and records, the user × client pairs this newly enables.
 * Adding an existing member succeeds without writing; a missing group or user is not-found.
 */
export const groupMemberAdd: WriteOperation<MembershipInput, GroupMemberAddResult> = {
  name: "group_member_add",
  class: { access: "write", concern: "user" },
  establishesIdentity: false,
  idempotent: false,
  target: { kind: "group", field: "group_id" },
  input: z.strictObject({ group_id: uuidSchema, user_id: uuidSchema }),
  http: { method: "PUT", path: "/v1/groups/{id}/members/{user_id}", status: 200 },
  output: groupMemberAddOutput,
  async plan(_ctx, input) {
    const { group_id: groupId, user_id: userId } = input;
    const guard = {
      sql:
        "EXISTS (SELECT 1 FROM groups WHERE id = ?) AND EXISTS (SELECT 1 FROM users WHERE id = ?) " +
        "AND NOT EXISTS (SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?)",
      params: [groupId, userId, groupId, userId],
    };
    const pairs = pairsEnabledByMembership(groupId, userId);
    return {
      target: `group:${groupId}`,
      probe: {
        sql:
          "SELECT EXISTS (SELECT 1 FROM groups WHERE id = ?) AS group_found, EXISTS (SELECT 1 FROM users WHERE id = ?) AS user_found, " +
          "EXISTS (SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?) AS member",
        params: [groupId, userId, groupId, userId],
      },
      guard,
      writes: [
        { sql: `SELECT * FROM (${pairs.sql}) WHERE ${guard.sql}`, params: [...pairs.params, ...guard.params] },
        { sql: `INSERT INTO group_members (user_id, group_id) SELECT ?, ? WHERE ${guard.sql}`, params: [userId, groupId, ...guard.params] },
      ],
      detail: { user_id: userId },
      computed: [{ key: "newly_enabled", ...pairsAsJson(pairs) }],
      settle(probe) {
        if (probe["group_found"] !== 1) throw new AdminProblem("not-found", "The group does not exist");
        if (probe["user_found"] !== 1) throw new AdminProblem("not-found", "The user does not exist");
        return probe["member"] === 1 ? "noop" : "write";
      },
      result: (writes) => ({ group_id: groupId, user_id: userId, newly_enabled: toPairs(writes[0]?.rows ?? []) }),
    };
  },
};

/** group_member_remove: removes a membership; removing one that does not exist is not-found (idpctl.md). */
export const groupMemberRemove: WriteOperation<MembershipInput, MembershipInput> = {
  name: "group_member_remove",
  class: { access: "write", concern: "user" },
  establishesIdentity: false,
  idempotent: false,
  target: { kind: "group", field: "group_id" },
  input: z.strictObject({ group_id: uuidSchema, user_id: uuidSchema }),
  http: { method: "DELETE", path: "/v1/groups/{id}/members/{user_id}", status: 200 },
  output: groupMemberRemoveOutput,
  async plan(_ctx, input) {
    const { group_id: groupId, user_id: userId } = input;
    const guard = { sql: "EXISTS (SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?)", params: [groupId, userId] };
    return {
      target: `group:${groupId}`,
      probe: { sql: `SELECT ${guard.sql} AS member`, params: guard.params },
      guard,
      writes: [{ sql: "DELETE FROM group_members WHERE group_id = ? AND user_id = ?", params: [groupId, userId] }],
      detail: { user_id: userId },
      settle(probe) {
        if (probe["member"] !== 1) throw new AdminProblem("not-found", "The user is not a member of the group");
        return "write";
      },
      result: () => ({ group_id: groupId, user_id: userId }),
    };
  },
};

/** One group in groups_list. */
export type GroupSummary = {
  readonly group_id: string;
  readonly name: string;
  readonly enablement: Enablement;
  readonly created_at: number;
  readonly members: readonly string[];
  readonly clients: readonly string[];
};

const GROUPS_PAGE: PageQuery = {
  columns:
    "g.id, g.name, g.created_at, COALESCE(ge.enablement, 'disabled') AS enablement, " +
    "(SELECT json_group_array(user_id) FROM (SELECT user_id FROM group_members WHERE group_id = g.id ORDER BY user_id)) AS members, " +
    "(SELECT json_group_array(client_id) FROM (SELECT client_id FROM client_access WHERE principal_id = g.id ORDER BY client_id)) AS clients",
  from: "groups g LEFT JOIN group_enablement ge ON ge.group_id = g.id",
  filters: [],
  key: [
    { sql: "g.created_at", column: "created_at", type: "integer" },
    { sql: "g.id", column: "id", type: "text" },
  ],
  order: "asc",
};

function toGroupSummary(row: SqlRow): GroupSummary {
  return {
    group_id: row["id"] as string,
    name: row["name"] as string,
    enablement: row["enablement"] as Enablement,
    created_at: row["created_at"] as number,
    members: JSON.parse(row["members"] as string) as string[],
    clients: JSON.parse(row["clients"] as string) as string[],
  };
}

/** groups_list: groups in creation order, each with its state, member user IDs, and granted client IDs. */
export const groupsList: ReadOperation<PageInput, Page<GroupSummary>> = {
  name: "groups_list",
  class: { access: "read" },
  establishesIdentity: false,
  input: z.strictObject(pageInputShape),
  http: { method: "GET", path: "/v1/groups", status: 200 },
  output: groupsListOutput,
  read: (ctx, input) => readPage(ctx.db, GROUPS_PAGE, input, toGroupSummary),
};
