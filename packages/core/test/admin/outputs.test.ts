// The output schemas must describe exactly the result types: the type tests below fail to compile when a member is
// added to, removed from, or retyped in one but not the other (tsc runs on the tests), and the runtime tests parse
// real results from a local D1 with the schemas.
import { describe, expect, expectTypeOf, it } from "vitest";
import type { z } from "zod";
import {
  ADMIN_OPERATIONS,
  type AccessCheckResult,
  type AuditEvent,
  type ClientCreateResult,
  type ClientRenameResult,
  type ClientRotateSecretResult,
  type ClientSetIdTokenAlgResult,
  type ClientSetRedirectsResult,
  type ClientSummary,
  type EnablementResult,
  type EnrollLinkIssueResult,
  type GrantAddResult,
  type GrantRemoveResult,
  type GrantSummary,
  type GroupCreateResult,
  type GroupMemberAddResult,
  type GroupRenameResult,
  type GroupSummary,
  type Page,
  type SessionRevokeResult,
  type UserCreateResult,
  type UserDetail,
  type UserRenameResult,
  type UserSummary,
} from "../../src/admin/index.js";
import * as o from "../../src/admin/outputs.js";
import { clientCreate } from "../../src/admin/clients.js";
import { accessCheck, grantAdd, grantsList } from "../../src/admin/grants.js";
import { groupCreate, groupMemberAdd, groupsList } from "../../src/admin/groups.js";
import { enrollLinkIssue } from "../../src/admin/passkeys.js";
import { auditTail } from "../../src/admin/audit-tail.js";
import { clientsList } from "../../src/admin/clients.js";
import { sessionRevoke, userCreate, userDisable, userGet, usersList } from "../../src/admin/users.js";
import { run, seedPasskey, useHarness } from "./harness.js";

type Out<S extends z.ZodType> = z.output<S>;
// Flattens an intersection (UserDetail, GroupMemberAddResult) into one object type, keeping readonly, so equality
// compares members rather than how the type was spelled.
type Flat<T> = { [K in keyof T]: T[K] };

describe("output schema types equal the result types", () => {
  it("users", () => {
    expectTypeOf<Out<typeof o.userCreateOutput>>().toEqualTypeOf<UserCreateResult>();
    expectTypeOf<Out<typeof o.userRenameOutput>>().toEqualTypeOf<UserRenameResult>();
    expectTypeOf<Out<typeof o.sessionRevokeOutput>>().toEqualTypeOf<SessionRevokeResult>();
    expectTypeOf<Out<typeof o.usersListOutput>>().toEqualTypeOf<Page<UserSummary>>();
    expectTypeOf<Out<typeof o.userGetOutput>>().toEqualTypeOf<Flat<UserDetail>>();
    expectTypeOf<Out<typeof o.enablementOutput>>().toEqualTypeOf<EnablementResult>();
    expectTypeOf<Out<typeof o.enrollLinkIssueOutput>>().toEqualTypeOf<EnrollLinkIssueResult>();
    expectTypeOf<Out<typeof o.passkeyRevokeOutput>>().toEqualTypeOf<{ readonly user_id: string; readonly credential_id: string }>();
  });

  it("groups", () => {
    expectTypeOf<Out<typeof o.groupCreateOutput>>().toEqualTypeOf<GroupCreateResult>();
    expectTypeOf<Out<typeof o.groupRenameOutput>>().toEqualTypeOf<GroupRenameResult>();
    expectTypeOf<Out<typeof o.groupMemberAddOutput>>().toEqualTypeOf<Flat<GroupMemberAddResult>>();
    expectTypeOf<Out<typeof o.groupMemberRemoveOutput>>().toEqualTypeOf<{ readonly group_id: string; readonly user_id: string }>();
    expectTypeOf<Out<typeof o.groupsListOutput>>().toEqualTypeOf<Page<GroupSummary>>();
  });

  it("clients", () => {
    expectTypeOf<Out<typeof o.clientCreateOutput>>().toEqualTypeOf<ClientCreateResult>();
    expectTypeOf<Out<typeof o.clientRenameOutput>>().toEqualTypeOf<ClientRenameResult>();
    expectTypeOf<Out<typeof o.clientSetRedirectsOutput>>().toEqualTypeOf<ClientSetRedirectsResult>();
    expectTypeOf<Out<typeof o.clientRotateSecretOutput>>().toEqualTypeOf<ClientRotateSecretResult>();
    expectTypeOf<Out<typeof o.clientSetIdTokenAlgOutput>>().toEqualTypeOf<ClientSetIdTokenAlgResult>();
    expectTypeOf<Out<typeof o.clientsListOutput>>().toEqualTypeOf<Page<ClientSummary>>();
  });

  it("access and audit", () => {
    expectTypeOf<Out<typeof o.grantAddOutput>>().toEqualTypeOf<GrantAddResult>();
    expectTypeOf<Out<typeof o.grantRemoveOutput>>().toEqualTypeOf<GrantRemoveResult>();
    expectTypeOf<Out<typeof o.grantsListOutput>>().toEqualTypeOf<Page<GrantSummary>>();
    expectTypeOf<Out<typeof o.accessCheckOutput>>().toEqualTypeOf<AccessCheckResult>();
    expectTypeOf<Out<typeof o.auditTailOutput>>().toEqualTypeOf<Page<AuditEvent>>();
  });
});

describe("output schemas", () => {
  it("are attached to every operation of the registry", () => {
    for (const operation of ADMIN_OPERATIONS) expect(operation.output, operation.name).toBeDefined();
  });

  const h = useHarness();

  it("accept the results the operations actually return", async () => {
    const user = (await run(h(), userCreate, { name: "Alice" })).body;
    expect(o.userCreateOutput.parse(user)).toEqual(user);
    await seedPasskey(h(), user.user_id);
    const group = (await run(h(), groupCreate, { name: "Family" })).body;
    const created = (
      await run(h(), clientCreate, { client_id: "grafana", name: "G", client_type: "confidential", redirect_uris: ["https://g.example.com/cb"] })
    ).body;
    const results: readonly (readonly [z.ZodType, unknown])[] = [
      [o.clientCreateOutput, created],
      [o.groupMemberAddOutput, (await run(h(), groupMemberAdd, { group_id: group.group_id, user_id: user.user_id }, null)).body],
      [o.grantAddOutput, (await run(h(), grantAdd, { client_id: "grafana", principal: `group:${group.group_id}` }, null)).body],
      [o.accessCheckOutput, (await run(h(), accessCheck, { user: user.user_id, client: "grafana" }, null)).body],
      [o.userGetOutput, (await run(h(), userGet, { user_id: user.user_id }, null)).body],
      [o.usersListOutput, (await run(h(), usersList, {}, null)).body],
      [o.groupsListOutput, (await run(h(), groupsList, {}, null)).body],
      [o.clientsListOutput, (await run(h(), clientsList, {}, null)).body],
      [o.grantsListOutput, (await run(h(), grantsList, {}, null)).body],
      [o.enrollLinkIssueOutput, (await run(h(), enrollLinkIssue, { user_id: user.user_id })).body],
      [o.sessionRevokeOutput, (await run(h(), sessionRevoke, { user_id: user.user_id }, null)).body],
      [o.enablementOutput, (await run(h(), userDisable, { user_id: user.user_id })).body],
      [o.auditTailOutput, (await run(h(), auditTail, {}, null)).body],
    ];
    for (const [schema, body] of results) expect(schema.parse(body)).toEqual(body);
  });

  it("omit a public client's secret rather than sending it as undefined", () => {
    expect(o.clientCreateOutput.safeParse({ client_id: "app", client_type: "public" }).success).toBe(true);
    expect(o.clientCreateOutput.safeParse({ client_id: "app", client_type: "public", client_secret: undefined }).success).toBe(false);
  });
});
