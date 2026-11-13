// The output schemas must accept the results the operations really return: the runtime test parses real results
// from a local D1 with the schemas.
import { describe, expect, it } from "vitest";
import type { z } from "zod";
import * as o from "../../src/domain/outputs.js";
import { clientCreate } from "../../src/domain/clients.js";
import { accessCheck, grantAdd, grantsList } from "../../src/domain/grants.js";
import { groupCreate, groupMemberAdd, groupsList } from "../../src/domain/groups.js";
import { enrollLinkIssue } from "../../src/domain/passkeys.js";
import { auditTail } from "../../src/domain/audit-tail.js";
import { clientsList } from "../../src/domain/clients.js";
import { sessionRevoke, userCreate, userDisable, userGet, usersList } from "../../src/domain/users.js";
import { run, seedPasskey, useHarness } from "./harness.js";

describe("output schemas", () => {
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
});
