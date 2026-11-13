// What the admin Worker's HTTP layer needs from the core beyond the operations themselves: a request the HTTP layer
// rejects before validation is still recorded as a failure row.
import { describe, expect, it } from "vitest";
import { AdminProblem, executeOperation } from "../../src/admin/index.js";
import { usersList, userRename } from "../../src/admin/users.js";
import { auditRows, useHarness } from "./harness.js";

const h = useHarness();
const USER = "00000000-0000-4000-8000-000000000001";

describe("executeOperation with a rejection from the HTTP layer", () => {
  it("throws the rejection and records it as the write's failure row, naming a valid target", async () => {
    const rejection = new AdminProblem("validation-failed", "The body is not JSON", { pointers: [""] });
    await expect(executeOperation(h().ctx(), userRename, { user_id: USER }, { rejection })).rejects.toBe(rejection);
    const rows = await auditRows(h());
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      operation: "user_rename",
      result: "failure",
      target: `user:${USER}`,
      detail: { problem: "validation-failed" },
    });
  });

  it("throws the rejection of a read without writing", async () => {
    const rejection = new AdminProblem("validation-failed", "bad");
    await expect(executeOperation(h().ctx(), usersList, {}, { rejection })).rejects.toBe(rejection);
    expect(await auditRows(h())).toEqual([]);
  });
});
