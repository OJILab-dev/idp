// What the admin Worker's HTTP layer needs from the core beyond the operations themselves: a request the HTTP layer
// rejects before validation is still recorded as a failure row, and the enablement-events body has one schema.
import { describe, expect, it } from "vitest";
import { AdminProblem, enablementEventSchema, executeOperation } from "../../src/admin/index.js";
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

  it("never runs the operation", async () => {
    const rejection = new AdminProblem("validation-failed", "bad");
    await expect(executeOperation(h().ctx(), userRename, { user_id: USER, name: "Alice" }, { rejection })).rejects.toBe(rejection);
    const rows = await auditRows(h());
    expect(rows.map((r) => r["result"])).toEqual(["failure"]);
  });

  it("throws the rejection of a read without writing", async () => {
    const rejection = new AdminProblem("validation-failed", "bad");
    await expect(executeOperation(h().ctx(), usersList, {}, { rejection })).rejects.toBe(rejection);
    expect(await auditRows(h())).toEqual([]);
  });
});

describe("enablementEventSchema", () => {
  it("accepts exactly one enablement member", () => {
    expect(enablementEventSchema.parse({ enablement: "enabled" })).toEqual({ enablement: "enabled" });
    expect(enablementEventSchema.parse({ enablement: "disabled" })).toEqual({ enablement: "disabled" });
  });

  it("rejects other values and members", () => {
    expect(enablementEventSchema.safeParse({ enablement: "on" }).success).toBe(false);
    expect(enablementEventSchema.safeParse({}).success).toBe(false);
    expect(enablementEventSchema.safeParse({ enablement: "enabled", reason: "x" }).success).toBe(false);
  });
});
