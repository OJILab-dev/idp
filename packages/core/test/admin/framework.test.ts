import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
  ADMIN_OPERATIONS,
  AdminProblem,
  OPERATION_NAMES,
  PROBLEM_STATUS,
  enablementOperationName,
  executeOperation,
  problemType,
  type WriteOperation,
} from "../../src/admin/index.js";
import { parseInput } from "../../src/admin/schemas.js";
import { userRename } from "../../src/admin/users.js";
import { DatabaseError, PROBLEM_KINDS, type Database } from "../../src/shared/index.js";
import { auditRows, query, run, useHarness } from "./harness.js";

const h = useHarness();

// docs/design/idpctl.md, "操作の一覧" and "管理 API の形": [class, concern, method, path].
const EXPECTED: Readonly<Record<string, readonly [string, string | null, string, string]>> = {
  users_list: ["read", null, "GET", "/v1/users"],
  user_get: ["read", null, "GET", "/v1/users/{id}"],
  clients_list: ["read", null, "GET", "/v1/clients"],
  groups_list: ["read", null, "GET", "/v1/groups"],
  grants_list: ["read", null, "GET", "/v1/grants"],
  access_check: ["read", null, "GET", "/v1/access"],
  audit_tail: ["read", null, "GET", "/v1/audit-events"],
  user_create: ["write", "user", "POST", "/v1/users"],
  user_rename: ["write", "user", "PUT", "/v1/users/{id}/name"],
  user_disable: ["write", "user", "POST", "/v1/users/{id}/enablement-events"],
  user_enable: ["write", "user", "POST", "/v1/users/{id}/enablement-events"],
  enroll_link_issue: ["write", "user", "POST", "/v1/users/{id}/enrollment-links"],
  passkey_revoke: ["write", "user", "DELETE", "/v1/users/{id}/passkeys/{credential_id}"],
  session_revoke: ["write", "user", "DELETE", "/v1/users/{id}/sessions"],
  group_create: ["write", "user", "POST", "/v1/groups"],
  group_rename: ["write", "user", "PUT", "/v1/groups/{id}/name"],
  group_disable: ["write", "user", "POST", "/v1/groups/{id}/enablement-events"],
  group_enable: ["write", "user", "POST", "/v1/groups/{id}/enablement-events"],
  group_member_add: ["write", "user", "PUT", "/v1/groups/{id}/members/{user_id}"],
  group_member_remove: ["write", "user", "DELETE", "/v1/groups/{id}/members/{user_id}"],
  client_create: ["write", "rp", "POST", "/v1/clients"],
  client_rename: ["write", "rp", "PUT", "/v1/clients/{id}/name"],
  client_set_redirects: ["write", "rp", "PUT", "/v1/clients/{id}/redirect-uris"],
  client_set_post_logout_redirects: ["write", "rp", "PUT", "/v1/clients/{id}/post-logout-redirect-uris"],
  client_rotate_secret: ["write", "rp", "POST", "/v1/clients/{id}/secrets"],
  client_set_id_token_alg: ["write", "rp", "PUT", "/v1/clients/{id}/id-token-alg"],
  client_disable: ["write", "rp", "POST", "/v1/clients/{id}/enablement-events"],
  client_enable: ["write", "rp", "POST", "/v1/clients/{id}/enablement-events"],
  grant_add: ["write", "access", "PUT", "/v1/clients/{id}/grants/{principal}"],
  grant_remove: ["write", "access", "DELETE", "/v1/clients/{id}/grants/{principal}"],
};

describe("the operation catalogue", () => {
  it("names the 30 operations of idpctl.md: 7 reads, 13 user, 8 rp, 2 access", () => {
    expect([...OPERATION_NAMES].sort()).toEqual(Object.keys(EXPECTED).sort());
    const counts = Object.values(EXPECTED).reduce<Record<string, number>>((acc, [cls, concern]) => {
      const key = concern ?? cls;
      acc[key] = (acc[key] ?? 0) + 1;
      return acc;
    }, {});
    expect(counts).toEqual({ read: 7, user: 13, rp: 8, access: 2 });
  });

  it("registers each of the 30 operations exactly once", () => {
    const names = ADMIN_OPERATIONS.map((o) => o.name);
    expect(new Set(names).size).toBe(names.length);
    expect([...names].sort()).toEqual([...OPERATION_NAMES].sort());
  });

  it("marks only enroll_link_issue as establishing identity", () => {
    expect(ADMIN_OPERATIONS.filter((o) => o.establishesIdentity).map((o) => o.name)).toEqual(["enroll_link_issue"]);
  });

  it.each(ADMIN_OPERATIONS.map((o) => [o.name, o] as const))("classifies %s as idpctl.md does", (name, operation) => {
    const [cls, concern, method, path] = EXPECTED[name] ?? [];
    expect(operation.class.access).toBe(cls);
    expect("concern" in operation.class ? operation.class.concern : null).toBe(concern);
    expect(operation.http.method).toBe(method);
    expect(operation.http.path).toBe(path);
    expect(operation.establishesIdentity).toBe(name === "enroll_link_issue");
    expect("read" in operation).toBe(cls === "read");
    // Idempotency-Key is required by exactly the creating and appending POSTs.
    if ("plan" in operation) expect(operation.idempotent).toBe(method === "POST");
    expect(operation.http.status).toBe(method === "POST" ? 201 : 200);
  });

  it("maps an enablement event to its operation name", () => {
    expect(enablementOperationName("user", "disabled")).toBe("user_disable");
    expect(enablementOperationName("client", "enabled")).toBe("client_enable");
    expect(enablementOperationName("group", "disabled")).toBe("group_disable");
  });
});

describe("problems", () => {
  it("maps every kind to the status of idpctl.md and to a urn type", () => {
    expect(Object.keys(PROBLEM_STATUS).sort()).toEqual([...PROBLEM_KINDS].sort());
    expect(PROBLEM_STATUS["validation-failed"]).toBe(400);
    expect(PROBLEM_STATUS["not-found"]).toBe(404);
    expect(PROBLEM_STATUS["idempotency-key-reused"]).toBe(422);
    expect(PROBLEM_STATUS.forbidden).toBe(403);
    expect(PROBLEM_STATUS.internal).toBe(500);
    for (const kind of ["already-exists", "state-conflict", "limit-reached", "last-passkey", "algorithm-disabled", "secret-not-replayable"] as const) {
      expect(PROBLEM_STATUS[kind]).toBe(409);
    }
    expect(problemType("not-found")).toBe("urn:ojilab:idp:problem:not-found");
  });

  it("serialises RFC 9457 problem details, with pointers only for validation", () => {
    expect(new AdminProblem("validation-failed", "bad", { pointers: ["/name"] }).toProblemDetails()).toEqual({
      type: "urn:ojilab:idp:problem:validation-failed",
      title: "The request is not valid",
      status: 400,
      detail: "bad",
      errors: ["/name"],
    });
    expect(new AdminProblem("not-found", "The user does not exist").toProblemDetails()).not.toHaveProperty("errors");
  });

  it("never exposes an internal detail", () => {
    const details = new AdminProblem("internal", "SELECT secret FROM x").toProblemDetails();
    expect(details.detail).not.toContain("SELECT");
  });
});

describe("parseInput", () => {
  it("reports every failing field as an escaped JSON Pointer", () => {
    const schema = z.strictObject({ "a/b": z.string(), list: z.array(z.int()), "c~d": z.string() });
    try {
      parseInput(schema, { "a/b": 1, list: [1, "x"], "c~d": "ok" });
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(AdminProblem);
      expect((error as AdminProblem).pointers).toEqual(["/a~1b", "/list/1"]);
    }
  });

  it("points at the root for a non-object input", () => {
    expect(() => parseInput(z.strictObject({}), "x")).toThrow(expect.objectContaining({ pointers: [""] }));
  });
});

describe("executeOperation", () => {
  it("wraps a database failure as internal, writes a failure row, and leaves no partial write", async () => {
    const failing: Database = {
      batch: async (statements) => {
        if (statements.some((s) => s.sql.startsWith("UPDATE"))) throw new DatabaseError("boom");
        return h().db.batch(statements);
      },
    };
    const ctx = { ...h().ctx(), db: failing };
    const id = "0f8fad5b-d9cb-469f-a165-70867728950e";
    const outcome = executeOperation(ctx, userRename, { user_id: id, name: "x" });
    await expect(outcome).rejects.toMatchObject({ kind: "internal", cause: expect.any(DatabaseError) });
    expect(await auditRows(h())).toEqual([expect.objectContaining({ result: "failure", target: `user:${id}`, detail: { problem: "internal" } })]);
  });

  it("hands a failure-row error to onFailureAuditError and still throws the original problem", async () => {
    const broken: Database = {
      batch: async () => {
        throw new DatabaseError("unreachable");
      },
    };
    const ctx = { ...h().ctx(), db: broken };
    await expect(executeOperation(ctx, userRename, { user_id: "bad", name: "x" })).rejects.toMatchObject({ kind: "validation-failed" });
    expect(h().failureAuditErrors).toEqual([expect.any(DatabaseError)]);
  });

  it("reports internal when a plan's guard and settle disagree", async () => {
    const liar: WriteOperation<Record<string, never>, null> = {
      name: "user_create",
      class: { access: "write", concern: "user" },
      establishesIdentity: false,
      idempotent: false,
      target: "none",
      input: z.strictObject({}),
      output: z.null(),
      http: { method: "POST", path: "/v1/users", status: 201 },
      plan: async () => ({
        target: "none",
        probe: { sql: "SELECT 1 AS ok", params: [] },
        guard: { sql: "0", params: [] },
        writes: [],
        detail: {},
        settle: () => "write",
        result: () => null,
      }),
    };
    await expect(run(h(), liar, {}, null)).rejects.toMatchObject({ kind: "internal" });
  });

  it("checks the admin identity through the audit-row builder", async () => {
    h().admin = { name: "root", keyid: "not-hex" };
    await expect(run(h(), userRename, { user_id: "0f8fad5b-d9cb-469f-a165-70867728950e", name: "x" }, null)).rejects.toMatchObject({
      kind: "internal",
    });
    expect(await query(h(), "SELECT COUNT(*) AS n FROM audit_log")).toEqual([{ n: 0 }]);
  });
});

describe("module boundaries", () => {
  // zod is for the admin API's schemas; keeping it out of shared and user keeps it out of the IdP Worker's bundle.
  it.each(["shared", "user"])("src/%s does not import zod", (dir) => {
    const root = join(import.meta.dirname, "..", "..", "src", dir);
    // Recursive, so a subdirectory such as src/user/webauthn is covered as well.
    const files = readdirSync(root, { recursive: true, withFileTypes: true }).filter((entry) => entry.isFile());
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      expect(readFileSync(join(file.parentPath, file.name), "utf8"), file.name).not.toMatch(/from "zod/);
    }
  });
});
