import { join } from "node:path";
import { ESLint } from "eslint";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "..", "..", "..");

async function lintAs(filePath: string, code: string): Promise<readonly string[]> {
  const eslint = new ESLint({ cwd: root });
  const [result] = await eslint.lintText(code, { filePath: join(root, filePath) });
  return (result?.messages ?? []).map((m) => m.ruleId ?? m.message);
}

describe("user-facing code cannot import the admin modules", () => {
  it.each([
    ["apps/worker/src/probe.ts", 'import "@idp/core/admin";'],
    ["apps/worker/src/probe.ts", 'import "@idp/core/admin/users";'],
    ["packages/core/src/user/probe.ts", 'import "../admin/index.js";'],
    ["packages/core/src/shared/probe.ts", 'import "../admin/index.js";'],
    ["apps/worker/src/probe.ts", 'import "@idp/d1-adapter/admin";'],
    ["apps/worker/src/probe.ts", 'import "../../../packages/d1-adapter/src/admin.js";'],
  ])("%s rejects %s", async (file, code) => {
    expect(await lintAs(file, code)).toContain("no-restricted-imports");
  });

  it.each([
    ["apps/worker/src/probe.ts", 'import "@idp/core/user";'],
    ["apps/worker/src/probe.ts", 'import "@idp/core/shared";'],
    ["apps/admin-worker/src/probe.ts", 'import "@idp/core/admin";'],
  ])("%s allows %s", async (file, code) => {
    expect(await lintAs(file, code)).not.toContain("no-restricted-imports");
  });
});

// A standards package must stay copy-portable (docs/design/packages.md, "依存の禁止の強制").
describe("standards packages import only web standards and their declared standards packages", () => {
  it.each([
    'import "node:crypto";',
    'import "cloudflare:workers";',
    'import "@cloudflare/workers-types";',
    'import "zod";',
    'import "hono";',
    'import "@idp/core/user";',
    'import "@idp/cloudflare/d1";',
    'import "@idp/d1-adapter";',
    'import "../../core/src/user/index.js";',
  ])("packages/base64url/src rejects %s", async (code) => {
    expect(await lintAs("packages/base64url/src/probe.ts", code)).toContain("no-restricted-imports");
  });

  it.each([
    ["packages/base64url/src/probe.ts", 'import "./base64url.js";'],
    ["packages/jwk-thumbprint/src/probe.ts", 'import "@idp/base64url";'],
  ])("%s allows %s", async (file, code) => {
    expect(await lintAs(file, code)).not.toContain("no-restricted-imports");
  });

  it("a standards package cannot import a standards package it does not declare", async () => {
    expect(await lintAs("packages/base64url/src/probe.ts", 'import "@idp/jwk-thumbprint";')).toContain("no-restricted-imports");
  });

  it("the sample relying party cannot import a standards package", async () => {
    expect(await lintAs("examples/rp-sample/src/probe.ts", 'import "@idp/base64url";')).toContain("no-restricted-imports");
  });
});
