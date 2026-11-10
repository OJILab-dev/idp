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
