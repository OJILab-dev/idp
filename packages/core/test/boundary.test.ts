import { join } from "node:path";
import { ESLint } from "eslint";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "..", "..", "..");

async function lintAs(filePath: string, code: string): Promise<readonly string[]> {
  const eslint = new ESLint({ cwd: root });
  const [result] = await eslint.lintText(code, { filePath: join(root, filePath) });
  return (result?.messages ?? []).map((m) => m.ruleId ?? m.message);
}

// User-facing code never imports the admin modules, and the concern directories import neither use-case layer.
describe("core module boundaries", () => {
  it.each([
    ["apps/worker/src/probe.ts", 'import "@idp/core/admin";'],
    ["apps/worker/src/probe.ts", 'import "@idp/core/admin/users";'],
    ["apps/worker/src/probe.ts", 'import "../../admin-worker/src/domain/index.js";'],
    ["packages/core/src/user/probe.ts", 'import "../admin/index.js";'],
    ["packages/core/src/audit/probe.ts", 'import "../admin/index.js";'],
    ["packages/core/src/db/probe.ts", 'import "../user/index.js";'],
    ["packages/core/src/passkeys/probe.ts", 'import "../user/webauthn/ceremony.js";'],
  ])("%s rejects %s", async (file, code) => {
    expect(await lintAs(file, code)).toContain("no-restricted-imports");
  });

  it.each([
    ["apps/worker/src/probe.ts", 'import "@idp/core/user";'],
    ["apps/worker/src/probe.ts", 'import "@idp/core/db";'],
    ["packages/core/src/user/probe.ts", 'import "../audit/index.js";'],
    ["packages/core/src/audit/probe.ts", 'import "../db/index.js";'],
    ["apps/admin-worker/src/probe.ts", 'import "./domain/index.js";'],
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
    'import "@idp/cloudflare/workers/tls";',
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

// The core never depends on the platform, and the subpaths of @idp/cloudflare import each other only along declared
// edges (docs/design/packages.md, "@idp/cloudflare の規則").
describe("@idp/cloudflare boundaries", () => {
  it.each([
    ["packages/core/src/audit/probe.ts", 'import "@idp/cloudflare/d1";'],
    ["packages/core/src/user/probe.ts", 'import "@idp/cloudflare/workers/tls";'],
    ["packages/core/src/user/probe.ts", 'import "../../../cloudflare/src/d1/index.js";'],
    ["packages/cloudflare/src/d1/probe.ts", 'import "@idp/cloudflare/workers/tls";'],
    ["packages/cloudflare/src/d1/probe.ts", 'import "../workers/tls/index.js";'],
    ["packages/cloudflare/src/workers/tls/probe.ts", 'import "@idp/core/db";'],
    ["packages/cloudflare/src/workers/tls/probe.ts", 'import "@idp/cloudflare/d1";'],
    ["packages/cloudflare/src/workers/tls/probe.ts", 'import "../../d1/index.js";'],
  ])("%s rejects %s", async (file, code) => {
    expect(await lintAs(file, code)).toContain("no-restricted-imports");
  });

  it.each([
    ["packages/cloudflare/src/d1/probe.ts", 'import "@idp/core/db";'],
    ["packages/cloudflare/src/d1/probe.ts", 'import "@idp/base64url";'],
    ["packages/cloudflare/src/d1/probe.ts", 'import "./d1.js";'],
    ["apps/worker/src/probe.ts", 'import "@idp/cloudflare/d1";'],
    ["apps/worker/src/probe.ts", 'import "@idp/cloudflare/workers/tls";'],
  ])("%s allows %s", async (file, code) => {
    expect(await lintAs(file, code)).not.toContain("no-restricted-imports");
  });
});
