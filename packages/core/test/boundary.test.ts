import { join } from "node:path";
import { ESLint } from "eslint";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "..", "..", "..");

async function lintAs(filePath: string, code: string): Promise<readonly string[]> {
  const eslint = new ESLint({ cwd: root });
  const [result] = await eslint.lintText(code, { filePath: join(root, filePath) });
  return (result?.messages ?? []).map((m) => m.ruleId ?? m.message);
}

// The IdP Worker never imports the admin Worker, and neither it nor the core it bundles imports zod; the core never
// imports the apps (docs/design/packages.md, "配置の規則").
describe("app and core boundaries", () => {
  it.each([
    ["apps/worker/src/probe.ts", 'import "../../admin-worker/src/domain/index.js";'],
    ["apps/worker/src/probe.ts", 'import "@idp/admin-worker";'],
    ["apps/worker/src/probe.ts", 'import "zod";'],
    ["packages/core/src/audit/probe.ts", 'import "zod";'],
    ["packages/core/src/db/probe.ts", 'import "../../../../apps/worker/src/domain/index.js";'],
    ["packages/core/src/passkeys/probe.ts", 'import "@idp/admin-worker";'],
  ])("%s rejects %s", async (file, code) => {
    expect(await lintAs(file, code)).toContain("no-restricted-imports");
  });

  it.each([
    ["apps/worker/src/probe.ts", 'import "./domain/index.js";'],
    ["apps/worker/src/probe.ts", 'import "@idp/core/db";'],
    ["packages/core/src/audit/probe.ts", 'import "../db/index.js";'],
    ["apps/admin-worker/src/probe.ts", 'import "./domain/index.js";'],
    ["apps/admin-worker/src/probe.ts", 'import "zod";'],
  ])("%s allows %s", async (file, code) => {
    expect(await lintAs(file, code)).not.toContain("no-restricted-imports");
  });
});

// An app's domain layer stays testable without the framework: no Hono, no platform, no HTTP layer, no other app
// (docs/design/packages.md, "アプリのドメインの層").
describe("app domain boundaries", () => {
  it.each([
    ["apps/worker/src/domain/probe.ts", 'import "hono";'],
    ["apps/worker/src/domain/probe.ts", 'import "cloudflare:workers";'],
    ["apps/worker/src/domain/probe.ts", 'import "@idp/cloudflare/d1";'],
    ["apps/worker/src/domain/probe.ts", 'import "../app.js";'],
    ["apps/worker/src/domain/probe.ts", 'import "zod";'],
    ["apps/worker/src/domain/webauthn/probe.ts", 'import "../../webauthn.js";'],
    ["apps/worker/src/domain/webauthn/probe.ts", 'import "hono/http-exception";'],
    ["apps/admin-worker/src/domain/probe.ts", 'import "hono";'],
    ["apps/admin-worker/src/domain/probe.ts", 'import "cloudflare:workers";'],
    ["apps/admin-worker/src/domain/probe.ts", 'import "@idp/cloudflare/workers/tls";'],
    ["apps/admin-worker/src/domain/probe.ts", 'import "../../../../packages/cloudflare/src/d1/index.js";'],
    ["apps/admin-worker/src/domain/probe.ts", 'import "../gate.js";'],
    ["apps/admin-worker/src/domain/probe.ts", 'import "../../../worker/src/domain/index.js";'],
  ])("%s rejects %s", async (file, code) => {
    expect(await lintAs(file, code)).toContain("no-restricted-imports");
  });

  it.each([
    ["apps/worker/src/domain/probe.ts", 'import "@idp/core/db";'],
    ["apps/worker/src/domain/probe.ts", 'import "@idp/jws";'],
    ["apps/worker/src/domain/probe.ts", 'import "./sessions.js";'],
    ["apps/worker/src/domain/webauthn/probe.ts", 'import "../sessions.js";'],
    ["apps/admin-worker/src/domain/probe.ts", 'import "@idp/core/audit";'],
    ["apps/admin-worker/src/domain/probe.ts", 'import "zod";'],
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
    'import "@idp/core/db";',
    'import "@idp/cloudflare/d1";',
    'import "@idp/cloudflare/workers/tls";',
    'import "../../core/src/db/index.js";',
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
    ["packages/core/src/passkeys/probe.ts", 'import "@idp/cloudflare/workers/tls";'],
    ["packages/core/src/passkeys/probe.ts", 'import "../../../cloudflare/src/d1/index.js";'],
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
