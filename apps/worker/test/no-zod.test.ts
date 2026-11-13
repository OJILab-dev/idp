// zod is for the admin API's schemas, which live in the admin Worker. Keeping every import of it out of the IdP
// Worker's sources and the domain packages it bundles keeps it out of the IdP Worker's bundle
// (docs/design/technology.md).
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "..", "..", "..");

describe("the IdP Worker bundles no zod", () => {
  const domainPackages = ["audit", "clients", "db", "hosting", "identifiers", "issuer", "passkeys", "problems"];
  it.each(["apps/worker/src", "apps/worker/pages", ...domainPackages.map((dir) => `packages/${dir}/src`)])("%s does not import zod", (dir) => {
    // Recursive, so subdirectories such as src/domain/webauthn are covered as well.
    const files = readdirSync(join(root, dir), { recursive: true, withFileTypes: true }).filter(
      (entry) => entry.isFile() && entry.name.endsWith(".ts"),
    );
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      expect(readFileSync(join(file.parentPath, file.name), "utf8"), file.name).not.toMatch(/from "zod|import\("zod/);
    }
  });
});
