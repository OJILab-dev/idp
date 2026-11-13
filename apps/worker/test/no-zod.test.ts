// zod is for the admin API's schemas, which live in the admin Worker. Keeping every import of it out of the IdP
// Worker's sources and the packages under packages/ it bundles keeps it out of the IdP Worker's bundle
// (docs/design/technology.md).
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "..", "..", "..");

const packageSources = readdirSync(join(root, "packages"), { withFileTypes: true })
  .filter((entry) => entry.isDirectory() && existsSync(join(root, "packages", entry.name, "package.json")))
  .map((entry) => `packages/${entry.name}/src`);

describe("the IdP Worker bundles no zod", () => {
  it.each(["apps/worker/src", "apps/worker/pages", ...packageSources])("%s does not import zod", (dir) => {
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
