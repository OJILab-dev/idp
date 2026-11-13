import { join } from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    // The runtime module of workerd; Node lacks it, so the tests get the base class only (see the stub's comment).
    alias: { "cloudflare:workers": join(import.meta.dirname, "apps", "worker", "test", "support", "cloudflare-workers.ts") },
  },
  test: {
    include: ["test/**/*.test.ts", "contract/test/**/*.test.ts", "packages/*/test/**/*.test.ts", "apps/*/test/**/*.test.ts", "examples/*/test/**/*.test.ts"],
    // Each schema test starts its own workerd process.
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
