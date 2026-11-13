import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts", "contract/test/**/*.test.ts", "packages/*/test/**/*.test.ts", "apps/*/test/**/*.test.ts", "examples/*/test/**/*.test.ts"],
    // Each schema test starts its own workerd process.
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
