import js from "@eslint/js";
import tseslint from "typescript-eslint";

// The IdP Worker must never contain admin use cases (design principle 1, docs/design/technology.md).
// User-facing code may import only the user-facing and shared modules of the core.
export const adminImportBan = {
  patterns: [
    {
      group: ["@idp/core/admin", "@idp/core/admin/*", "**/core/src/admin", "**/core/src/admin/*", "**/admin/*"],
      message: "User-facing code must not depend on the admin modules (docs/design/technology.md).",
    },
  ],
};

export default tseslint.config(
  { ignores: ["**/node_modules/**", "**/dist/**", "**/.cloudflare/**"] },
  js.configs.recommended,
  ...tseslint.configs.strict,
  {
    rules: {
      // Named functions are declarations; inline callbacks may stay arrows.
      "func-style": ["error", "declaration"],
      // Handler signatures are fixed by the runtime; unused leading parameters are marked with `_`.
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
    },
  },
  {
    files: ["apps/worker/**/*.ts", "packages/core/src/user/**/*.ts", "packages/core/src/shared/**/*.ts"],
    rules: { "no-restricted-imports": ["error", adminImportBan] },
  },
);
