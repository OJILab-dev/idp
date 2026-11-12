import js from "@eslint/js";
import tseslint from "typescript-eslint";

// The IdP Worker must never contain admin use cases (design principle 1, docs/design/technology.md).
// User-facing code may import only the user-facing and shared modules of the core.
export const adminImportBan = {
  patterns: [
    {
      group: [
        "@idp/core/admin",
        "@idp/core/admin/*",
        "**/core/src/admin",
        "**/core/src/admin/*",
        "**/admin/*",
        // The D1 adapters of the admin-only ports import the admin modules.
        "@idp/d1-adapter/admin",
        "**/d1-adapter/src/admin",
        "**/d1-adapter/src/admin.js",
      ],
      message: "User-facing code must not depend on the admin modules (docs/design/technology.md).",
    },
  ],
};

// The samples under examples/ are relying parties, deployed on their own: no IdP code may depend on them.
export const sampleImportBan = {
  patterns: [
    {
      group: ["@idp/rp-sample", "@idp/rp-sample/*", "**/examples/*", "**/examples/**"],
      message: "The IdP and admin code must not depend on the sample relying parties (examples/).",
    },
  ],
};

// A sample is a reference for RPs outside this repository, which cannot import the IdP's packages either.
const idpImportBan = {
  patterns: [
    {
      group: ["@idp/*", "**/packages/*", "**/packages/**", "**/apps/*", "**/apps/**"],
      message: "A sample relying party talks to the IdP over HTTP only; it must not import the IdP's code.",
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
    files: ["apps/**/*.ts", "packages/**/*.ts"],
    rules: { "no-restricted-imports": ["error", sampleImportBan] },
  },
  // A later block replaces the rule's options for the files it matches, so the user-facing code repeats the sample ban.
  {
    files: ["apps/worker/**/*.ts", "packages/core/src/user/**/*.ts", "packages/core/src/shared/**/*.ts"],
    rules: { "no-restricted-imports": ["error", { patterns: [...adminImportBan.patterns, ...sampleImportBan.patterns] }] },
  },
  {
    files: ["examples/**/*.ts"],
    rules: { "no-restricted-imports": ["error", idpImportBan] },
  },
);
