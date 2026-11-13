import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import js from "@eslint/js";
import tseslint from "typescript-eslint";

// The packages under packages/ that hold IdP or platform code. Every other directory there is a standards package
// (docs/design/packages.md), so a new package gets the strict rules below unless it is listed here.
const IDP_PACKAGES = new Set(["core", "cloudflare"]);

const standardsPackages = readdirSync(join(import.meta.dirname, "packages"), { withFileTypes: true })
  // A directory without a manifest is not a package (for example node_modules left behind by another branch).
  .filter((entry) => entry.isDirectory() && !IDP_PACKAGES.has(entry.name))
  .filter((entry) => existsSync(join(import.meta.dirname, "packages", entry.name, "package.json")))
  .map((entry) => {
    const manifest = JSON.parse(readFileSync(join(import.meta.dirname, "packages", entry.name, "package.json"), "utf8"));
    return { dir: entry.name, dependencies: Object.keys(manifest.dependencies ?? {}) };
  });

// A standards package depends only on the standards packages it declares and on the web-standard APIs, so a copy of
// its directory works in another repository (docs/design/packages.md, "依存の禁止の強制").
function standardsImportBan(dependencies) {
  return {
    patterns: [
      {
        group: ["@idp/*", "@idp/*/**", ...dependencies.map((name) => `!${name}`)],
        message: "A standards package may import only the standards packages it declares (docs/design/packages.md).",
      },
      {
        group: ["node:*", "cloudflare:*", "@cloudflare/*", "zod", "zod/*", "hono", "hono/*"],
        message: "A standards package uses web-standard APIs only (docs/design/packages.md).",
      },
      {
        group: ["../../*", "**/packages/**", "**/apps/**", ...sampleImportBan.patterns[0].group],
        message: "A standards package must not reach outside its own directory (docs/design/packages.md).",
      },
    ],
  };
}

// The IdP Worker must never contain admin use cases (design principle 1, docs/design/technology.md).
// User-facing code may import only the user-facing modules and the concern directories of the core.
export const adminImportBan = {
  patterns: [
    {
      group: [
        "@idp/core/admin",
        "@idp/core/admin/*",
        "**/core/src/admin",
        "**/core/src/admin/*",
        "**/admin/*",
      ],
      message: "User-facing code must not depend on the admin modules (docs/design/technology.md).",
    },
  ],
};

// The concern directories of the core are below the user-facing use cases, so they never import them.
const userImportBan = {
  patterns: [
    {
      group: ["@idp/core/user", "@idp/core/user/*", "**/core/src/user", "**/core/src/user/*", "**/user/*", "../user"],
      message: "A concern directory of the core must not depend on the user-facing use cases (docs/design/packages.md).",
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

// Cloudflare-specific code lives in @idp/cloudflare, which the apps wire to the core; the core never reaches for it,
// so the core and the standards packages stay free of any platform (docs/design/packages.md, "@idp/cloudflare の規則").
const cloudflareImportBan = {
  patterns: [
    {
      group: ["@idp/cloudflare", "@idp/cloudflare/*", "@idp/cloudflare/**", "**/cloudflare/src/**"],
      message: "The core must not depend on @idp/cloudflare; the apps wire the two together (docs/design/packages.md).",
    },
  ],
};

// The subpaths of @idp/cloudflare import each other only along declared edges, and there are none yet: the D1
// adapter implements the core's ports, and the TLS check needs neither the core nor D1.
const cloudflareD1ImportBan = {
  patterns: [
    {
      group: ["@idp/cloudflare", "@idp/cloudflare/*", "@idp/cloudflare/**", "**/workers/**", "hono", "hono/*"],
      message: "@idp/cloudflare/d1 may import only @idp/core and the standards packages (docs/design/packages.md).",
    },
    ...sampleImportBan.patterns,
  ],
};

const cloudflareTlsImportBan = {
  patterns: [
    {
      group: ["@idp/*", "@idp/*/**", "**/d1/**", "**/packages/**", "**/apps/**", "hono", "hono/*"],
      message: "@idp/cloudflare/workers/tls imports neither the core nor the D1 adapter (docs/design/packages.md).",
    },
    ...sampleImportBan.patterns,
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
  // A later block replaces the rule's options for the files it matches, so each block repeats the bans it keeps.
  {
    files: ["packages/core/src/**/*.ts"],
    rules: { "no-restricted-imports": ["error", { patterns: [...cloudflareImportBan.patterns, ...sampleImportBan.patterns] }] },
  },
  {
    files: ["apps/worker/**/*.ts"],
    rules: { "no-restricted-imports": ["error", { patterns: [...adminImportBan.patterns, ...sampleImportBan.patterns] }] },
  },
  // Every directory of the core except admin/ is user-facing: the IdP Worker bundles it.
  {
    files: ["packages/core/src/**/*.ts"],
    ignores: ["packages/core/src/admin/**"],
    rules: {
      "no-restricted-imports": [
        "error",
        { patterns: [...adminImportBan.patterns, ...cloudflareImportBan.patterns, ...sampleImportBan.patterns] },
      ],
    },
  },
  // The concern directories (db/, identifiers/, audit/, ...) sit below both use-case layers and import neither.
  {
    files: ["packages/core/src/**/*.ts"],
    ignores: ["packages/core/src/admin/**", "packages/core/src/user/**"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            ...adminImportBan.patterns,
            ...userImportBan.patterns,
            ...cloudflareImportBan.patterns,
            ...sampleImportBan.patterns,
          ],
        },
      ],
    },
  },
  {
    files: ["packages/cloudflare/src/d1/**/*.ts"],
    rules: { "no-restricted-imports": ["error", cloudflareD1ImportBan] },
  },
  {
    files: ["packages/cloudflare/src/workers/tls/**/*.ts"],
    rules: { "no-restricted-imports": ["error", cloudflareTlsImportBan] },
  },
  ...standardsPackages.map(({ dir, dependencies }) => ({
    files: [`packages/${dir}/src/**/*.ts`],
    rules: { "no-restricted-imports": ["error", standardsImportBan(dependencies)] },
  })),
  {
    files: ["examples/**/*.ts"],
    rules: { "no-restricted-imports": ["error", idpImportBan] },
  },
);
