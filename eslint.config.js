import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import js from "@eslint/js";
import tseslint from "typescript-eslint";

// Every package under packages/ declares its kind in package.json as `"idp": { "kind": ... }`, and the lint targets
// below are derived from those tags (docs/design/packages.md, "パッケージの種類"):
// - standard: a standard's implementation; depends only on standard packages and web-standard APIs (copy-portable);
// - domain: an IdP concern both apps share, or a port; depends only on standard and domain packages;
// - infra: platform code; depends only on domain packages (the ports it implements) and standard packages.
// The kinds each kind may depend on. The apps under apps/ may depend on every kind; no package depends on an app.
const ALLOWED_DEPENDENCY_KINDS = {
  standard: ["standard"],
  domain: ["standard", "domain"],
  infra: ["standard", "domain"],
};

const packages = readdirSync(join(import.meta.dirname, "packages"), { withFileTypes: true })
  // A directory without a manifest is not a package (for example node_modules left behind by another branch).
  .filter((entry) => entry.isDirectory())
  .filter((entry) => existsSync(join(import.meta.dirname, "packages", entry.name, "package.json")))
  .map((entry) => {
    const manifest = JSON.parse(readFileSync(join(import.meta.dirname, "packages", entry.name, "package.json"), "utf8"));
    return { dir: entry.name, name: manifest.name, kind: manifest.idp?.kind, dependencies: Object.keys(manifest.dependencies ?? {}) };
  });

// An untagged package, or a declared dependency that its kind does not allow, fails the whole lint run: the rules
// below cannot be derived for it.
const kindOf = new Map(packages.map((p) => [p.name, p.kind]));
for (const p of packages) {
  if (!Object.hasOwn(ALLOWED_DEPENDENCY_KINDS, p.kind ?? "")) {
    throw new Error(`packages/${p.dir}/package.json needs "idp": { "kind": "standard" | "domain" | "infra" } (docs/design/packages.md)`);
  }
  for (const dependency of p.dependencies.filter((d) => d.startsWith("@idp/"))) {
    if (!ALLOWED_DEPENDENCY_KINDS[p.kind].includes(kindOf.get(dependency))) {
      throw new Error(`${p.name} (${p.kind}) must not depend on ${dependency} (${kindOf.get(dependency) ?? "not a package"}) (docs/design/packages.md)`);
    }
  }
}

function packagesOfKind(kind) {
  return packages.filter((p) => p.kind === kind);
}

function dependenciesOf(dir) {
  return packages.find((p) => p.dir === dir)?.dependencies ?? [];
}

// A package imports another @idp package only when its manifest declares it, so every edge is in a manifest.
function undeclaredImportBan(dependencies, message) {
  return { group: ["@idp/*", "@idp/*/**", ...dependencies.flatMap((name) => [`!${name}`, `!${name}/**`])], message };
}

// A standards package depends only on the standards packages it declares and on the web-standard APIs, so a copy of
// its directory works in another repository (docs/design/packages.md, "依存の禁止の強制").
function standardsImportBan(dependencies) {
  return {
    patterns: [
      {
        ...undeclaredImportBan(dependencies, "A standards package may import only the standards packages it declares (docs/design/packages.md)."),
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

// The IdP Worker must never contain the admin use cases (design principle 1, docs/design/technology.md). They live in
// the admin Worker, so the IdP Worker never imports that app.
const adminWorkerImportBan = {
  patterns: [
    {
      group: ["@idp/admin-worker", "@idp/admin-worker/*", "**/admin-worker", "**/admin-worker/**"],
      message: "The IdP Worker must not depend on the admin Worker (docs/design/technology.md).",
    },
  ],
};

// zod is for the admin API's schemas; keeping it out of the IdP Worker and the domain packages it bundles keeps it out
// of the IdP Worker's bundle (docs/design/technology.md). apps/worker/test/no-zod.test.ts checks the sources as well.
const zodImportBan = {
  patterns: [{ group: ["zod", "zod/*"], message: "Only the admin Worker may import zod (docs/design/technology.md)." }],
};

// A domain package sits below the apps and the platform and imports only the standard and domain packages it
// declares, by package name, so every edge is in a manifest (docs/design/packages.md, "パッケージの種類").
function domainPackageImportBan(dependencies) {
  return {
    patterns: [
      undeclaredImportBan(dependencies, "A domain package may import only the standard and domain packages it declares (docs/design/packages.md)."),
      {
        group: ["node:*", "cloudflare:*", "@cloudflare/*", "hono", "hono/*", "**/cloudflare/src/**"],
        message: "A domain package must not depend on the platform; the apps wire it in (docs/design/packages.md).",
      },
      {
        group: ["../../*", "**/packages/**", "**/apps/**"],
        message: "A domain package imports another package by its name, never by a path (docs/design/packages.md).",
      },
    ],
  };
}

// An infra package implements the domain ports on the platform and imports only the domain and standard packages it
// declares; it never imports an app (docs/design/packages.md, "パッケージの種類").
function infraPackageImportBan(dependencies) {
  return {
    patterns: [
      undeclaredImportBan(dependencies, "An infra package may import only the domain and standard packages it declares (docs/design/packages.md)."),
      { group: ["**/apps/**"], message: "An infra package must not depend on the apps (docs/design/packages.md)." },
    ],
  };
}

// An app's domain layer holds its use cases and rules and stays testable without the framework or the platform: it
// imports only the domain and standards packages and itself (docs/design/packages.md, "アプリのドメインの層").
// `escape` is the relative prefix that leaves src/domain/ from the file's depth, so the HTTP layer and the other app
// are out of reach while the domain's own subdirectories may import each other.
function domainImportBan(escape) {
  return {
    patterns: [
      {
        group: ["hono", "hono/*", "cloudflare:*", "@cloudflare/*", "@idp/cloudflare", "@idp/cloudflare/**", "**/packages/cloudflare/**"],
        message: "The domain layer must not depend on the framework or the platform; the HTTP layer composes them (docs/design/packages.md).",
      },
      {
        group: [`${escape}**`, "@idp/worker", "@idp/worker/*", "@idp/admin-worker", "@idp/admin-worker/*", "**/apps/**"],
        message: "The domain layer must not depend on the app's HTTP layer or on another app (docs/design/packages.md).",
      },
    ],
  };
}

// One block per depth below src/domain/, since a relative import escapes the domain at a different prefix from each.
function domainBlocks(app, extraPatterns) {
  return ["", "*/", "*/*/"].map((subdirs, depth) => ({
    files: [`apps/${app}/src/domain/${subdirs}*.ts`],
    rules: {
      "no-restricted-imports": [
        "error",
        { patterns: [...domainImportBan("../".repeat(depth + 1)).patterns, ...extraPatterns, ...sampleImportBan.patterns] },
      ],
    },
  }));
}

// The samples under examples/ are relying parties, deployed on their own: no IdP code may depend on them.
export const sampleImportBan = {
  patterns: [
    {
      group: ["@idp/rp-sample", "@idp/rp-sample/*", "**/examples/*", "**/examples/**"],
      message: "The IdP and admin code must not depend on the sample relying parties (examples/).",
    },
  ],
};

// The subpaths of @idp/cloudflare import each other only along declared edges, and there are none yet: the D1
// adapter implements the @idp/db port, and the TLS check needs neither the port nor D1.
const cloudflareD1ImportBan = {
  patterns: [
    {
      group: ["@idp/cloudflare", "@idp/cloudflare/*", "@idp/cloudflare/**", "**/workers/**", "hono", "hono/*"],
      message: "@idp/cloudflare/d1 may import only the domain ports and the standards packages (docs/design/packages.md).",
    },
    ...sampleImportBan.patterns,
  ],
};

const cloudflareTlsImportBan = {
  patterns: [
    {
      group: ["@idp/*", "@idp/*/**", "**/d1/**", "**/packages/**", "**/apps/**", "hono", "hono/*"],
      message: "@idp/cloudflare/workers/tls imports neither the domain packages nor the D1 adapter (docs/design/packages.md).",
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
  // The rules of each package come from its kind tag. The domain packages hold the concerns both apps share, and the
  // IdP Worker bundles them, so they are kept free of zod as well.
  ...packagesOfKind("standard").map(({ dir, dependencies }) => ({
    files: [`packages/${dir}/src/**/*.ts`],
    rules: { "no-restricted-imports": ["error", standardsImportBan(dependencies)] },
  })),
  ...packagesOfKind("domain").map(({ dir, dependencies }) => ({
    files: [`packages/${dir}/src/**/*.ts`],
    rules: {
      "no-restricted-imports": [
        "error",
        { patterns: [...domainPackageImportBan(dependencies).patterns, ...zodImportBan.patterns, ...sampleImportBan.patterns] },
      ],
    },
  })),
  ...packagesOfKind("infra").map(({ dir, dependencies }) => ({
    files: [`packages/${dir}/src/**/*.ts`],
    rules: {
      "no-restricted-imports": ["error", { patterns: [...infraPackageImportBan(dependencies).patterns, ...sampleImportBan.patterns] }],
    },
  })),
  {
    files: ["apps/worker/**/*.ts"],
    rules: {
      "no-restricted-imports": [
        "error",
        { patterns: [...adminWorkerImportBan.patterns, ...zodImportBan.patterns, ...sampleImportBan.patterns] },
      ],
    },
  },
  ...domainBlocks("worker", zodImportBan.patterns),
  ...domainBlocks("admin-worker", []),
  // The subpaths of @idp/cloudflare narrow its infra rules further.
  {
    files: ["packages/cloudflare/src/d1/**/*.ts"],
    rules: {
      "no-restricted-imports": [
        "error",
        { patterns: [...infraPackageImportBan(dependenciesOf("cloudflare")).patterns, ...cloudflareD1ImportBan.patterns] },
      ],
    },
  },
  {
    files: ["packages/cloudflare/src/workers/tls/**/*.ts"],
    rules: { "no-restricted-imports": ["error", cloudflareTlsImportBan] },
  },
  {
    files: ["examples/**/*.ts"],
    rules: { "no-restricted-imports": ["error", idpImportBan] },
  },
);
