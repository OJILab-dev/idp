// Builds what the deployment would serve: the IdP Worker and the admin Worker as one ES module each, and the three
// pages as static assets.
// Vite is the build tool cf runs through the Cloudflare Vite plugin (docs/design/technology.md); the plugin itself is
// not declared yet, so the e2e build calls Vite directly with the same inputs instead of going through cf.
import { rm } from "node:fs/promises";
import { join } from "node:path";
import { build } from "vite";

const repoRoot = join(import.meta.dirname, "..", "..");
const workerDir = join(repoRoot, "apps", "worker");
const adminWorkerDir = join(repoRoot, "apps", "admin-worker");
const pagesDir = join(workerDir, "pages");

/** Where the build, the certificates, and the test results go; e2e/dist, which git and ESLint ignore. */
export const OUTPUT_DIR = join(import.meta.dirname, "..", "dist");
/** The static assets: the pages, their bundled scripts, style.css, and _headers. */
export const ASSETS_DIR = join(OUTPUT_DIR, "assets");
/** The Worker bundle's directory; the module is `index.js`. */
export const WORKER_DIR = join(OUTPUT_DIR, "worker");
/** The admin Worker bundle's directory; the module is `index.js`. */
export const ADMIN_WORKER_DIR = join(OUTPUT_DIR, "admin-worker");

/**
 * Bundles one Worker into a single ES module for workerd, with every dependency bundled.
 *
 * @param root The Worker's package directory; its entry is `src/index.ts`.
 * @param outDir Where `index.js` is written.
 */
async function buildWorker(root: string, outDir: string): Promise<void> {
  await build({
    configFile: false,
    logLevel: "warn",
    root,
    publicDir: false,
    resolve: { conditions: ["workerd", "worker", "browser", "import", "default"] },
    ssr: { noExternal: true, target: "webworker" },
    build: {
      outDir,
      emptyOutDir: true,
      ssr: join(root, "src", "index.ts"),
      target: "es2024",
      minify: false,
      // The runtime's own cloudflare: modules are provided by workerd at run time.
      rollupOptions: { external: [/^cloudflare:/], output: { entryFileNames: "index.js", format: "es" } },
    },
  });
}

/**
 * Builds the Worker bundle and the static assets into {@link OUTPUT_DIR}, replacing an earlier build.
 *
 * @throws {Error} Vite fails to resolve or bundle a module.
 */
export async function buildIdp(): Promise<void> {
  await rm(OUTPUT_DIR, { recursive: true, force: true });
  // The pages: each HTML file is an entry, and public/ (style.css, _headers) is copied as is.
  await build({
    configFile: false,
    logLevel: "warn",
    root: pagesDir,
    publicDir: join(pagesDir, "public"),
    build: {
      outDir: ASSETS_DIR,
      emptyOutDir: true,
      // The CSP is default-src 'self': nothing may be inlined as a data: URL.
      assetsInlineLimit: 0,
      rollupOptions: {
        input: {
          signin: join(pagesDir, "signin.html"),
          enroll: join(pagesDir, "enroll.html"),
          account: join(pagesDir, "account.html"),
        },
      },
    },
  });
  await buildWorker(workerDir, WORKER_DIR);
  // The admin Worker runs only for its own gate (scenario 10); the suite seeds through the core, not through it.
  await buildWorker(adminWorkerDir, ADMIN_WORKER_DIR);
}
