// The IdP Worker's build, run by `cf build` and `cf deploy` through the Cloudflare Vite plugin
// (docs/design/deployment.md, デプロイの道具): the Worker bundle and the three pages as static assets. The Worker
// itself is described in cloudflare.config.ts. e2e/support/build.ts builds the same inputs for the local tests.
import { basename, join } from "node:path";
import { cloudflare } from "@cloudflare/vite-plugin";
import { defineConfig, type Plugin } from "vite";

const pagesDir = join(import.meta.dirname, "pages");

/**
 * Moves the pages from `pages/<name>.html` to the root of the assets. Vite names an HTML output by its path
 * from the project root, but the plugin needs the project root to be this directory (where cloudflare.config.ts
 * is), and the pages are served at `/signin`, `/enroll`, and `/account`. Their scripts and styles are referenced
 * by absolute paths, so moving the HTML files does not break them.
 *
 * @returns The Vite plugin.
 */
function pagesAtAssetRoot(): Plugin {
  return {
    name: "idp:pages-at-asset-root",
    // After Vite's own HTML plugin, which emits the HTML files in its generateBundle.
    enforce: "post",
    applyToEnvironment: (environment) => environment.name === "client",
    generateBundle(_options, bundle) {
      for (const output of Object.values(bundle)) {
        if (output.type === "asset" && output.fileName.startsWith("pages/") && output.fileName.endsWith(".html")) {
          output.fileName = basename(output.fileName);
        }
      }
    },
  };
}

export default defineConfig({
  publicDir: join(pagesDir, "public"),
  environments: {
    client: {
      build: {
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
    },
  },
  // Generated types would be an untracked file that drifts from the hand-written Env in src/config.ts.
  plugins: [cloudflare({ types: { generate: false } }), pagesAtAssetRoot()],
});
