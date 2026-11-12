// The sample RP's build, run by `cf build` and `cf deploy` through the Cloudflare Vite plugin, like the IdP's Workers.
// The Worker itself is described in cloudflare.config.ts.
import { cloudflare } from "@cloudflare/vite-plugin";
import { defineConfig } from "vite";

export default defineConfig({
  // Generated types would be an untracked file that drifts from the hand-written Env in src/config.ts.
  plugins: [cloudflare({ types: { generate: false } })],
});
