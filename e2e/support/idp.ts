// Runs the built IdP Worker on workerd through Miniflare, the runtime cf bundles: the Worker with its static assets,
// the deployment's own asset settings from apps/worker/cloudflare.config.ts, and a local D1 with the migrations.
import { readFile } from "node:fs/promises";
import { Miniflare } from "miniflare";
import type { D1Database } from "@cloudflare/workers-types";
import { workerConfig } from "../../apps/worker/cloudflare.config.js";
import { migrationNames, readMigration, splitStatements } from "../../contract/test/d1.js";
import { generateEd25519Jwk } from "../../packages/core/test/keys.js";
import { ASSETS_DIR, WORKER_DIR } from "./build.js";
import type { TestCertificate } from "./tls.js";

/** The issuer host; Chromium resolves it to the local server, so the RP ID and origin are the production shape. */
export const IDP_HOST = "idp.test";
export const ISSUER = `https://${IDP_HOST}`;

/** A running local IdP. */
export type LocalIdp = {
  /** The loopback port the HTTPS server listens on; the issuer's port 443 is mapped to it. */
  readonly port: number;
  /** The certificate it serves; the RP stand-in trusts only this one. */
  readonly certificate: TestCertificate;
  /** The IdP's D1, the one the Worker reads; the tests seed and inspect it directly. */
  readonly db: D1Database;
  readonly dispose: () => Promise<void>;
};

/**
 * Starts the IdP Worker over HTTPS on a free loopback port, with a fresh signing key and an empty, migrated D1.
 *
 * @param certificate The throwaway certificate for {@link IDP_HOST}.
 * @returns The running IdP.
 * @throws {Error} The build output is missing, or workerd fails to start.
 */
export async function startIdp(certificate: TestCertificate): Promise<LocalIdp> {
  // The deployment's configuration, so the asset handling under test is the one that ships; only what a local run
  // must replace is replaced (the module, the asset directory, the signing key Secret, the D1 placeholder ID).
  const deployed = workerConfig({
    IDP_ISSUER: ISSUER,
    IDP_D1_DATABASE_ID: "00000000-0000-4000-8000-000000000000",
    IDP_RATE_LIMIT_NAMESPACE_ID: "1",
  });
  const signingKey = JSON.stringify(await generateEd25519Jwk());
  const mf = new Miniflare({
    host: "127.0.0.1",
    port: 0,
    https: true,
    httpsKey: certificate.keyPem,
    httpsCert: certificate.certPem,
    workers: [
      {
        config: {
          name: deployed.name,
          compatibilityDate: deployed.compatibilityDate,
          manifest: {
            mainModule: "index.js",
            modules: { "index.js": { type: "esm", contents: await readFile(`${WORKER_DIR}/index.js`, "utf8") } },
          },
          // hasUserWorker defaults to false in Miniflare, which would answer every non-asset path with the asset 404.
          assets: { ...deployed.assets, directory: ASSETS_DIR, hasUserWorker: true },
          env: {
            ...deployed.env,
            DB: { type: "d1", name: "idp-e2e" },
            // The shipped binding with a limit the suite cannot reach: every test signs in from the same loopback
            // address within seconds, which the production limit would rightly refuse. The limit itself is covered
            // by apps/worker/test/edge.test.ts.
            RATE_LIMITER: { type: "rate-limit", namespace: "1", simple: { limit: 100_000, period: 60 } },
            // A Worker Secret in production; a key generated for this run, held only in memory and in workerd.
            SIGNING_KEY_ED25519_CURRENT: { type: "text", value: signingKey },
          },
        },
      },
    ],
  });
  const url = await mf.ready;
  const db = (await mf.getD1Database("DB")) as unknown as D1Database;
  const statements = migrationNames().flatMap((name) => splitStatements(readMigration(name)));
  await db.batch(statements.map((s) => db.prepare(s)));
  return { port: Number(url.port), certificate, db, dispose: () => mf.dispose() };
}
