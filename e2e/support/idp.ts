// Runs the built IdP Worker on workerd through Miniflare, the runtime cf bundles: the Worker with its static assets,
// the deployment's own asset settings from apps/worker/cloudflare.config.ts, and a local D1 with the migrations. The
// admin Worker runs beside it with its own deployment configuration (apps/admin-worker/cloudflare.config.ts) and a
// signing-key allowlist of one test-time P-384 key, so that its RFC 9421 gate runs on a real workerd.
import { readFile } from "node:fs/promises";
import { Miniflare } from "miniflare";
import type { D1Database } from "@cloudflare/workers-types";
import { adminWorkerConfig } from "../../apps/admin-worker/cloudflare.config.js";
import { generateTestAdminKey, signingKeysJson, type TestAdminKey } from "../../apps/admin-worker/test/signer.js";
import { workerConfig } from "../../apps/worker/cloudflare.config.js";
import { migrationNames, readMigration, splitStatements } from "../../contract/test/d1.js";
import { generateEd25519Jwk } from "../../packages/core/test/keys.js";
import { ADMIN_WORKER_DIR, ASSETS_DIR, WORKER_DIR } from "./build.js";
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
  /**
   * Calls the IdP Worker's IdpInternal.discovery() over a real Service Binding, as the admin Worker's IDP binding
   * does: from another Worker in the same workerd, with no request.cf and no client IP.
   */
  readonly internalDiscovery: () => Promise<unknown>;
  /**
   * Sends one request to the IdP Worker through workerd's entry, as the edge hands it over: the static assets
   * settings apply, and the URL's scheme reaches the Worker as given. The browser cannot send plain http here,
   * since the local server speaks only TLS.
   */
  readonly dispatch: (url: string, init?: { readonly method?: string; readonly body?: string; readonly headers?: Record<string, string> }) => Promise<Response>;
  /**
   * Sends one request to the admin Worker as the edge hands it over (no zone rule stands in front of it): TLS 1.3 for
   * https, and the given headers, which a test sets to carry a signature and a CF-Connecting-IP.
   */
  readonly dispatchAdmin: (url: string, init?: AdminRequestInit) => Promise<Response>;
  /** The only allowlisted admin key, `e2e-admin`, generated for this run and held only in memory. */
  readonly adminKey: TestAdminKey;
  readonly dispose: () => Promise<void>;
};

/** A request to the admin Worker. */
export type AdminRequestInit = { readonly method?: string; readonly body?: string; readonly headers?: Headers };

/** The admin Worker's host; only {@link LocalIdp.dispatchAdmin} reaches it. */
export const ADMIN_HOST = "admin.idp.test";

/** The local D1 both Workers bind, as the deployment's two Workers bind one database. */
const E2E_D1_ID = "idp-e2e";

/** The admin Worker's rate limit in the suite: low enough for a test to cross it from one client IP. */
export const ADMIN_TEST_RATE_LIMIT = 5;

/** A Worker whose only job is to call the IdP Worker's internal entrypoint over its IDP binding. */
const BINDING_PROBE = [
  "export default {",
  "  async fetch(_request, env) {",
  "    return Response.json(await env.IDP.discovery());",
  "  },",
  "};",
].join("\n");

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
    IDP_HOSTING_MODE: "custom_domain",
    IDP_ISSUER: ISSUER,
    IDP_D1_DATABASE_ID: "00000000-0000-4000-8000-000000000000",
    IDP_RATE_LIMIT_NAMESPACE_ID: "1",
  });
  const signingKey = JSON.stringify(await generateEd25519Jwk());
  const adminKey = await generateTestAdminKey();
  const admin = adminWorkerConfig({
    IDP_HOSTING_MODE: "custom_domain",
    IDP_ISSUER: ISSUER,
    IDP_ADMIN_HOST: ADMIN_HOST,
    IDP_D1_DATABASE_ID: "00000000-0000-4000-8000-000000000000",
    IDP_ADMIN_RATE_LIMIT_NAMESPACE_ID: "2",
    IDP_ADMIN_SIGNING_KEYS: signingKeysJson([["e2e-admin", adminKey]]),
  });
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
            // Miniflare keys a local database by its id, so the admin Worker's binding below names the same one.
            DB: { type: "d1", id: E2E_D1_ID },
            // The shipped binding with a limit the suite cannot reach: every test signs in from the same loopback
            // address within seconds, which the production limit would rightly refuse. The limit itself is covered
            // by apps/worker/test/edge.test.ts.
            RATE_LIMITER: { type: "rate-limit", namespace: "1", simple: { limit: 100_000, period: 60 } },
            // A Worker Secret in production; a key generated for this run, held only in memory and in workerd.
            SIGNING_KEY_ED25519_CURRENT: { type: "text", value: signingKey },
          },
        },
      },
      {
        config: {
          name: "binding-probe",
          compatibilityDate: deployed.compatibilityDate,
          manifest: { mainModule: "probe.js", modules: { "probe.js": { type: "esm", contents: BINDING_PROBE } } },
          // The same binding shape the admin Worker declares (docs/design/idpctl.md).
          env: { IDP: { type: "worker", worker: deployed.name, exportName: "IdpInternal" } },
        },
      },
      {
        config: {
          name: admin.name,
          compatibilityDate: admin.compatibilityDate,
          manifest: {
            mainModule: "index.js",
            modules: { "index.js": { type: "esm", contents: await readFile(`${ADMIN_WORKER_DIR}/index.js`, "utf8") } },
          },
          // The shipped configuration; only the D1 placeholder and the limit are replaced. The limit is low so that
          // a test can cross it; each test sends from its own client IP, so the counts do not mix.
          env: {
            ...admin.env,
            DB: { type: "d1", id: E2E_D1_ID },
            RATE_LIMITER: { type: "rate-limit", namespace: "2", simple: { limit: ADMIN_TEST_RATE_LIMIT, period: 60 } },
          },
        },
      },
    ],
  });
  const url = await mf.ready;
  async function internalDiscovery(): Promise<unknown> {
    const probe = await mf.getWorker("binding-probe");
    const response = await probe.fetch("http://probe.invalid/");
    if (response.status !== 200) throw new Error(`the binding probe answered ${response.status}`);
    return response.json();
  }
  async function dispatch(target: string, init: { readonly method?: string; readonly body?: string; readonly headers?: Record<string, string> } = {}): Promise<Response> {
    // A plain http request carries no TLS version at the edge; manual, so that a redirect is seen, not followed.
    const response = await mf.dispatchFetch(target, { ...init, redirect: "manual", cf: { tlsVersion: target.startsWith("https:") ? "TLSv1.3" : "" } });
    return response as unknown as Response;
  }
  async function dispatchAdmin(target: string, init: AdminRequestInit = {}): Promise<Response> {
    const worker = await mf.getWorker(admin.name);
    const response = await worker.fetch(target, {
      method: init.method ?? "GET",
      headers: Object.fromEntries(init.headers ?? new Headers()),
      ...(init.body === undefined ? {} : { body: init.body }),
      redirect: "manual",
      cf: { tlsVersion: target.startsWith("https:") ? "TLSv1.3" : "" },
    });
    return response as unknown as Response;
  }
  const db = (await mf.getD1Database("DB")) as unknown as D1Database;
  const statements = migrationNames().flatMap((name) => splitStatements(readMigration(name)));
  await db.batch(statements.map((s) => db.prepare(s)));
  return { port: Number(url.port), certificate, db, internalDiscovery, dispatch, dispatchAdmin, adminKey, dispose: () => mf.dispose() };
}
