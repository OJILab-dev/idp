// The sample bundled the way cf builds it and run on workerd (Miniflare, offline), with the bindings of
// cloudflare.config.ts. The other tests run on Node; this one shows that the runtime's WebCrypto (Ed25519,
// AES-GCM) and fetch behave the same. Outbound fetches go to the fake IdP, never to the network.
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Miniflare, type Response as MiniflareResponse } from "miniflare";
import { build } from "vite";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { workerConfig } from "../cloudflare.config.js";
import { CLIENT_ID, CLIENT_SECRET, FakeIdp, ISSUER, ORIGIN, SESSION_KEY, SUB } from "./support/fake-idp.js";

const root = join(import.meta.dirname, "..");
let outDir: string;
let mf: Miniflare;
let idp: FakeIdp;

function cookieFrom(response: Response, name: string): string {
  const line = response.headers.getSetCookie().find((cookie) => cookie.startsWith(`${name}=`)) ?? "";
  return line.slice(name.length + 1).split(";")[0] ?? "";
}

async function dispatch(url: string, cookie?: string): Promise<Response> {
  const response = await mf.dispatchFetch(url, { redirect: "manual", headers: cookie === undefined ? {} : { cookie } });
  return response as unknown as Response;
}

beforeAll(async () => {
  outDir = await mkdtemp(join(tmpdir(), "rp-sample-"));
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
      rollupOptions: { output: { entryFileNames: "index.js", format: "es" } },
    },
  });
  idp = await FakeIdp.create();
  const deployed = workerConfig({ RP_SAMPLE_ISSUER: ISSUER, RP_SAMPLE_CLIENT_ID: CLIENT_ID, RP_SAMPLE_ORIGIN: ORIGIN });
  mf = new Miniflare({
    workers: [
      {
        config: {
          name: deployed.name,
          compatibilityDate: deployed.compatibilityDate ?? "2026-10-01",
          manifest: { mainModule: "index.js", modules: { "index.js": { type: "esm", contents: await readFile(join(outDir, "index.js"), "utf8") } } },
          env: {
            ...deployed.env,
            // Worker Secrets in production; fake values here.
            CLIENT_SECRET: { type: "text", value: CLIENT_SECRET },
            SESSION_KEY: { type: "text", value: SESSION_KEY },
          },
        },
        // Node's fetch types and Miniflare's are both undici's, declared twice; the objects are the same at run time.
        dev: {
          outboundService: {
            type: "fetcher",
            handler: async (request) => (await idp.fetch(request as unknown as Request)) as unknown as MiniflareResponse,
          },
        },
      },
    ],
  });
  await mf.ready;
}, 60_000);

afterAll(async () => {
  await mf.dispose();
  await rm(outDir, { recursive: true, force: true });
});

describe("the sample on workerd", () => {
  it("signs in end to end and shows the account", async () => {
    const login = await dispatch(`${ORIGIN}/login`);
    expect(login.status).toBe(302);
    const flow = cookieFrom(login, "__Host-rp-sample-flow");
    const callback = idp.authorize(login.headers.get("location") ?? "");

    const signedIn = await dispatch(callback.href, `__Host-rp-sample-flow=${flow}`);
    expect(signedIn.status).toBe(303);
    const session = cookieFrom(signedIn, "__Host-rp-sample-session");
    expect(session).not.toBe("");

    const account = await dispatch(`${ORIGIN}/`, `__Host-rp-sample-session=${session}`);
    const html = await account.text();
    expect(html).toContain(SUB);
    expect(html).toContain('action="/logout"');
    for (const request of idp.requests) expect(request.headers.get("user-agent")).toMatch(/^idp-rp-sample\//);

    // RP-Initiated Logout: the hashed auto-submit page, then the return with the state.
    const logout = (await mf.dispatchFetch(`${ORIGIN}/logout`, {
      method: "POST",
      redirect: "manual",
      headers: { cookie: `__Host-rp-sample-session=${session}`, "sec-fetch-site": "same-origin" },
    })) as unknown as Response;
    expect(logout.status).toBe(200);
    expect(logout.headers.get("content-security-policy")).toMatch(/script-src 'sha256-[A-Za-z0-9+/]{43}='/);
    const page = await logout.text();
    expect(page).toContain(`action="${ISSUER}/end_session"`);
    const state = /name="state" value="([^"]*)"/.exec(page)?.[1] ?? "";
    const pending = cookieFrom(logout, "__Host-rp-sample-logout");
    const back = await dispatch(`${ORIGIN}/signed-out?state=${state}`, `__Host-rp-sample-logout=${pending}`);
    expect(back.status).toBe(200);
  });
});
