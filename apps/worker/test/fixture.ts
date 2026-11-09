// The core's OIDC fixture (a local D1 with the migrations, a settable clock, a counting random source) behind the
// Worker's fetch handler, so the HTTP layer is tested end to end against the real schema.
import { afterEach, beforeEach, expect } from "vitest";
import { createFixture, type Fixture as CoreFixture } from "../../../packages/core/test/oidc-fixture.js";
import { generateEd25519Jwk } from "../../../packages/core/test/keys.js";
import { generateCredential, type SoftCredential } from "../../../packages/core/test/webauthn-authenticator.js";
import { base64urlEncode } from "../../../packages/core/src/shared/index.js";
import { createHandler } from "../src/index.js";
import type { Env } from "../src/config.js";

export { CONFIDENTIAL_SECRET, NOW, PKCE } from "../../../packages/core/test/oidc-fixture.js";

export const ISSUER = "https://idp.example.com";
export const USER = "00000000-0000-4000-8000-000000000001";
export const CREDENTIAL = "Y3JlZGVudGlhbC0wMDAx";
export const CLIENT = "app";
export const REDIRECT_URI = "https://app.example.com/callback";
export const VERSION_ID = "00000000-0000-4000-8000-0000000000bb";
/** The RP the software authenticator signs for: the issuer's. */
export const RP = { rpId: "idp.example.com", origin: ISSUER } as const;

let ed25519Jwk: Promise<string> | undefined;

/** One Ed25519 private JWK per test file, as the Worker Secret would hold it; generated in memory, never stored. */
export function testSigningKey(): Promise<string> {
  ed25519Jwk ??= generateEd25519Jwk().then((jwk) => JSON.stringify(jwk));
  return ed25519Jwk;
}

/** The client IP every test request carries unless a test replaces it; Cloudflare's edge sets the header. */
export const CLIENT_IP = "192.0.2.1";

/** A stand-in for the Rate Limiting binding that records each key and answers as the test sets. */
export type FakeRateLimiter = RateLimit & {
  /** The keys counted, in order. */
  readonly keys: string[];
  /** What the next calls answer: allow, deny (over the limit), or throw (the binding failed). */
  outcome: "allow" | "deny" | "throw";
};

/**
 * Builds a fake Rate Limiting binding that allows every request until a test changes its outcome.
 *
 * @returns The fake binding.
 */
export function createFakeRateLimiter(): FakeRateLimiter {
  const fake: FakeRateLimiter = {
    keys: [],
    outcome: "allow",
    limit: async ({ key }) => {
      fake.keys.push(key);
      if (fake.outcome === "throw") throw new Error("rate limiter unavailable");
      return { success: fake.outcome === "allow" };
    },
  };
  return fake;
}

/** A stand-in for the static assets binding: the paths it was asked for, and one known page. */
export type FakeAssets = Fetcher & {
  /** The method and path of each request handed to the binding, in order. */
  readonly requests: string[];
};

/** The only path the fake assets serve; anything else is the asset server's 404. */
export const ASSET_PAGE = "/signin";

/**
 * Builds a fake static assets binding that serves {@link ASSET_PAGE} as HTML and answers 404 for anything else.
 *
 * @returns The fake binding.
 */
export function createFakeAssets(): FakeAssets {
  const requests: string[] = [];
  const fake = {
    requests,
    fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      const { pathname } = new URL(request.url);
      requests.push(`${request.method} ${pathname}`);
      if (pathname !== ASSET_PAGE) return new Response("asset not found", { status: 404 });
      return new Response("<!doctype html><title>sign in</title>", { headers: { "content-type": "text/html; charset=utf-8" } });
    },
    connect: () => {
      throw new Error("the assets binding has no sockets");
    },
  };
  return fake as unknown as FakeAssets;
}

/**
 * Gives a hand-built request what Cloudflare's edge adds to every request: a TLS 1.3 `request.cf` and the
 * CF-Connecting-IP header. The Worker refuses a request without either.
 *
 * @returns The same request.
 */
export function fromEdge(request: Request): Request {
  if (!request.headers.has("cf-connecting-ip")) request.headers.set("cf-connecting-ip", CLIENT_IP);
  Object.defineProperty(request, "cf", { value: { tlsVersion: "TLSv1.3" } });
  return request;
}

/** The state of one test. */
export type Fixture = {
  readonly core: CoreFixture;
  readonly env: Env;
  readonly rateLimiter: FakeRateLimiter;
  readonly assets: FakeAssets;
  readonly handler: ReturnType<typeof createHandler>;
};

/**
 * Registers hooks that give each test a fresh database, environment, and handler.
 *
 * @returns A getter for the current test's fixture.
 */
export function useFixture(): () => Fixture {
  let f: Fixture | undefined;
  beforeEach(async () => {
    const core = await createFixture();
    const rateLimiter = createFakeRateLimiter();
    const assets = createFakeAssets();
    const env: Env = {
      DB: core.t.db,
      ISSUER,
      SIGNING_KEY_ED25519_CURRENT: await testSigningKey(),
      CF_VERSION_METADATA: { id: VERSION_ID, tag: "", timestamp: "" },
      RATE_LIMITER: rateLimiter,
      ASSETS: assets,
    };
    f = { core, env, rateLimiter, assets, handler: createHandler({ clock: core.clock, random: core.random }) };
  });
  afterEach(async () => {
    await f?.core.dispose();
  });
  return () => {
    if (f === undefined) throw new Error("fixture used outside a test");
    return f;
  };
}

/** Seeds an enabled user with a passkey, an enabled confidential client, and a grant between them. */
export async function seedAccess(f: Fixture, client: Partial<Parameters<CoreFixture["addClient"]>[0]> = {}): Promise<void> {
  await f.core.addUser(USER);
  await f.core.addCredential(CREDENTIAL, USER);
  await f.core.addClient({ id: CLIENT, redirectUris: [REDIRECT_URI], ...client });
  await f.core.grant(USER, client.id ?? CLIENT);
}

/**
 * Generates a software passkey for a seeded user (with the user's stored handle) and stores its public key, as an
 * enrollment would have.
 *
 * @returns The credential; the test signs with it.
 */
export async function addSoftPasskey(f: Fixture, userId: string, createdAt: number): Promise<SoftCredential> {
  const [row] = await f.core.query("SELECT user_handle FROM users WHERE id = ?", userId);
  const credential = await generateCredential(-8, { userHandle: row?.["user_handle"] as Uint8Array });
  await f.core.run(
    `INSERT INTO credentials (id, user_id, public_key, sign_count, backup_eligible, backup_state, created_at, created_via)
     VALUES (?, ?, ?, 0, 1, 1, ?, 'enroll')`,
    base64urlEncode(credential.id),
    userId,
    credential.cosePublicKey,
    createdAt,
  );
  return credential;
}

/** What a test request carries besides its method and path. */
export type CallOptions = {
  readonly headers?: Readonly<Record<string, string>>;
  /** Cookie name (with its `__Host-` prefix) to value. */
  readonly cookies?: Readonly<Record<string, string>>;
  /** A form body, sent as application/x-www-form-urlencoded. */
  readonly form?: Readonly<Record<string, string>>;
  /** A body serialised as JSON and sent as application/json. */
  readonly json?: unknown;
  /** Replaces the environment. */
  readonly env?: Env;
  /** The URL origin; defaults to the issuer. */
  readonly origin?: string;
  /** request.cf; `null` sends a request without it. Defaults to a TLS 1.3 connection. */
  readonly cf?: Record<string, unknown> | null;
  /** The CF-Connecting-IP header; `null` omits it. Defaults to {@link CLIENT_IP}. */
  readonly clientIp?: string | null;
};

/**
 * Sends one request to the Worker and checks the headers every response must carry.
 *
 * @returns The response.
 */
export async function call(f: Fixture, method: string, path: string, options: CallOptions = {}): Promise<Response> {
  const headers = new Headers(options.headers);
  if (options.cookies !== undefined) {
    headers.set("cookie", Object.entries(options.cookies).map(([name, value]) => `${name}=${value}`).join("; "));
  }
  let body: string | undefined;
  if (options.form !== undefined) {
    body = new URLSearchParams(options.form).toString();
    headers.set("content-type", "application/x-www-form-urlencoded");
  }
  if (options.json !== undefined) {
    body = JSON.stringify(options.json);
    if (!headers.has("content-type")) headers.set("content-type", "application/json");
  }
  const clientIp = options.clientIp === undefined ? CLIENT_IP : options.clientIp;
  if (clientIp !== null && !headers.has("cf-connecting-ip")) headers.set("cf-connecting-ip", clientIp);
  const request = new Request(`${options.origin ?? ISSUER}${path}`, { method, headers, redirect: "manual", ...(body === undefined ? {} : { body }) });
  const cf = options.cf === undefined ? { tlsVersion: "TLSv1.3" } : options.cf;
  if (cf !== null) Object.defineProperty(request, "cf", { value: cf });
  const response = await f.handler.fetch(request, options.env ?? f.env, {
    waitUntil: () => undefined,
    passThroughOnException: () => undefined,
    props: {},
  } as unknown as ExecutionContext);
  expectSecurityHeaders(response);
  return response;
}

/** Asserts the headers the Worker puts on every response, whatever produced it. */
export function expectSecurityHeaders(response: Response): void {
  expect(response.headers.get("cache-control")).toBe("no-store");
  expect(response.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
  expect(response.headers.get("x-content-type-options")).toBe("nosniff");
  expect(response.headers.get("x-frame-options")).toBe("DENY");
  expect(response.headers.get("referrer-policy")).toBe("no-referrer");
  expect(response.headers.get("strict-transport-security")).toMatch(/^max-age=\d+/);
  // No endpoint opens CORS (docs/design/standards-compliance.md, "例外：CORS に対応しない").
  for (const name of response.headers.keys()) expect(name).not.toMatch(/^access-control-/);
}

/** The cookies a response sets, by name, with their raw attribute strings. */
export function setCookies(response: Response): ReadonlyMap<string, string> {
  const cookies = new Map<string, string>();
  for (const line of response.headers.getSetCookie()) {
    const name = line.split("=", 1)[0];
    if (name !== undefined) cookies.set(name, line);
  }
  return cookies;
}

/** The value part of a Set-Cookie line. */
export function cookieValue(line: string | undefined): string {
  const value = line?.split(";", 1)[0]?.split("=").slice(1).join("=");
  if (value === undefined) throw new Error("no cookie");
  return value;
}

/** The query of a redirect's Location. */
export function locationParams(response: Response): URLSearchParams {
  const location = response.headers.get("location");
  if (location === null) throw new Error("no Location header");
  return new URL(location).searchParams;
}

/** The query of a valid authorization request for the seeded client. */
export function authorizeQuery(overrides: Readonly<Record<string, string | undefined>> = {}, challenge: string): string {
  const params = new URLSearchParams();
  const base: Record<string, string | undefined> = {
    response_type: "code",
    client_id: CLIENT,
    redirect_uri: REDIRECT_URI,
    scope: "openid profile",
    state: "st-1",
    nonce: "n-1",
    code_challenge: challenge,
    code_challenge_method: "S256",
    ...overrides,
  };
  for (const [name, value] of Object.entries(base)) if (value !== undefined) params.set(name, value);
  return params.toString();
}
