// The core's OIDC fixture (a local D1 with the migrations, a settable clock, a counting random source) behind the
// Worker's fetch handler, so the HTTP layer is tested end to end against the real schema.
import { afterEach, beforeEach, expect } from "vitest";
import { createFixture, type Fixture as CoreFixture } from "../../../packages/core/test/oidc-fixture.js";
import { generateEd25519Jwk } from "../../../packages/core/test/keys.js";
import { createHandler } from "../src/index.js";
import type { Env } from "../src/config.js";

export { CONFIDENTIAL_SECRET, NOW, PKCE } from "../../../packages/core/test/oidc-fixture.js";

export const ISSUER = "https://idp.example.com";
export const USER = "00000000-0000-4000-8000-000000000001";
export const CREDENTIAL = "Y3JlZGVudGlhbC0wMDAx";
export const CLIENT = "app";
export const REDIRECT_URI = "https://app.example.com/callback";

let ed25519Jwk: Promise<string> | undefined;

/** One Ed25519 private JWK per test file, as the Worker Secret would hold it; generated in memory, never stored. */
export function testSigningKey(): Promise<string> {
  ed25519Jwk ??= generateEd25519Jwk().then((jwk) => JSON.stringify(jwk));
  return ed25519Jwk;
}

/** The state of one test. */
export type Fixture = {
  readonly core: CoreFixture;
  readonly env: Env;
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
    const env: Env = { DB: core.t.db, ISSUER, SIGNING_KEY_ED25519_CURRENT: await testSigningKey() };
    f = { core, env, handler: createHandler({ clock: core.clock, random: core.random }) };
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

/** What a test request carries besides its method and path. */
export type CallOptions = {
  readonly headers?: Readonly<Record<string, string>>;
  /** Cookie name (with its `__Host-` prefix) to value. */
  readonly cookies?: Readonly<Record<string, string>>;
  /** A form body, sent as application/x-www-form-urlencoded. */
  readonly form?: Readonly<Record<string, string>>;
  /** Replaces the environment. */
  readonly env?: Env;
  /** The URL origin; defaults to the issuer. */
  readonly origin?: string;
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
  const request = new Request(`${options.origin ?? ISSUER}${path}`, { method, headers, redirect: "manual", ...(body === undefined ? {} : { body }) });
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
