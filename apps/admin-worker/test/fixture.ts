// A local D1 with the migrations applied, an environment shaped like the deployed admin Worker's, and requests signed
// with RFC 9421 by test-time P-384 keys, with a fabricated request.cf and client IP, so the HTTP layer is tested end
// to end against the real schema and the real gate.
import { afterEach, beforeAll, beforeEach, expect } from "vitest";
import { createTestD1, type TestD1 } from "../../../contract/test/d1.js";
import worker, { type Env } from "../src/index.js";
import { generateTestAdminKey, signAdminRequest, signingKeysJson, type SignOptions, type TestAdminKey } from "./signer.js";

export const ADMIN_HOST = "admin.example.com";
export const ISSUER = "https://idp.example.com";
export const CLIENT_IP = "192.0.2.10";

/** The test keys: two allowlisted admins and one key that is not on the allowlist. */
export type TestKeys = { readonly root: TestAdminKey; readonly other: TestAdminKey; readonly stranger: TestAdminKey };

let testKeys: TestKeys | undefined;

beforeAll(async () => {
  testKeys = { root: await generateTestAdminKey(), other: await generateTestAdminKey(), stranger: await generateTestAdminKey() };
});

/**
 * The keys of the current test file, generated once per file.
 *
 * @returns The keys.
 */
export function keys(): TestKeys {
  if (testKeys === undefined) throw new Error("keys used before beforeAll");
  return testKeys;
}

/** The state of one test. */
export type Fixture = {
  readonly d1: TestD1;
  /** The keys the fake Rate Limiting binding was called with, in order. */
  readonly limiterKeys: string[];
  /** What the fake Rate Limiting binding answers; it may throw. */
  limiterAnswer: () => RateLimitOutcome;
  readonly env: () => Env;
};

/**
 * Registers hooks that give each test a fresh database and environment.
 *
 * @returns A getter for the current test's fixture.
 */
export function useFixture(): () => Fixture {
  let f: Fixture | undefined;
  beforeEach(async () => {
    const d1 = await createTestD1();
    const limiterKeys: string[] = [];
    const state: Fixture = {
      d1,
      limiterKeys,
      limiterAnswer: () => ({ success: true }),
      env: () => env,
    };
    const env: Env = {
      DB: d1.db,
      ISSUER,
      ADMIN_HOST,
      HOSTING_MODE: "custom_domain",
      ADMIN_SIGNING_KEYS: signingKeysJson([
        ["root", keys().root],
        ["other", keys().other],
      ]),
      RATE_LIMITER: {
        limit: async ({ key }) => {
          limiterKeys.push(key);
          return state.limiterAnswer();
        },
      },
      CF_VERSION_METADATA: { id: "00000000-0000-4000-8000-0000000000aa", tag: "", timestamp: "" },
    };
    f = state;
  });
  afterEach(async () => {
    await f?.d1.dispose();
  });
  return () => {
    if (f === undefined) throw new Error("fixture used outside a test");
    return f;
  };
}

/** What a test request carries besides its method and path. */
export type CallOptions = {
  readonly body?: unknown;
  /** A raw body, sent as is. */
  readonly rawBody?: string;
  readonly headers?: Readonly<Record<string, string>>;
  /** request.cf; `null` sends a request without it. Defaults to TLS 1.3. */
  readonly cf?: Record<string, unknown> | null;
  /** The URL origin; defaults to the admin host. */
  readonly origin?: string;
  /** Replaces the environment. */
  readonly env?: Env;
  /** The signing key; `null` sends an unsigned request. Defaults to the root admin's key. */
  readonly signer?: TestAdminKey | null;
  /** Overrides of the signature (created, nonce, claimed keyid). */
  readonly sign?: SignOptions;
  /** Changes the signed request before it is sent, to tamper with what the signature covers. */
  readonly tamper?: (signed: { url: string; method: string; headers: Headers; body: string | undefined }) => void;
  /** The CF-Connecting-IP header; `null` sends none. */
  readonly clientIp?: string | null;
};

/** A request ready to send: the result of {@link buildRequest}. */
export type Prepared = { readonly url: string; readonly method: string; readonly headers: Headers; readonly body: string | undefined };

/**
 * Builds and signs one request as idpctl would, without sending it, so that a test can send the same bytes twice.
 *
 * @returns The request parts.
 */
export async function buildRequest(method: string, path: string, options: CallOptions = {}): Promise<Prepared> {
  let headers = new Headers(options.headers);
  let body: string | undefined = options.rawBody;
  if (options.body !== undefined) {
    body = JSON.stringify(options.body);
    if (!headers.has("content-type")) headers.set("content-type", "application/json");
  }
  const url = `${options.origin ?? `https://${ADMIN_HOST}`}${path}`;
  const signer = options.signer === undefined ? keys().root : options.signer;
  if (signer !== null) {
    headers = await signAdminRequest({ method, url, headers, body: new TextEncoder().encode(body ?? "") }, signer, options.sign);
  }
  const clientIp = options.clientIp === undefined ? CLIENT_IP : options.clientIp;
  if (clientIp !== null) headers.set("cf-connecting-ip", clientIp);
  const prepared = { url, method, headers, body };
  options.tamper?.(prepared);
  return prepared;
}

/**
 * Sends a prepared request to the admin Worker and checks the header every response must carry.
 *
 * @returns The response.
 */
export async function send(f: Fixture, prepared: Prepared, options: Pick<CallOptions, "cf" | "env"> = {}): Promise<Response> {
  const request = new Request(prepared.url, {
    method: prepared.method,
    headers: prepared.headers,
    ...(prepared.body === undefined ? {} : { body: prepared.body }),
  });
  const cf = options.cf === undefined ? { tlsVersion: "TLSv1.3" } : options.cf;
  if (cf !== null) Object.defineProperty(request, "cf", { value: cf });
  const response = await worker.fetch(request as Request<unknown, IncomingRequestCfProperties>, options.env ?? f.env(), {
    waitUntil: () => undefined,
    passThroughOnException: () => undefined,
    props: {},
  } as unknown as ExecutionContext);
  expect(response.headers.get("cache-control")).toBe("no-store");
  return response;
}

/**
 * Signs and sends one request to the admin Worker.
 *
 * @returns The response.
 */
export async function call(f: Fixture, method: string, path: string, options: CallOptions = {}): Promise<Response> {
  return send(f, await buildRequest(method, path, options), options);
}

/** A fresh Idempotency-Key in the contract's format (32 random bytes, unpadded base64url). */
export function newKey(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The headers of an idempotent POST. */
export function idempotent(key: string = newKey()): Readonly<Record<string, string>> {
  return { "idempotency-key": key };
}

/** The audit rows, oldest first. */
export async function auditRows(f: Fixture): Promise<readonly Record<string, unknown>[]> {
  const { results } = await f.d1.db.prepare("SELECT * FROM audit_log ORDER BY id").all();
  return results;
}

/** The number of stored nonces. */
export async function nonceCount(f: Fixture): Promise<number> {
  return (await f.d1.db.prepare("SELECT COUNT(*) AS n FROM admin_request_nonces").first<number>("n")) ?? 0;
}

/** Asserts an RFC 9457 problem response of a kind and returns its body. */
export async function expectProblem(response: Response, kind: string, status: number): Promise<Record<string, unknown>> {
  expect(response.status).toBe(status);
  expect(response.headers.get("content-type")).toBe("application/problem+json");
  const body = (await response.json()) as Record<string, unknown>;
  expect(body).toMatchObject({ type: `urn:ojilab:idp:problem:${kind}`, status });
  return body;
}
