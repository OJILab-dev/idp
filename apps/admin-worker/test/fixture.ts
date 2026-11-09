// A local D1 with the migrations applied, an environment shaped like the deployed admin Worker's, and requests with
// a fabricated request.cf, so the HTTP layer is tested end to end against the real schema.
import { afterEach, beforeEach, expect } from "vitest";
import { createTestD1, type TestD1 } from "../../../contract/test/d1.js";
import worker, { type Env } from "../src/index.js";

export const ADMIN_HOST = "admin.example.com";
export const ISSUER = "https://idp.example.com";
export const ROOT_FP = "ab".repeat(32);
export const OTHER_FP = "cd".repeat(32);

/** A client certificate that passed the edge mTLS, as Cloudflare reports it to a Worker. */
export function verifiedCert(fingerprint: string = ROOT_FP): Record<string, unknown> {
  return { tlsVersion: "TLSv1.3", tlsClientAuth: { certVerified: "SUCCESS", certRevoked: "0", certFingerprintSHA256: fingerprint } };
}

/** The discovery document the fake IdP Worker returns; `algs` decides whether RS256 is enabled. */
export function discovery(algs: readonly string[]): unknown {
  return { issuer: ISSUER, id_token_signing_alg_values_supported: algs };
}

/** The state of one test. */
export type Fixture = {
  readonly d1: TestD1;
  /** What the fake IdP Worker's internal entrypoint returns from discovery(); it may throw. */
  idpResponse: () => unknown;
  /** The RPC methods the fake IdP Worker received, in order. */
  readonly idpCalls: string[];
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
    const idpCalls: string[] = [];
    const state: Fixture = {
      d1,
      idpResponse: () => discovery(["EdDSA"]),
      idpCalls,
      env: () => env,
    };
    const env: Env = {
      DB: d1.db,
      IDP: {
        discovery: async () => {
          idpCalls.push("discovery");
          return state.idpResponse();
        },
      },
      ISSUER,
      ADMIN_HOST,
      ADMIN_ALLOWLIST: JSON.stringify([
        { sha256: ROOT_FP, name: "root" },
        { sha256: OTHER_FP, name: "other" },
      ]),
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
  /** request.cf; `null` sends a request without it. Defaults to the root admin's verified certificate. */
  readonly cf?: Record<string, unknown> | null;
  /** The URL origin; defaults to the admin host. */
  readonly origin?: string;
  /** Replaces the environment. */
  readonly env?: Env;
};

/**
 * Sends one request to the admin Worker and checks the header every response must carry.
 *
 * @returns The response.
 */
export async function call(f: Fixture, method: string, path: string, options: CallOptions = {}): Promise<Response> {
  const headers = new Headers(options.headers);
  let body: string | undefined = options.rawBody;
  if (options.body !== undefined) {
    body = JSON.stringify(options.body);
    if (!headers.has("content-type")) headers.set("content-type", "application/json");
  }
  const request = new Request(`${options.origin ?? `https://${ADMIN_HOST}`}${path}`, { method, headers, ...(body === undefined ? {} : { body }) });
  const cf = options.cf === undefined ? verifiedCert() : options.cf;
  if (cf !== null) Object.defineProperty(request, "cf", { value: cf });
  const response = await worker.fetch(request as Request<unknown, IncomingRequestCfProperties>, options.env ?? f.env(), {
    waitUntil: () => undefined,
    passThroughOnException: () => undefined,
    props: {},
  } as unknown as ExecutionContext);
  expect(response.headers.get("cache-control")).toBe("no-store");
  return response;
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

/** Asserts an RFC 9457 problem response of a kind and returns its body. */
export async function expectProblem(response: Response, kind: string, status: number): Promise<Record<string, unknown>> {
  expect(response.status).toBe(status);
  expect(response.headers.get("content-type")).toBe("application/problem+json");
  const body = (await response.json()) as Record<string, unknown>;
  expect(body).toMatchObject({ type: `urn:ojilab:idp:problem:${kind}`, status });
  return body;
}
