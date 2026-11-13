// An in-memory model of the IdP's endpoints, as the IdP's design describes them (docs/design/tokens.md): discovery,
// JWKS with one Ed25519 key, the token endpoint with client_secret_basic and PKCE S256, and /userinfo with a Bearer
// token. It never reaches the network: the sample's outbound fetch is replaced by `fakeIdp.fetch`.
import type { Env } from "../../src/config.js";

export const ISSUER = "https://idp.team-1.workers.dev";
export const ORIGIN = "https://rp-sample.team-1.workers.dev";
export const CLIENT_ID = "rp-sample";
// Fake values in the formats the deploy scripts accept; never real secrets.
export const CLIENT_SECRET = "test-client-secret-not-real-0123456789abcde";
export const SESSION_KEY = btoa(String.fromCharCode(...new Uint8Array(32).map((_, i) => i + 1)));
export const SUB = "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f";
export const KID = "test-kid";

export const ENV: Env = { ISSUER, CLIENT_ID, ORIGIN, CLIENT_SECRET, SESSION_KEY };

export type JsonObject = Readonly<Record<string, unknown>>;

/** What the fake IdP answers; a test overrides one part to model a misbehaving or hostile IdP. */
export type FakeIdpOptions = {
  /** Merged into the discovery document. */
  readonly discovery?: JsonObject;
  /** Merged into the ID token's claims (undefined values remove a claim). */
  readonly idTokenClaims?: JsonObject;
  /** Merged into the ID token's header. */
  readonly idTokenHeader?: JsonObject;
  /** Signs the ID token with another key than the one the JWKS lists. */
  readonly signWithForeignKey?: boolean;
  /** Replaces the /userinfo body. */
  readonly userinfo?: JsonObject;
  /** The token endpoint's status; anything but 200 answers {"error":"invalid_grant"}. */
  readonly tokenStatus?: number;
  /** Merged into the successful token response (undefined values remove a member). */
  readonly tokenResponse?: JsonObject;
  /** Replaces the Content-Type of one endpoint's answer. */
  readonly contentType?: Partial<Record<Endpoint, string>>;
};

export type Endpoint = "discovery" | "jwks" | "token" | "userinfo";

export type RecordedRequest = { readonly method: string; readonly url: string; readonly headers: Headers; readonly body: string };

const ENDPOINTS: Readonly<Record<string, Endpoint>> = {
  "/.well-known/openid-configuration": "discovery",
  "/jwks": "jwks",
  "/token": "token",
  "/userinfo": "userinfo",
};

type PendingCode ={ readonly challenge: string; readonly nonce: string; readonly redirectUri: string };

function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function encodeJson(value: unknown): string {
  return base64url(new TextEncoder().encode(JSON.stringify(value)));
}

async function sha256Base64url(value: string): Promise<string> {
  return base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))));
}

function json(body: unknown, status = 200, contentType = "application/json"): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": contentType } });
}

/**
 * Generates a test Ed25519 key pair.
 *
 * @returns The extractable key pair.
 */
export async function generateEd25519(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
}

function without(claims: Record<string, unknown>): JsonObject {
  return Object.fromEntries(Object.entries(claims).filter(([, value]) => value !== undefined));
}

/** The fake IdP: the sample's fetcher, and the browser's side of /authorize. */
export class FakeIdp {
  readonly requests: RecordedRequest[] = [];
  /** The last ID token the token endpoint issued, as the RP received it. */
  lastIdToken: string | undefined;
  /** Makes discovery fail from now on: a 500, or a failed connection. */
  failDiscovery: "status" | "network" | undefined;
  readonly #codes = new Map<string, PendingCode>();
  readonly #options: FakeIdpOptions;
  readonly #key: CryptoKeyPair;
  readonly #foreignKey: CryptoKeyPair;
  readonly #publicJwk: JsonWebKey;
  #now: () => number;

  private constructor(options: FakeIdpOptions, key: CryptoKeyPair, foreignKey: CryptoKeyPair, publicJwk: JsonWebKey, now: () => number) {
    this.#options = options;
    this.#key = key;
    this.#foreignKey = foreignKey;
    this.#publicJwk = publicJwk;
    this.#now = now;
  }

  /**
   * Creates a fake IdP with a fresh Ed25519 key.
   *
   * @param options The overrides of a misbehaving IdP.
   * @param now The clock in seconds, shared with the sample under test.
   * @returns The fake IdP.
   */
  static async create(options: FakeIdpOptions = {}, now: () => number = () => Math.floor(Date.now() / 1000)): Promise<FakeIdp> {
    const key = await generateEd25519();
    const publicJwk = (await crypto.subtle.exportKey("jwk", key.publicKey)) as JsonWebKey;
    return new FakeIdp(options, key, await generateEd25519(), publicJwk, now);
  }

  /** The discovery document of the live IdP (2026-11-13), with the test's overrides. */
  discovery(): JsonObject {
    return {
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      userinfo_endpoint: `${ISSUER}/userinfo`,
      jwks_uri: `${ISSUER}/jwks`,
      end_session_endpoint: `${ISSUER}/end_session`,
      response_types_supported: ["code"],
      response_modes_supported: ["query"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["client_secret_basic", "none"],
      authorization_response_iss_parameter_supported: true,
      scopes_supported: ["openid", "profile"],
      id_token_signing_alg_values_supported: ["Ed25519"],
      subject_types_supported: ["public"],
      ...this.#options.discovery,
    };
  }

  /**
   * Signs a JWT the way the IdP does: header {typ, alg, kid}, Ed25519 over `header.payload`.
   *
   * @param claims The payload.
   * @param header Overrides of the header.
   * @param foreign Signs with a key the JWKS does not list.
   * @returns The compact JWS.
   */
  async sign(claims: JsonObject, header: JsonObject = {}, foreign = false): Promise<string> {
    const input = `${encodeJson({ typ: "JWT", alg: "Ed25519", kid: KID, ...header })}.${encodeJson(claims)}`;
    const key = foreign ? this.#foreignKey.privateKey : this.#key.privateKey;
    const signature = await crypto.subtle.sign({ name: "Ed25519" }, key, new TextEncoder().encode(input));
    return `${input}.${base64url(new Uint8Array(signature))}`;
  }

  /**
   * The ID token claims the IdP issues for this nonce (tokens.md, クレームの一覧), with the test's overrides.
   *
   * @param nonce The nonce of the authorization request.
   * @returns The claims.
   */
  idTokenClaims(nonce: string): JsonObject {
    const now = this.#now();
    return without({ iss: ISSUER, sub: SUB, aud: CLIENT_ID, exp: now + 300, iat: now, auth_time: now - 5, nonce, name: "Alice", ...this.#options.idTokenClaims });
  }

  /**
   * Plays the browser at /authorize: checks the request the sample built and returns the redirect back to it.
   *
   * @param authorizationUrl The Location the sample's /login answered.
   * @returns The callback URL with code, state, and iss (RFC 9207).
   */
  authorize(authorizationUrl: string): URL {
    const url = new URL(authorizationUrl);
    const params = url.searchParams;
    const challenge = params.get("code_challenge");
    const nonce = params.get("nonce");
    const redirectUri = params.get("redirect_uri");
    const state = params.get("state");
    if (challenge === null || nonce === null || redirectUri === null || state === null) throw new Error("incomplete authorization request");
    const code = `code-${this.#codes.size + 1}`;
    this.#codes.set(code, { challenge, nonce, redirectUri });
    const callback = new URL(redirectUri);
    callback.searchParams.set("code", code);
    callback.searchParams.set("state", state);
    callback.searchParams.set("iss", ISSUER);
    return callback;
  }

  /** The sample's outbound fetch. */
  readonly fetch = async (request: Request): Promise<Response> => {
    const body = await request.text();
    this.requests.push({ method: request.method, url: request.url, headers: request.headers, body });
    const url = new URL(request.url);
    if (url.origin !== ISSUER) return new Response("unexpected host", { status: 599 });
    if (this.failDiscovery !== undefined && url.pathname === "/.well-known/openid-configuration") {
      if (this.failDiscovery === "network") throw new TypeError("connection refused");
      return json({ error: "server_error" }, 500);
    }
    const response = await this.#answer(`${request.method} ${url.pathname}`, request.headers, body);
    const endpoint = ENDPOINTS[url.pathname];
    const contentType = endpoint === undefined ? undefined : this.#options.contentType?.[endpoint];
    if (contentType !== undefined) response.headers.set("content-type", contentType);
    return response;
  };

  async #answer(route: string, headers: Headers, body: string): Promise<Response> {
    switch (route) {
      case "GET /.well-known/openid-configuration":
        return json(this.discovery());
      case "GET /jwks":
        return json({ keys: [{ ...this.#publicJwk, kid: KID, alg: "Ed25519", use: "sig" }] });
      case "POST /token":
        return this.#token(headers, body);
      case "GET /userinfo":
        return this.#userinfo(headers);
      default:
        return new Response("not found", { status: 404 });
    }
  }

  async #token(headers: Headers, body: string): Promise<Response> {
    if (this.#options.tokenStatus !== undefined && this.#options.tokenStatus !== 200) {
      return json({ error: "invalid_grant" }, this.#options.tokenStatus);
    }
    const expected = `Basic ${btoa(`${encodeURIComponent(CLIENT_ID)}:${encodeURIComponent(CLIENT_SECRET)}`)}`;
    if (headers.get("authorization") !== expected) return json({ error: "invalid_client" }, 401);
    if (headers.get("content-type") !== "application/x-www-form-urlencoded") return json({ error: "invalid_request" }, 400);
    const params = new URLSearchParams(body);
    const code = params.get("code") ?? "";
    const pending = this.#codes.get(code);
    this.#codes.delete(code);
    if (
      pending === undefined ||
      params.get("grant_type") !== "authorization_code" ||
      params.get("redirect_uri") !== pending.redirectUri ||
      (await sha256Base64url(params.get("code_verifier") ?? "")) !== pending.challenge
    ) {
      return json({ error: "invalid_grant" }, 400);
    }
    const idToken = await this.sign(this.idTokenClaims(pending.nonce), this.#options.idTokenHeader, this.#options.signWithForeignKey);
    this.lastIdToken = idToken;
    return json(
      without({ access_token: "access-token-1", token_type: "Bearer", expires_in: 300, id_token: idToken, scope: "openid profile", ...this.#options.tokenResponse }),
    );
  }

  #userinfo(headers: Headers): Response {
    if (headers.get("authorization") !== "Bearer access-token-1") return json({ error: "invalid_token" }, 401);
    return json(this.#options.userinfo ?? { sub: SUB, name: "Alice" });
  }
}
