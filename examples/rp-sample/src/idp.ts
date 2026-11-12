// The RP's back channel to the IdP: discovery, JWKS, the token endpoint, and /userinfo. The browser never sees these
// calls. Discovery and the JWKS are cached in the isolate for a few minutes, so a login costs the IdP's per-IP rate
// limit as few requests as possible (docs/design/free-tier.md); an unknown kid refreshes the JWKS once (rotation).
import type { Config } from "./config.js";
import { parseJsonObject } from "./encoding.js";
import { IdpError } from "./errors.js";
import { IdTokenError, verifyIdToken, type IdTokenClaims } from "./id-token.js";

/**
 * Every request to the IdP names this client. workers.dev's Browser Integrity Check refuses library-default
 * User-Agents before the IdP Worker sees the request (docs/deployment/bootstrap.md; hosting-modes.md 5.2).
 */
export const USER_AGENT = "idp-rp-sample/1.0";
const CACHE_SECONDS = 300;
const TIMEOUT_MS = 10_000;

/** The outbound fetch; the Worker's global fetch in production, the fake IdP in tests. */
export type Fetcher = (request: Request) => Promise<Response>;

/** The endpoints this RP uses, from a discovery document whose issuer matched. */
export type Discovery = {
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly userinfoEndpoint: string;
  readonly jwksUri: string;
};

/** The result of a completed login: the checked ID token claims and the /userinfo response for the same sub. */
export type LoginResult = {
  readonly idToken: IdTokenClaims;
  readonly userinfo: Readonly<Record<string, unknown>>;
};

/** The parameters of the token request that this login's flow cookie kept. */
export type CodeExchange = {
  readonly code: string;
  readonly verifier: string;
  readonly nonce: string;
};

/** The IdP as this RP sees it. One instance per isolate; it caches discovery and the JWKS. */
export interface IdpClient {
  /**
   * Returns the IdP's endpoints from discovery (cached for a few minutes).
   *
   * @throws {IdpError} Discovery fails, names another issuer (OIDC Discovery 1.0 §4.3), lacks an endpoint, or does
   *   not support what this RP requires: code + S256, client_secret_basic, Ed25519 ID tokens, and the iss response
   *   parameter.
   */
  discover(): Promise<Discovery>;

  /**
   * Redeems an authorization code as a confidential client (client_secret_basic), validates the ID token, and reads
   * /userinfo with the access token. Not idempotent: the IdP accepts a code once.
   *
   * @throws {IdpError} The token endpoint refuses, a response is malformed, the JWKS cannot be read, or /userinfo
   *   fails or names another sub (OIDC Core 1.0 §5.3.2).
   * @throws {IdTokenError} The ID token does not validate (signature, iss, aud, exp, iat, or nonce).
   */
  redeem(exchange: CodeExchange): Promise<LoginResult>;
}

type Cached<T> = { readonly value: T; readonly expiresAt: number };

function httpsUrl(value: unknown, name: string): string {
  if (typeof value !== "string" || !URL.canParse(value) || new URL(value).protocol !== "https:") {
    throw new IdpError(`discovery: ${name} is not an https URL`);
  }
  return value;
}

function includes(value: unknown, item: string): boolean {
  return Array.isArray(value) && value.includes(item);
}

// RFC 6749 §5.2: error codes are limited to %x20-21 / %x23-5B / %x5D-7E; only plain codes are logged.
const ERROR_CODE = /^[a-z0-9_.-]{1,64}$/i;

/**
 * Whether a Content-Type names exactly application/json: the media type before any parameter, compared
 * case-insensitively (RFC 9110 §8.3.1), so application/jsonx or application/json-seq is not JSON.
 *
 * @param contentType The header's value.
 * @returns Whether the body is application/json.
 */
export function isJson(contentType: string | null): boolean {
  return (contentType ?? "").split(";")[0]?.trim().toLowerCase() === "application/json";
}

function formEncode(value: string): string {
  return new URLSearchParams({ v: value }).toString().slice("v=".length);
}

/**
 * The Authorization header of client_secret_basic. RFC 6749 §2.3.1: the client_id and the secret are each encoded
 * with application/x-www-form-urlencoded (Appendix B; the WHATWG serializer, which URLSearchParams implements) before
 * they are joined with ":" and Base64-encoded as HTTP Basic (RFC 7617).
 *
 * @param clientId The client_id.
 * @param secret The client secret.
 * @returns The header value.
 */
export function clientSecretBasic(clientId: string, secret: string): string {
  return `Basic ${btoa(`${formEncode(clientId)}:${formEncode(secret)}`)}`;
}

/**
 * Creates the factory of IdP clients. The configuration is read per request (src/config.ts), while the caches live
 * in this closure for the isolate's lifetime; one isolate serves one deployment, so they always hold one IdP's data.
 *
 * @param fetcher The outbound fetch.
 * @param now The clock, in Unix seconds.
 * @returns A function that binds a client to the request's configuration, sharing the caches.
 */
export function createIdpClient(fetcher: Fetcher, now: () => number): (config: Config) => IdpClient {
  let discoveryCache: Cached<Discovery> | undefined;
  let jwksCache: Cached<readonly unknown[]> | undefined;

  async function requestJson(url: string, init: RequestInit, what: string): Promise<Record<string, unknown>> {
    const headers = new Headers(init.headers);
    headers.set("user-agent", USER_AGENT);
    headers.set("accept", "application/json");
    let response: Response;
    try {
      response = await fetcher(new Request(url, { ...init, headers, redirect: "manual", signal: AbortSignal.timeout(TIMEOUT_MS) }));
    } catch {
      throw new IdpError(`${what}: request failed`);
    }
    const json = isJson(response.headers.get("content-type"));
    // Workers report a refused same-account workers.dev fetch as an error page (1042); it fails here, as any non-2xx.
    if (response.status !== 200) {
      // RFC 6749 §5.2 and OIDC Core §3.1.3.4: an error response carries a JSON `error` code; only a plain code is
      // logged, never error_description, which is free text from the IdP.
      const error = json ? parseJsonObject(await response.text())?.error : undefined;
      const code = typeof error === "string" && ERROR_CODE.test(error) ? ` error ${error}` : "";
      throw new IdpError(`${what}: status ${response.status}${code}`);
    }
    // RFC 6749 §5.1 and OIDC Core §5.3.2: the token and UserInfo responses are application/json.
    if (!json) throw new IdpError(`${what}: not application/json`);
    const body = parseJsonObject(await response.text());
    if (body === undefined) throw new IdpError(`${what}: not a JSON object`);
    return body;
  }

  return (config) => {
    async function discover(): Promise<Discovery> {
      if (discoveryCache !== undefined && now() < discoveryCache.expiresAt) return discoveryCache.value;
      const document = await requestJson(`${config.issuer}/.well-known/openid-configuration`, {}, "discovery");
      if (document.issuer !== config.issuer) throw new IdpError("discovery: issuer does not match");
      const methods = document.token_endpoint_auth_methods_supported;
      if (
        !includes(document.response_types_supported, "code") ||
        !includes(document.code_challenge_methods_supported, "S256") ||
        !includes(document.id_token_signing_alg_values_supported, "Ed25519") ||
        // Omitted means client_secret_basic (OIDC Discovery 1.0 §3).
        (methods !== undefined && !includes(methods, "client_secret_basic")) ||
        document.authorization_response_iss_parameter_supported !== true
      ) {
        throw new IdpError("discovery: the IdP lacks a feature this RP requires");
      }
      const value: Discovery = {
        authorizationEndpoint: httpsUrl(document.authorization_endpoint, "authorization_endpoint"),
        tokenEndpoint: httpsUrl(document.token_endpoint, "token_endpoint"),
        userinfoEndpoint: httpsUrl(document.userinfo_endpoint, "userinfo_endpoint"),
        jwksUri: httpsUrl(document.jwks_uri, "jwks_uri"),
      };
      discoveryCache = { value, expiresAt: now() + CACHE_SECONDS };
      return value;
    }

    async function jwks(discovery: Discovery, refresh: boolean): Promise<readonly unknown[]> {
      if (!refresh && jwksCache !== undefined && now() < jwksCache.expiresAt) return jwksCache.value;
      const document = await requestJson(discovery.jwksUri, {}, "jwks");
      if (!Array.isArray(document.keys)) throw new IdpError("jwks: no keys");
      jwksCache = { value: document.keys, expiresAt: now() + CACHE_SECONDS };
      return document.keys;
    }

    async function verify(discovery: Discovery, idToken: string, nonce: string): Promise<IdTokenClaims> {
      const expected = { issuer: config.issuer, clientId: config.clientId, nonce, now: now() };
      try {
        return await verifyIdToken(idToken, expected, await jwks(discovery, false));
      } catch (error) {
        if (!(error instanceof IdTokenError) || error.reason !== "unknown_kid") throw error;
        return verifyIdToken(idToken, expected, await jwks(discovery, true));
      }
    }

    async function redeem(exchange: CodeExchange): Promise<LoginResult> {
      const discovery = await discover();
      const body = new URLSearchParams({
        grant_type: "authorization_code",
        code: exchange.code,
        redirect_uri: config.redirectUri,
        code_verifier: exchange.verifier,
      });
      const tokens = await requestJson(
        discovery.tokenEndpoint,
        {
          method: "POST",
          headers: {
            authorization: clientSecretBasic(config.clientId, config.clientSecret),
            "content-type": "application/x-www-form-urlencoded",
          },
          body: body.toString(),
        },
        "token",
      );
      const { access_token: accessToken, token_type: tokenType, id_token: idToken } = tokens;
      if (typeof accessToken !== "string" || accessToken === "" || typeof idToken !== "string" || typeof tokenType !== "string" || tokenType.toLowerCase() !== "bearer") {
        throw new IdpError("token: malformed response");
      }
      const claims = await verify(discovery, idToken, exchange.nonce);

      const userinfo = await requestJson(discovery.userinfoEndpoint, { headers: { authorization: `Bearer ${accessToken}` } }, "userinfo");
      // OIDC Core §5.3.2: the UserInfo sub MUST match the ID token's, or the response MUST NOT be used.
      if (typeof userinfo.sub !== "string" || userinfo.sub !== claims.sub) throw new IdpError("userinfo: sub does not match the ID token");
      return { idToken: claims, userinfo };
    }

    return { discover, redeem };
  };
}
