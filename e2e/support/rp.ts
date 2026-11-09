// A minimal RP stand-in: it starts the code flow with PKCE, receives the redirect on its own HTTPS endpoint, and
// makes the back-channel calls an RP makes, over real TLS to the local IdP.
import { createHash, randomBytes } from "node:crypto";
import { createServer, request } from "node:https";
import type { Page } from "@playwright/test";
import { IDP_HOST, ISSUER, type LocalIdp } from "./idp.js";
import { REDIRECT_URI, type SeededClient } from "./seed.js";
import type { TestCertificate } from "./tls.js";

/** The RP stand-in's host, the one in {@link REDIRECT_URI}. */
export const RP_HOST = "rp.test";

/** A back-channel response. */
export type IdpResponse = {
  readonly status: number;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
  readonly body: string;
};

/** What the redirect to the RP carried. */
export type Callback = {
  readonly code: string | null;
  readonly state: string | null;
  readonly iss: string | null;
  readonly error: string | null;
};

/** One authorization request's values the RP keeps until the callback. */
export type Flow = {
  readonly url: string;
  readonly state: string;
  readonly nonce: string;
  readonly verifier: string;
};

function random(): string {
  return randomBytes(32).toString("base64url");
}

/**
 * Builds an authorization request for the client with fresh state, nonce, and PKCE (S256) values.
 *
 * @param client The registered client.
 * @param extra More parameters, such as `prompt`.
 * @returns The /authorize URL and the values the RP checks later.
 */
export function authorizeFlow(client: SeededClient, extra: Readonly<Record<string, string>> = {}): Flow {
  const state = random();
  const nonce = random();
  const verifier = random();
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const params = new URLSearchParams({
    response_type: "code",
    client_id: client.clientId,
    redirect_uri: REDIRECT_URI,
    scope: "openid profile",
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
    ...extra,
  });
  return { url: `${ISSUER}/authorize?${params.toString()}`, state, nonce, verifier };
}

/** The RP stand-in's HTTPS server. */
export type LocalRp = {
  /** The loopback port; Chromium maps rp.test:443 to it. */
  readonly port: number;
  readonly close: () => Promise<void>;
};

/**
 * Starts the RP's redirect endpoint on a free loopback port. It answers every request with a plain page: the RP's
 * checks are made by the test from the URL the browser landed on. (Playwright's request routing cannot stand in for
 * it: Chromium does not route the target of a redirect.)
 *
 * @param certificate The run's certificate, which also names {@link RP_HOST}.
 * @returns The running server.
 * @throws {Error} The server cannot listen.
 */
export async function startRp(certificate: TestCertificate): Promise<LocalRp> {
  const server = createServer({ key: certificate.keyPem, cert: certificate.certPem }, (_req, res) => {
    res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    res.end("RP");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("the RP server has no port");
  return {
    port: address.port,
    close: () => new Promise((resolve, reject) => server.close((error) => (error === undefined ? resolve() : reject(error)))),
  };
}

/**
 * Waits until the page is on the RP's redirect URI and reads the response parameters.
 *
 * @returns The parameters of the redirect.
 * @throws {Error} The page does not reach the RP in time.
 */
export async function waitForCallback(page: Page): Promise<Callback> {
  await page.waitForURL((url) => url.origin === `https://${RP_HOST}`);
  const params = new URL(page.url()).searchParams;
  return { code: params.get("code"), state: params.get("state"), iss: params.get("iss"), error: params.get("error") };
}

/**
 * Sends one request to the local IdP as a server-side client would: TLS to the issuer's host, trusting only the
 * run's certificate.
 *
 * @param idp The running IdP.
 * @param method The HTTP method.
 * @param path The path and query.
 * @param headers Request headers.
 * @param body A request body.
 * @returns The response.
 * @throws {Error} The connection or the TLS handshake fails.
 */
export function idpRequest(
  idp: LocalIdp,
  method: string,
  path: string,
  headers: Readonly<Record<string, string>> = {},
  body?: string,
): Promise<IdpResponse> {
  return new Promise((resolve, reject) => {
    const req = request(
      { host: "127.0.0.1", port: idp.port, servername: IDP_HOST, ca: idp.certificate.certPem, method, path, headers: { host: IDP_HOST, ...headers } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
        res.on("error", reject);
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

/**
 * Exchanges a code at /token: client_secret_basic for a confidential client, client_id alone for a public one.
 *
 * @returns The response.
 * @throws {Error} The request cannot be sent.
 */
export function exchangeCode(idp: LocalIdp, client: SeededClient, flow: Flow, code: string): Promise<IdpResponse> {
  const form = new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: flow.verifier });
  const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" };
  if (client.secret === undefined) {
    form.set("client_id", client.clientId);
  } else {
    // RFC 6749 §2.3.1: both halves are form-encoded before Base64.
    const basic = `${encodeURIComponent(client.clientId)}:${encodeURIComponent(client.secret)}`;
    headers["authorization"] = `Basic ${Buffer.from(basic).toString("base64")}`;
  }
  return idpRequest(idp, "POST", "/token", headers, form.toString());
}

/**
 * Calls /userinfo with a Bearer access token.
 *
 * @returns The response.
 * @throws {Error} The request cannot be sent.
 */
export function fetchUserinfo(idp: LocalIdp, accessToken: string): Promise<IdpResponse> {
  return idpRequest(idp, "GET", "/userinfo", { authorization: `Bearer ${accessToken}` });
}
