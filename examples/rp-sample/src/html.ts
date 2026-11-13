// Server-rendered HTML. Every value that comes from the IdP or the request goes through escapeHtml; the only markup
// is the literal text of this file. No script runs on these pages, and the CSP forbids any; the one exception is the
// logout page's auto-submit, allowed by its hash in that page's own CSP.
import { base64urlDecode, parseJsonObject } from "./encoding.js";
import type { IdTokenClaims } from "./id-token.js";

/** What the session keeps: only what the account page shows. */
export type SessionView = {
  readonly idToken: Readonly<Record<string, unknown>>;
  readonly userinfo: Readonly<Record<string, unknown>>;
};

/**
 * Escapes text for HTML element content and quoted attribute values.
 *
 * @param value Any value; non-strings are converted with String.
 * @returns The escaped text.
 */
export function escapeHtml(value: unknown): string {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

const STYLE = `body{font-family:system-ui,sans-serif;max-width:48rem;margin:2rem auto;padding:0 1rem;line-height:1.5}
table{border-collapse:collapse}th,td{border:1px solid #ccc;padding:.25rem .5rem;text-align:left;vertical-align:top}
pre{background:#f4f4f4;padding:.5rem;overflow:auto}`;

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>${STYLE}</style>
</head>
<body>
<h1>${escapeHtml(title)}</h1>
${body}
</body>
</html>`;
}

/** The CSP of every page: no script, no external resource, the one inline style, forms to this origin only. */
export const CONTENT_SECURITY_POLICY =
  "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/** The one script any page runs: it submits the logout form, so the ID token travels in a POST body. */
export const AUTO_SUBMIT_SCRIPT = "document.forms[0].submit();";

/**
 * The CSP of the logout page: the page's CSP with exactly {@link AUTO_SUBMIT_SCRIPT} allowed by its hash (no nonce,
 * no 'unsafe-inline'), and form posts to the IdP's origin. 'self' stays in form-action because the IdP answers the
 * post with a redirect back to this RP's /signed-out, and browsers check form-action on redirects too.
 *
 * @param idpOrigin The origin of the end_session_endpoint.
 * @returns The header value.
 */
export function logoutContentSecurityPolicy(idpOrigin: string): string {
  return `default-src 'none'; script-src 'sha256-${AUTO_SUBMIT_SCRIPT_SHA256}'; style-src 'unsafe-inline'; form-action ${idpOrigin} 'self'; frame-ancestors 'none'; base-uri 'none'`;
}

/** SHA-256 of {@link AUTO_SUBMIT_SCRIPT}, base64 (CSP Level 3 hash-source); a test recomputes it from the script. */
export const AUTO_SUBMIT_SCRIPT_SHA256 = "8lDeP0UDwCO6/RhblgeH/ctdBzjVpJxrXizsnIk3cEQ=";

/**
 * The ID token claims the account page shows, read from the sealed ID token. The token was verified at /callback
 * and the cookie is authenticated, so it is only decoded here; keeping it once saves cookie octets.
 *
 * @param jwt The ID token as issued.
 * @returns The claims to show, or undefined when the value is not a JWS with a JSON object payload.
 */
export function idTokenViewFromJwt(jwt: string): Readonly<Record<string, unknown>> | undefined {
  const payload = jwt.split(".")[1];
  const bytes = payload === undefined ? undefined : base64urlDecode(payload);
  const claims = bytes === undefined ? undefined : parseJsonObject(new TextDecoder().decode(bytes));
  return claims === undefined ? undefined : idTokenView(claims as IdTokenClaims);
}

/**
 * The logout page: a form that posts the RP-Initiated Logout request to the IdP and submits itself. Without script
 * the button submits it.
 *
 * @param endpoint The end_session_endpoint.
 * @param fields The request parameters, in order; each name and value is escaped.
 * @returns The HTML.
 */
export function logoutFormPage(endpoint: string, fields: readonly (readonly [string, string])[]): string {
  const inputs = fields.map(([name, value]) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`).join("\n");
  return page(
    "RP sample",
    `<p>この RP からログアウトしました。IdP からもサインアウトします。</p>
<form method="post" action="${escapeHtml(endpoint)}">
${inputs}
<button type="submit">IdP からもサインアウトする</button>
</form>
<script>${AUTO_SUBMIT_SCRIPT}</script>`,
  );
}

/**
 * The post-logout landing page.
 *
 * @param confirmed Whether the returned state matched this browser's logout request.
 * @returns The HTML.
 */
export function postLogoutPage(confirmed: boolean): string {
  const message = confirmed
    ? "IdP からもサインアウトしました。"
    : "IdP からの戻りを確かめられませんでした。この RP のセッションは消してあります。";
  return page("RP sample", `<p>${message}</p>\n<p><a href="/">トップへ戻る</a></p>`);
}

/**
 * The page for a visitor without a session.
 *
 * @returns The HTML.
 */
export function signedOutPage(): string {
  return page("RP sample", `<p>サインインしていません。</p>\n<p><a href="/login">IdP でサインイン</a></p>`);
}

function row(name: string, value: unknown): string {
  return `<tr><th>${escapeHtml(name)}</th><td>${escapeHtml(value)}</td></tr>`;
}

function time(value: unknown): string {
  return typeof value === "number" ? `${value} (${new Date(value * 1000).toISOString()})` : "";
}

/**
 * The account page: sub, the ID token claims that matter, the /userinfo response, and the logout button.
 *
 * @param session The signed-in session.
 * @returns The HTML.
 */
export function accountPage(session: SessionView): string {
  const claims = session.idToken;
  const rows = [
    row("sub", claims.sub),
    row("name", claims.name ?? ""),
    row("iss", claims.iss),
    row("aud", Array.isArray(claims.aud) ? claims.aud.join(" ") : claims.aud),
    row("auth_time", time(claims.auth_time)),
    row("iat", time(claims.iat)),
    row("exp", time(claims.exp)),
  ].join("\n");
  return page(
    "RP sample",
    `<p>サインインしています。利用者は <code>iss</code> と <code>sub</code> の組で識別します。</p>
<h2>ID トークンのクレーム</h2>
<table>
${rows}
</table>
<h2>/userinfo の応答</h2>
<pre>${escapeHtml(JSON.stringify(session.userinfo, null, 2))}</pre>
<form method="post" action="/logout"><button type="submit">ログアウト（IdP からも）</button></form>`,
  );
}

/**
 * An error page. The message is fixed text chosen by the caller; detail is an escaped short code.
 *
 * @param message The fixed message.
 * @param detail An optional code to show, such as the IdP's OAuth error code.
 * @returns The HTML.
 */
export function errorPage(message: string, detail?: string): string {
  const code = detail === undefined ? "" : `<p><code>${escapeHtml(detail)}</code></p>`;
  return page("RP sample", `<p>${escapeHtml(message)}</p>\n${code}<p><a href="/">トップへ戻る</a></p>`);
}

/**
 * The claims of an ID token that the session keeps for the account page.
 *
 * @param claims The checked claims.
 * @returns The subset to store.
 */
export function idTokenView(claims: IdTokenClaims): Readonly<Record<string, unknown>> {
  const { iss, sub, aud, iat, exp, auth_time: authTime, name } = claims;
  return { iss, sub, aud, iat, exp, auth_time: authTime, name };
}
