// Server-rendered HTML. Every value that comes from the IdP or the request goes through escapeHtml; the only markup
// is the literal text of this file. No script runs on these pages, and the CSP forbids any.
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
<form method="post" action="/logout"><button type="submit">ログアウト（この RP だけ）</button></form>`,
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
