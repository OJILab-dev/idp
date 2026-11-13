// The pages of RP-Initiated Logout 1.0 (docs/design/authentication.md, "RP からのログアウト"): the confirmation, the
// signed-out page, and the error page. They render the core's decision, so they are drawn here rather than served as
// static assets. Every value that comes from the request is HTML-escaped; the rest comes from the dictionaries.
import type { EndSessionErrorReason, UiLocale } from "@idp/core/user";

/** Why the logout error page is shown: the core's reasons, plus a confirmation that failed the same-origin check. */
export type LogoutErrorReason = EndSessionErrorReason | "cross_origin_request";

type Messages = {
  readonly confirmTitle: string;
  readonly confirmBody: string;
  readonly confirmOtherUser: string;
  readonly confirmButton: string;
  readonly signedOutTitle: string;
  readonly signedOutBody: string;
  readonly errorTitle: string;
  readonly errorBody: string;
  readonly code: string;
};

// One dictionary per language; adding a language means adding an entry here and to UiLocale in the core.
const MESSAGES: Readonly<Record<UiLocale, Messages>> = {
  en: {
    confirmTitle: "Sign out of the identity provider?",
    confirmBody:
      "An app asked to sign you out of the identity provider. After you sign out, the next sign-in asks for your passkey again. If you did not ask for this, close this page.",
    confirmOtherUser: "This request was made for another account than the one signed in here.",
    confirmButton: "Sign out",
    signedOutTitle: "You are signed out",
    signedOutBody: "You are signed out of the identity provider. You can close this page.",
    errorTitle: "Sign-out could not continue",
    errorBody: "This sign-out request cannot be completed. Go back to the app and try again.",
    code: "Error type",
  },
  ja: {
    confirmTitle: "ID プロバイダーからサインアウトしますか",
    confirmBody:
      "アプリが、ID プロバイダーからのサインアウトを求めています。サインアウトすると、次のサインインでもう一度パスキーが必要になります。心当たりがなければ、このページを閉じてください。",
    confirmOtherUser: "この要求は、ここでサインインしているのとは別のアカウントのためのものです。",
    confirmButton: "サインアウトする",
    signedOutTitle: "サインアウトしました",
    signedOutBody: "ID プロバイダーからサインアウトしました。このページは閉じてかまいません。",
    errorTitle: "サインアウトを続けられません",
    errorBody: "このサインアウトの要求は完了できません。アプリに戻って、もう一度お試しください。",
    code: "エラーの種類",
  },
};

const ESCAPES: Readonly<Record<string, string>> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

/**
 * Escapes text for an HTML text node or a double-quoted attribute value.
 *
 * @param value Untrusted text.
 * @returns The text with `& < > " '` replaced by character references.
 */
export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (ch) => ESCAPES[ch] ?? ch);
}

function page(locale: UiLocale, title: string, body: string): string {
  return `<!doctype html>
<html lang="${locale}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<main>
<h1>${title}</h1>
${body}
</main>
</body>
</html>
`;
}

/**
 * Renders the confirmation page: a form that posts the validated values to `/end_session/confirm`.
 *
 * @param locale The language the core chose.
 * @param form The values to carry, in order; each name and value is escaped.
 * @param otherUser Whether the hint named another user than the signed-in one.
 * @returns The HTML document.
 */
export function renderLogoutConfirmPage(locale: UiLocale, form: readonly (readonly [string, string])[], otherUser: boolean): string {
  const m = MESSAGES[locale];
  const fields = form.map(([name, value]) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`).join("\n");
  const warning = otherUser ? `<p role="alert">${m.confirmOtherUser}</p>\n` : "";
  return page(
    locale,
    m.confirmTitle,
    `${warning}<p>${m.confirmBody}</p>
<form method="post" action="/end_session/confirm">
${fields}
<button type="submit">${m.confirmButton}</button>
</form>`,
  );
}

/**
 * Renders the IdP's own signed-out page, shown when there is no registered redirect to return to.
 *
 * @param locale The language the core chose.
 * @returns The HTML document.
 */
export function renderSignedOutPage(locale: UiLocale): string {
  const m = MESSAGES[locale];
  return page(locale, m.signedOutTitle, `<p>${m.signedOutBody}</p>`);
}

/**
 * Renders the logout error page: a generic sentence and the error type for support, never internal detail.
 *
 * @param reason The error type.
 * @param locale The language.
 * @returns The HTML document.
 */
export function renderLogoutErrorPage(reason: LogoutErrorReason, locale: UiLocale): string {
  const m = MESSAGES[locale];
  return page(locale, m.errorTitle, `<p role="alert">${m.errorBody}</p>\n<p>${m.code}: <code>${reason}</code></p>`);
}
