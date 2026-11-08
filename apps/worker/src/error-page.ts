// The only page the Worker renders: the /authorize error page, shown when there is no redirect target that can be
// trusted (RFC 6749 §4.1.2.1). It shows a generic sentence and the error type for support, never internal detail
// (docs/design/authentication.md, "画面と言語").
import type { AuthorizeErrorPageReason, UiLocale } from "@idp/core/user";

/** Why the page is shown: the core's reasons, plus a resume request that failed the same-origin check. */
export type ErrorPageReason = AuthorizeErrorPageReason | "cross_origin_request";

type Messages = {
  readonly title: string;
  readonly body: string;
  readonly code: string;
};

// One dictionary per language; adding a language means adding an entry here and to UiLocale in the core.
const MESSAGES: Readonly<Record<UiLocale, Messages>> = {
  en: {
    title: "Sign-in could not continue",
    body: "This sign-in request cannot be completed. Go back to the app and try again.",
    code: "Error type",
  },
  ja: {
    title: "サインインを続けられません",
    body: "このサインインの要求は完了できません。アプリに戻って、もう一度お試しください。",
    code: "エラーの種類",
  },
};

/**
 * Renders the error page.
 *
 * @param reason The error type shown for support.
 * @param locale The language chosen by the core from ui_locales and Accept-Language.
 * @returns The HTML document; every string in it comes from the dictionary or the fixed reason list.
 */
export function renderErrorPage(reason: ErrorPageReason, locale: UiLocale): string {
  const m = MESSAGES[locale];
  return `<!doctype html>
<html lang="${locale}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${m.title}</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<main>
<h1>${m.title}</h1>
<p role="alert">${m.body}</p>
<p>${m.code}: <code>${reason}</code></p>
</main>
</body>
</html>
`;
}
