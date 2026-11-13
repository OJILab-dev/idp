// The UI language: ui_locales first, then the browser's languages, then English (docs/design/authentication.md,
// "画面と言語"). An unsupported language is skipped rather than rejected (OIDC Core §3.1.2.1, SHOULD NOT error).
// The browser's wildcard range "*" never selects a language: it matches no supported primary subtag.
import { parseAcceptLanguage } from "@idp/accept-language";

/** A language the sign-in page and the error page have a dictionary for (BCP 47; the contract's "UI の言語"). */
export type UiLocale = "en" | "ja";

const SUPPORTED: readonly UiLocale[] = ["en", "ja"];
const DEFAULT_LOCALE: UiLocale = "en";

/**
 * Chooses the UI language for an authorization request.
 *
 * Tags match on their primary subtag, case-insensitively, so `ja-JP` selects `ja` (RFC 5646 §2.1.1 makes tags
 * case-insensitive).
 *
 * @param uiLocales The `ui_locales` parameter: space-separated tags in order of preference; `undefined` when absent.
 * @param acceptLanguage The `Accept-Language` header (RFC 9110 §12.5.4); `undefined` when absent.
 * @returns The first supported language, or `en`.
 */
export function selectUiLocale(uiLocales: string | undefined, acceptLanguage: string | undefined): UiLocale {
  const browserTags = acceptLanguage === undefined ? [] : parseAcceptLanguage(acceptLanguage).map((preference) => preference.range);
  const candidates = [...(uiLocales?.split(" ") ?? []), ...browserTags];
  for (const tag of candidates) {
    const match = toSupported(tag);
    if (match !== undefined) return match;
  }
  return DEFAULT_LOCALE;
}

/**
 * Narrows a stored or queried value to a supported language.
 *
 * @param value An untrusted value, such as `authorize_requests.locale`.
 * @returns The language, or `undefined` when the value is not exactly a supported tag.
 */
export function asUiLocale(value: unknown): UiLocale | undefined {
  return SUPPORTED.find((locale) => locale === value);
}

function toSupported(tag: string): UiLocale | undefined {
  const primary = tag.split("-")[0]?.toLowerCase();
  return SUPPORTED.find((locale) => locale === primary);
}
