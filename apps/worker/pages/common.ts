// What the three pages share: the language, the messages, and the JSON calls to the Worker. The pages are static
// assets, so every check that matters happens in the Worker; this code only drives the WebAuthn ceremonies.
// The core's language rules, imported from their own module rather than the @idp/core/user barrel: it has no imports,
// so the page bundle carries no server code (tokens, SQL) and needs no Worker types.
import { asUiLocale, selectUiLocale, type UiLocale } from "../../../packages/core/src/user/locale.js";
import { en, type MessageKey } from "./locales/en.js";

export type { UiLocale };
import { ja } from "./locales/ja.js";

const DICTIONARIES: Readonly<Record<UiLocale, Readonly<Record<MessageKey, string>>>> = { en, ja };

/** A failed call to the Worker; `type` is the error type shown for support, never a server detail. */
export class ApiError extends Error {
  override readonly name = "ApiError";
  constructor(readonly status: number, readonly type: string) {
    super(`${status} ${type}`);
  }
}

/**
 * Chooses the language: `?lang=` (set by the Worker from ui_locales), then the browser's languages, then English,
 * with the same rules as the core.
 *
 * @returns The language.
 */
export function pageLocale(): UiLocale {
  const fromQuery = asUiLocale(new URLSearchParams(location.search).get("lang"));
  return fromQuery ?? selectUiLocale(undefined, navigator.languages.join(","));
}

/**
 * Looks a message up.
 *
 * @returns The message in the language.
 */
export function t(locale: UiLocale, key: MessageKey): string {
  return DICTIONARIES[locale][key];
}

/**
 * Fills every `[data-i18n]` element with its message and sets the document language.
 *
 * @param locale The language.
 */
export function applyMessages(locale: UiLocale): void {
  document.documentElement.lang = locale;
  for (const element of document.querySelectorAll<HTMLElement>("[data-i18n]")) {
    const key = element.dataset["i18n"];
    if (key !== undefined && key in en) element.textContent = t(locale, key as MessageKey);
  }
}

/**
 * Wires the language selector of a page that does not come from an RP (enrollment, account).
 *
 * @param initial The language to start with.
 * @param onChange Called with the new language after the messages are applied.
 */
export function wireLanguageSelector(initial: UiLocale, onChange: (locale: UiLocale) => void): void {
  const select = element<HTMLSelectElement>("lang");
  select.value = initial;
  select.addEventListener("change", () => {
    const locale = asUiLocale(select.value) ?? initial;
    applyMessages(locale);
    onChange(locale);
  });
}

/**
 * Shows a status line that assistive technology reads out (`role="status"` or `role="alert"` in the HTML).
 *
 * @param text The message; an empty string hides the line.
 */
export function showStatus(id: string, text: string): void {
  const target = element(id);
  target.textContent = text;
  target.hidden = text === "";
}

/**
 * Describes a failure for the user: the generic sentence plus the error type.
 *
 * @returns The text to show.
 */
export function describeFailure(locale: UiLocale, error: unknown): string {
  // A cancelled or timed-out ceremony is the browser's NotAllowedError; it needs no error type.
  if (error instanceof DOMException && error.name === "NotAllowedError") return t(locale, "failed");
  const type = error instanceof ApiError ? error.type : error instanceof DOMException ? error.name : "client_error";
  return `${t(locale, "failed")} (${t(locale, "error_type")}: ${type})`;
}

/**
 * Gets an element the page's HTML is known to have.
 *
 * @throws {Error} The element is missing, which means the HTML and the script disagree.
 */
export function element<T extends HTMLElement = HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (found === null) throw new Error(`#${id} is missing`);
  return found as T;
}

/**
 * Calls a Worker endpoint with a JSON body (or none) and returns its JSON response.
 *
 * Same-origin and with cookies; the Worker checks Sec-Fetch-Site on every /webauthn/* call.
 *
 * @throws {ApiError} The response is not 2xx; `type` is the body's `error` when it is a plain identifier.
 */
export async function api(method: "GET" | "POST", path: string, body?: unknown): Promise<unknown> {
  const response = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: body === undefined ? {} : { "content-type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await response.text();
  let json: unknown = null;
  try {
    json = text === "" ? null : JSON.parse(text);
  } catch {
    // A 500 from the Worker is plain text; it is still reported by its status below.
    if (response.ok) throw new ApiError(response.status, "invalid_response");
  }
  if (!response.ok) {
    const error = typeof json === "object" && json !== null ? (json as Record<string, unknown>)["error"] : undefined;
    throw new ApiError(response.status, typeof error === "string" && /^[a-z0-9_-]{1,64}$/.test(error) ? error : `http_${response.status}`);
  }
  return json;
}

/**
 * Whether the browser has the WebAuthn Level 3 JSON helpers the pages rely on (§5.1.8, §5.1.9, §5.1).
 *
 * @returns `true` when passkeys can be used from these pages.
 */
export function supportsPasskeys(): boolean {
  return typeof PublicKeyCredential !== "undefined" && typeof PublicKeyCredential.parseRequestOptionsFromJSON === "function";
}

/**
 * Runs an authentication ceremony with options from the Worker.
 *
 * @param options The Worker's `PublicKeyCredentialRequestOptionsJSON`.
 * @param extra `mediation` and `signal` for the conditional (autofill) request.
 * @returns The assertion as JSON, ready to send back.
 * @throws {DOMException} The user cancelled, the ceremony timed out, or it was aborted.
 */
export async function getAssertion(options: unknown, extra: Omit<CredentialRequestOptions, "publicKey"> = {}): Promise<unknown> {
  const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(options as PublicKeyCredentialRequestOptionsJSON);
  const credential = await navigator.credentials.get({ ...extra, publicKey });
  if (!(credential instanceof PublicKeyCredential)) throw new DOMException("no credential", "NotAllowedError");
  return credential.toJSON();
}

/**
 * Runs a registration ceremony with options from the Worker.
 *
 * @param options The Worker's `PublicKeyCredentialCreationOptionsJSON`.
 * @returns The new credential as JSON, ready to send back.
 * @throws {DOMException} The user cancelled, the ceremony timed out, or the authenticator already holds a passkey.
 */
export async function createCredential(options: unknown): Promise<unknown> {
  const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(options as PublicKeyCredentialCreationOptionsJSON);
  const credential = await navigator.credentials.create({ publicKey });
  if (!(credential instanceof PublicKeyCredential)) throw new DOMException("no credential", "NotAllowedError");
  return credential.toJSON();
}
