// The sign-in page (docs/design/authentication.md, steps 4 to 6). Each load takes one challenge bound to the
// authorize request cookie; the conditional (autofill) request and the button share it, and the button aborts the
// conditional request first. After /webauthn/auth/verify the form posts to /authorize/resume.
import { ApiError, api, applyMessages, describeFailure, element, getAssertion, pageLocale, showStatus, supportsPasskeys, t } from "./common.js";

const locale = pageLocale();
applyMessages(locale);

async function finish(credential: unknown): Promise<void> {
  await api("POST", "/webauthn/auth/verify", { credential });
  // A form POST rather than a fetch: the response is the redirect to the RP, which the browser must follow.
  element<HTMLFormElement>("resume").submit();
}

async function main(): Promise<void> {
  const button = element<HTMLButtonElement>("signin");
  if (!supportsPasskeys()) {
    showStatus("error", t(locale, "unsupported_browser"));
    return;
  }
  let options: unknown;
  try {
    options = await api("POST", "/webauthn/auth/options");
  } catch (error) {
    // The authorize request is gone (expired, or already resumed): only the app can start a new one.
    if (error instanceof ApiError && error.type === "passkey_rejected") {
      showStatus("error", t(locale, "signin_restart"));
      return;
    }
    throw error;
  }
  let conditional: AbortController | undefined;
  let failed = false;

  button.disabled = false;
  button.addEventListener("click", () => {
    // The challenge may have been consumed by a failed verify; a fresh load takes a new one.
    if (failed) {
      location.reload();
      return;
    }
    conditional?.abort();
    button.disabled = true;
    showStatus("error", "");
    showStatus("status", t(locale, "signin_working"));
    getAssertion(options)
      .then(finish)
      .catch((error: unknown) => {
        showStatus("status", "");
        showStatus("error", describeFailure(locale, error));
        failed = true;
        button.disabled = false;
      });
  });

  // WebAuthn Level 3 §5.1.4: check for conditional mediation before using it.
  if (await PublicKeyCredential.isConditionalMediationAvailable()) {
    conditional = new AbortController();
    getAssertion(options, { mediation: "conditional", signal: conditional.signal })
      .then(finish)
      .catch((error: unknown) => {
        // The button aborts the autofill request on purpose; only a real failure is shown.
        if (!(error instanceof DOMException && error.name === "AbortError")) showStatus("error", describeFailure(locale, error));
      });
  }
}

main().catch((error: unknown) => showStatus("error", describeFailure(locale, error)));
