// The enrollment page (docs/design/authentication.md, "パスキーの登録"). The one-time token arrives in the URL
// fragment, so it never reaches a server log; it is removed from the address bar before anything else runs.
import {
  ApiError,
  api,
  applyMessages,
  createCredential,
  describeFailure,
  element,
  pageLocale,
  showStatus,
  supportsPasskeys,
  t,
  wireLanguageSelector,
} from "./common.js";

let locale = pageLocale();
applyMessages(locale);
wireLanguageSelector(locale, (next) => (locale = next));

const token = location.hash.slice(1);
history.replaceState(null, "", location.pathname + location.search);

// The Worker's refusals the user can act on: the link is no longer usable, or the passkey limit is reached.
function describeRefusal(error: unknown): string {
  if (error instanceof ApiError && error.type === "passkey_rejected") return t(locale, "enroll_invalid");
  if (error instanceof ApiError && error.type === "limit_reached") return t(locale, "enroll_limit");
  return describeFailure(locale, error);
}

async function enroll(button: HTMLButtonElement): Promise<void> {
  button.disabled = true;
  showStatus("error", "");
  let options: unknown;
  let credential: unknown;
  try {
    options = await api("POST", "/webauthn/register/options", { token });
    credential = await createCredential(options);
  } catch (error) {
    showStatus("error", describeRefusal(error));
    // The token is not consumed by options, so a cancelled ceremony can be retried; a refused link cannot.
    button.disabled = error instanceof ApiError;
    return;
  }
  try {
    await api("POST", "/webauthn/register/verify", { token, credential });
  } catch (error) {
    // Without an answer (the connection dropped, or the Worker failed after its batch) the token may already be
    // consumed with the passkey saved, so registering again would fail; the user is sent to sign in instead.
    const lost = !(error instanceof ApiError) || error.status >= 500;
    showStatus("error", lost ? t(locale, "enroll_lost") : describeRefusal(error));
    return;
  }
  button.hidden = true;
  showStatus("status", t(locale, "enroll_done"));
}

const button = element<HTMLButtonElement>("enroll");
if (!/^[A-Za-z0-9_-]{43}$/.test(token)) {
  showStatus("error", t(locale, "enroll_no_token"));
} else if (!supportsPasskeys()) {
  showStatus("error", t(locale, "unsupported_browser"));
} else {
  button.disabled = false;
  button.addEventListener("click", () => void enroll(button));
}
