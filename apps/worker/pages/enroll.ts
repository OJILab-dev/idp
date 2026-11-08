// The enrollment page (docs/design/authentication.md, "パスキーの登録"). The one-time token arrives in the URL
// fragment, so it never reaches a server log; it is removed from the address bar before anything else runs.
import {
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

async function enroll(button: HTMLButtonElement): Promise<void> {
  button.disabled = true;
  showStatus("error", "");
  let options: unknown;
  let credential: unknown;
  try {
    options = await api("POST", "/webauthn/register/options", { token });
    credential = await createCredential(options);
  } catch (error) {
    showStatus("error", describeFailure(locale, error));
    button.disabled = false;
    return;
  }
  try {
    await api("POST", "/webauthn/register/verify", { token, credential });
  } catch (error) {
    // The token may already be consumed with the passkey saved (a lost response), so registering again would fail;
    // the user is sent to sign in instead of being asked to retry.
    showStatus("error", error instanceof TypeError ? t(locale, "enroll_lost") : describeFailure(locale, error));
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
