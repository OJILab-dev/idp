// The account page (docs/design/authentication.md, "アカウントページ"). It checks nothing itself: every list, add,
// and revoke goes through the /webauthn/* API, which checks the session, and both add and revoke re-authenticate
// with an existing passkey before they act.
import {
  ApiError,
  api,
  applyMessages,
  createCredential,
  describeFailure,
  element,
  getAssertion,
  pageLocale,
  showStatus,
  supportsPasskeys,
  t,
  wireLanguageSelector,
  type UiLocale,
} from "./common.js";

/** One row of `GET /webauthn/credentials` (the core's OwnPasskey): only what the design lets the API return. */
type PasskeyRow = {
  readonly credential_id: string;
  readonly created_at: number;
  readonly last_used_at: number | null;
  readonly created_via: "enroll" | "self";
  readonly backup_state: boolean;
};

let locale: UiLocale = pageLocale();
let rows: readonly PasskeyRow[] = [];
applyMessages(locale);
wireLanguageSelector(locale, (next) => {
  locale = next;
  render();
});

function formatTime(seconds: number | null): string {
  return seconds === null ? t(locale, "account_never") : new Date(seconds * 1000).toLocaleString(locale);
}

function render(): void {
  const list = element<HTMLUListElement>("passkeys");
  list.replaceChildren(
    ...rows.map((row) => {
      const item = document.createElement("li");
      const kind = document.createElement("strong");
      kind.textContent = t(locale, row.backup_state ? "account_synced" : "account_device_bound");
      const times = document.createElement("span");
      times.textContent = ` ${t(locale, "account_created")}: ${formatTime(row.created_at)} / ${t(locale, "account_last_used")}: ${formatTime(row.last_used_at)} `;
      const revoke = document.createElement("button");
      revoke.type = "button";
      revoke.textContent = t(locale, "account_revoke");
      // The last passkey cannot be revoked (the Worker refuses it too); offering the button would only fail.
      revoke.disabled = rows.length < 2;
      revoke.addEventListener("click", () => void run(() => revokePasskey(row.credential_id)));
      item.append(kind, times, revoke);
      return item;
    }),
  );
}

async function load(): Promise<void> {
  const body = (await api("GET", "/webauthn/credentials")) as { readonly credentials: readonly PasskeyRow[] };
  rows = body.credentials;
  element("signed-in").hidden = false;
  render();
}

async function addPasskey(): Promise<void> {
  const reauth = await api("POST", "/webauthn/add/begin");
  const creation = await api("POST", "/webauthn/add/options", { credential: await getAssertion(reauth) });
  await api("POST", "/webauthn/add/verify", { credential: await createCredential(creation) });
  await load();
}

async function revokePasskey(credentialId: string): Promise<void> {
  const reauth = await api("POST", "/webauthn/revoke/begin", { credential_id: credentialId });
  const result = (await api("POST", "/webauthn/revoke/verify", { credential_id: credentialId, credential: await getAssertion(reauth) })) as {
    readonly session_ended: boolean;
  };
  // Revoking the passkey this session was signed in with ends the session too (authentication.md, revocation step 4).
  if (result.session_ended) signedOut(t(locale, "account_revoked_signed_out"));
  else await load();
}

async function signOut(): Promise<void> {
  await api("POST", "/logout");
  signedOut(t(locale, "account_signed_out"));
}

function signedOut(message: string): void {
  element("signed-in").hidden = true;
  showStatus("status", message);
}

// Runs one action; a 401 means the session is gone (expired, signed out, or ended by revoking its own passkey).
async function run(action: () => Promise<void>): Promise<void> {
  showStatus("error", "");
  try {
    await action();
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) signedOut(t(locale, "account_no_session"));
    else if (error instanceof ApiError && error.type === "limit_reached") showStatus("error", t(locale, "account_limit"));
    else if (error instanceof ApiError && error.type === "last_passkey") showStatus("error", t(locale, "account_last_passkey"));
    else showStatus("error", describeFailure(locale, error));
  }
}

if (!supportsPasskeys()) {
  showStatus("error", t(locale, "unsupported_browser"));
} else {
  element("add").addEventListener("click", () => void run(addPasskey));
  element("logout").addEventListener("click", () => void run(signOut));
  void run(load);
}
