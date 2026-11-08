// The English messages of the static pages; every other language has exactly these keys (test/pages.test.ts).
export const en = {
  language: "Language",
  error_type: "Error type",
  unsupported_browser: "This browser does not support passkeys.",
  failed: "Something went wrong. Try again.",
  signin_title: "Sign in",
  signin_button: "Sign in with a passkey",
  signin_working: "Waiting for your passkey…",
  enroll_title: "Register a passkey",
  enroll_button: "Create a passkey",
  enroll_done: "Your passkey is registered. Return to the app and sign in.",
  enroll_no_token: "This registration link is incomplete. Ask your administrator for a new link.",
  enroll_lost: "The registration may have completed. Try signing in from the app; if that fails, ask your administrator for a new link.",
  account_title: "Your passkeys",
  account_no_session: "You are not signed in. Sign in from an app, then open this page again.",
  account_add: "Add a passkey",
  account_revoke: "Remove",
  account_logout: "Sign out",
  account_signed_out: "You are signed out.",
  account_created: "Created",
  account_last_used: "Last used",
  account_synced: "Synced passkey",
  account_device_bound: "Device-bound passkey",
  account_never: "Never",
} as const;

/** A message key. */
export type MessageKey = keyof typeof en;
