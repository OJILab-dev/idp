// A CDP virtual authenticator (Chrome DevTools Protocol, WebAuthn domain), so the pages run the browser's real
// WebAuthn API: a platform passkey provider with resident keys and user verification, as a phone or laptop has.
import type { CDPSession, Page } from "@playwright/test";

/** A credential as the virtual authenticator holds it, private key included (it exists only in this run). */
export type VirtualCredential = {
  readonly credentialId: string;
  readonly isResidentCredential: boolean;
  readonly rpId?: string;
  readonly privateKey: string;
  readonly userHandle?: string;
  readonly signCount: number;
};

/** One tab's virtual authenticators. */
export interface Authenticators {
  /**
   * Adds a CTAP2, internal-transport authenticator with resident keys and user verification, which approves every
   * ceremony without a prompt. It becomes the device the next ceremony uses, alongside any others still attached.
   *
   * @returns Its authenticator ID.
   * @throws {Error} The CDP call fails (the tab is closed).
   */
  add(): Promise<string>;
  /**
   * Detaches an authenticator; its credentials go with it.
   *
   * @throws {Error} The ID is unknown or the CDP call fails.
   */
  remove(authenticatorId: string): Promise<void>;
  /**
   * Lists the credentials an authenticator holds.
   *
   * @throws {Error} The ID is unknown or the CDP call fails.
   */
  credentials(authenticatorId: string): Promise<readonly VirtualCredential[]>;
  /**
   * Puts a credential (taken from another authenticator with {@link credentials}) into an authenticator, as a passkey
   * provider syncing it to a new device would.
   *
   * @throws {Error} The ID is unknown, the authenticator already holds the credential, or the CDP call fails.
   */
  addCredential(authenticatorId: string, credential: VirtualCredential): Promise<void>;
}

/**
 * Enables the WebAuthn domain on a page's tab.
 *
 * @param page The page; the authenticators stay attached across its navigations.
 * @returns The tab's authenticators, none attached yet.
 * @throws {Error} The CDP session cannot be opened (not Chromium).
 */
export async function virtualAuthenticators(page: Page): Promise<Authenticators> {
  const cdp: CDPSession = await page.context().newCDPSession(page);
  // No browser UI: every ceremony completes as if the user approved it.
  await cdp.send("WebAuthn.enable", { enableUI: false });
  return {
    async add() {
      const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
        options: {
          protocol: "ctap2",
          transport: "internal",
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: true,
          automaticPresenceSimulation: true,
        },
      });
      return authenticatorId;
    },
    async remove(authenticatorId) {
      await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
    },
    async credentials(authenticatorId) {
      const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
      return credentials;
    },
    async addCredential(authenticatorId, credential) {
      await cdp.send("WebAuthn.addCredential", { authenticatorId, credential });
    },
  };
}
