// What the OIDC use cases take from the Worker. Time and randomness are ports, so the tests can fix both and every
// expiry and token in a test run is predictable.
import { randomToken, type Database, type Issuer } from "../shared/index.js";
import type { SigningKeySet } from "./signing-keys.js";

/** The current time. */
export interface Clock {
  /**
   * Reads the current time.
   *
   * Every expiry the IdP stores and checks is in these units, so the same clock must drive issuance and checking.
   *
   * @returns UNIX seconds as an integer; never null.
   */
  now(): number;
}

/** The source of the random values the IdP issues (codes, authorize request IDs). */
export interface RandomSource {
  /**
   * Generates one secret value.
   *
   * Not idempotent: each call must return a new value with 256 bits of entropy, because the hash of the value is the
   * row's primary key and the plaintext is the bearer credential.
   *
   * @returns 32 random bytes as unpadded base64url (the contract's token format); never null.
   */
  token(): string;
}

/** The dependencies every OIDC use case takes. */
export type OidcDeps = {
  readonly db: Database;
  readonly issuer: Issuer;
  readonly keys: SigningKeySet;
  readonly clock: Clock;
  readonly random: RandomSource;
};

/** The Worker's clock: the system time in whole seconds. */
export const systemClock: Clock = {
  now(): number {
    return Math.floor(Date.now() / 1000);
  },
};

/** The Worker's random source: the platform CSPRNG. */
export const cryptoRandomSource: RandomSource = {
  token(): string {
    return randomToken();
  },
};
