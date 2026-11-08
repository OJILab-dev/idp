// Rules used by both the user-facing and the admin use cases.
// Neither src/user nor src/admin may be imported from here (eslint.config.js).

/**
 * The most passkeys one user may have (`max_passkeys_per_user` in docs/design/cross-language-contract.md).
 *
 * A provisional value, not one any specification sets; contract/testdata/vectors.json holds the same value.
 */
export const MAX_PASSKEYS_PER_USER = 10;
