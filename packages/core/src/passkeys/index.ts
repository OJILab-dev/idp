// The passkey limit and the SQL conditions of the passkey rules, applied by both Workers.
export { MAX_PASSKEYS_PER_USER } from "./limits.js";
export { passkeyBelowLimitCondition, passkeyRevocableCondition, userEnabledCondition } from "./passkey-rules.js";
