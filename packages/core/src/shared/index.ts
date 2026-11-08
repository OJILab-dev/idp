// Rules used by both the user-facing and the admin use cases.
// Neither src/user nor src/admin may be imported from here (eslint.config.js).

export {
  AUDIT_DETAIL_COMPUTED_KEYS,
  InvalidAuditRowError,
  auditFailureStatement,
  auditSuccessStatement,
  isAuditTarget,
  type AuditActor,
  type AuditComputedMember,
  type AuditDetail,
  type AuditDetailValue,
  type AuditFailureRow,
  type AuditSuccessRow,
  type AuditTarget,
  type SqlCondition,
} from "./audit.js";
export { InvalidBase64urlError, base64urlDecode, base64urlEncode } from "./base64url.js";
export { DatabaseError, type Database, type SqlRow, type SqlStatement, type SqlStatementResult, type SqlValue } from "./db.js";
export { sha256Base64url } from "./hash.js";
export { isClientId, isRandomTokenFormat, isUuidV4, newUuidV4, randomToken } from "./identifiers.js";
export { InvalidIssuerError, parseIssuer, type Issuer } from "./issuer.js";
export { InvalidJwkError, jwkThumbprint } from "./jwk.js";
export { PROBLEM_KINDS, isProblemKind, type ProblemKind } from "./problems.js";

/**
 * The most passkeys one user may have (`max_passkeys_per_user` in docs/design/cross-language-contract.md).
 *
 * A provisional value, not one any specification sets; contract/testdata/vectors.json holds the same value.
 */
export const MAX_PASSKEYS_PER_USER = 10;
