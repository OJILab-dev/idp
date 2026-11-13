// Admin use cases (the idpctl operations). Only the admin Worker may import this module.

export type { AccessPair, Principal } from "./access.js";
export type { AuditEvent } from "./audit-tail.js";
export { ENROLL_LINK_TTL_SECONDS, type EnrollLinkIssueResult } from "./passkeys.js";
export {
  MAX_REDIRECT_URIS,
  type ClientCreateResult,
  type ClientRenameResult,
  type ClientRotateSecretResult,
  type ClientSetIdTokenAlgResult,
  type ClientSetPostLogoutRedirectsResult,
  type ClientSetRedirectsResult,
  type ClientSummary,
  type IdTokenAlg,
} from "./clients.js";
export { enablementEventSchema, enablementOperationName, type Enablement, type EnablementResource, type EnablementResult } from "./enablement.js";
export { executeOperation, type ExecuteOptions } from "./execute.js";
export type {
  AccessCheckResult,
  AccessDenialReason,
  AccessGrant,
  GrantAddResult,
  GrantRemoveResult,
  GrantSummary,
  PrincipalRef,
} from "./grants.js";
export type { GroupCreateResult, GroupMemberAddResult, GroupRenameResult, GroupSummary } from "./groups.js";
export { IDEMPOTENCY_TTL_SECONDS, requestHash } from "./idempotency.js";
export {
  OPERATION_NAMES,
  type AdminContext,
  type AdminIdentity,
  type AdminOperation,
  type Concern,
  type HttpMapping,
  type OperationBase,
  type OperationClass,
  type OperationName,
  type OperationOutcome,
  type PlanOutcome,
  type ReadOperation,
  type TargetSpec,
  type WriteOperation,
  type WritePlan,
} from "./operation.js";
export { AdminNonceStoreError, adminNonceClaimStatements, type AdminNonceClaim, type AdminNonceStore } from "./nonces.js";
export {
  ADMIN_SIGNATURE_TAG,
  ADMIN_SIGNATURE_WINDOW_SECONDS,
  verifyAdminSignature,
  type AdminSignatureRefusal,
  type AdminSignatureRequest,
  type AdminSignatureResult,
  type AdminSigningKey,
  type VerifiedAdminSignature,
} from "./signature.js";
export { decodeCursor, encodeCursor, type Cursor, type CursorKey, type Page } from "./paging.js";
export { AdminProblem, PROBLEM_STATUS, problemType, type ProblemDetails } from "./problem.js";
export { ADMIN_OPERATIONS, findOperation } from "./registry.js";
export { DEFAULT_PAGE_LIMIT, MAX_NAME_LENGTH, MAX_PAGE_LIMIT, parseInput } from "./schemas.js";
export type { PasskeySummary, SessionRevokeResult, UserCreateResult, UserDetail, UserRenameResult, UserSummary } from "./users.js";
