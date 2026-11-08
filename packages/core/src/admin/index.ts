// Admin use cases (the idpctl operations). Only the admin Worker may import this module.

export type { AccessPair, Principal } from "./access.js";
export {
  MAX_REDIRECT_URIS,
  type ClientCreateResult,
  type ClientRenameResult,
  type ClientRotateSecretResult,
  type ClientSetIdTokenAlgResult,
  type ClientSetRedirectsResult,
  type ClientSummary,
  type IdTokenAlg,
} from "./clients.js";
export { enablementOperationName, type Enablement, type EnablementResource, type EnablementResult } from "./enablement.js";
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
export { IDEMPOTENCY_TTL_SECONDS, canonicalJson, requestHash } from "./idempotency.js";
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
export { decodeCursor, encodeCursor, type Cursor, type CursorKey, type Page } from "./paging.js";
export { AdminProblem, PROBLEM_STATUS, problemType, type ProblemDetails } from "./problem.js";
export { ADMIN_OPERATIONS, findOperation } from "./registry.js";
export { DEFAULT_PAGE_LIMIT, MAX_NAME_LENGTH, MAX_PAGE_LIMIT } from "./schemas.js";
export type { PasskeySummary, SessionRevokeResult, UserCreateResult, UserDetail, UserRenameResult, UserSummary } from "./users.js";
