// The operation registry: every admin operation with its metadata, in one list. Entry points derive what they
// expose from this list (docs/design/idpctl.md, "操作の分類"); none keeps its own list of operations.
import {
  clientCreate,
  clientDisable,
  clientEnable,
  clientRename,
  clientRotateSecret,
  clientSetIdTokenAlg,
  clientSetPostLogoutRedirects,
  clientSetRedirects,
  clientsList,
} from "./clients.js";
import { auditTail } from "./audit-tail.js";
import { accessCheck, grantAdd, grantRemove, grantsList } from "./grants.js";
import { enrollLinkIssue, passkeyRevoke } from "./passkeys.js";
import { groupCreate, groupDisable, groupEnable, groupMemberAdd, groupMemberRemove, groupRename, groupsList } from "./groups.js";
import type { AdminOperation, OperationName } from "./operation.js";
import { sessionRevoke, userCreate, userDisable, userEnable, userGet, userRename, usersList } from "./users.js";

/** Every admin operation: the 30 of docs/design/idpctl.md, each exactly once. */
export const ADMIN_OPERATIONS: readonly AdminOperation[] = [
  usersList,
  userGet,
  clientsList,
  groupsList,
  grantsList,
  accessCheck,
  auditTail,
  userCreate,
  userRename,
  userDisable,
  userEnable,
  enrollLinkIssue,
  passkeyRevoke,
  sessionRevoke,
  groupCreate,
  groupRename,
  groupDisable,
  groupEnable,
  groupMemberAdd,
  groupMemberRemove,
  clientCreate,
  clientRename,
  clientSetRedirects,
  clientSetPostLogoutRedirects,
  clientRotateSecret,
  clientSetIdTokenAlg,
  clientDisable,
  clientEnable,
  grantAdd,
  grantRemove,
];

/**
 * Finds an operation by name.
 *
 * @param name The operation name.
 * @returns The operation, or undefined when it is not implemented.
 */
export function findOperation(name: OperationName): AdminOperation | undefined {
  return ADMIN_OPERATIONS.find((operation) => operation.name === name);
}
