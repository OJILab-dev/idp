// The operation registry: every admin operation with its metadata, in one list. Entry points derive what they
// expose from this list (docs/design/idpctl.md, "操作の分類"); none keeps its own list of operations.
import { groupCreate, groupDisable, groupEnable, groupMemberAdd, groupMemberRemove, groupRename, groupsList } from "./groups.js";
import type { AdminOperation, OperationName } from "./operation.js";
import { sessionRevoke, userCreate, userDisable, userEnable, userGet, userRename, usersList } from "./users.js";

/** Every implemented admin operation. */
export const ADMIN_OPERATIONS: readonly AdminOperation[] = [
  usersList,
  userGet,
  groupsList,
  userCreate,
  userRename,
  userDisable,
  userEnable,
  sessionRevoke,
  groupCreate,
  groupRename,
  groupDisable,
  groupEnable,
  groupMemberAdd,
  groupMemberRemove,
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
