// Output schemas: the response body of every admin operation, as zod. The admin API's OpenAPI spec is generated from
// them, and idpctl's Go types from that spec (docs/design/idpctl.md, "管理 API の形"). Each operation carries its
// schema as `output: z.ZodType<R>`, so the compiler checks that the schema produces the result type, and a type test
// checks that the two are equal, so a member added to one and not the other fails to build.
// They describe what the server sends; they are not used to validate the core's own results at run time.
import { z } from "zod";

const enablement = z.enum(["enabled", "disabled"]);
const idTokenAlg = z.enum(["Ed25519", "RS256"]);
const clientType = z.enum(["confidential", "public"]);
const unixSeconds = z.int().min(0);
const principalRef = z.union([z.templateLiteral(["user:", z.string()]), z.templateLiteral(["group:", z.string()])]);
const auditTarget = z.union([
  z.templateLiteral(["user:", z.string()]),
  z.templateLiteral(["client:", z.string()]),
  z.templateLiteral(["group:", z.string()]),
  z.literal("schema"),
  z.literal("none"),
]);
const accessPair = z.object({ user_id: z.string(), client_id: z.string() }).readonly();
const stringList = z.array(z.string()).readonly();

/**
 * Builds the schema of one page of a list (docs/design/idpctl.md, "一覧のページング").
 *
 * @param item The schema of one item.
 * @returns `{items, next_cursor, prev_cursor}`, the cursors a string or null.
 */
function page<T extends z.ZodType>(item: T) {
  return z.object({ items: z.array(item).readonly(), next_cursor: z.string().nullable(), prev_cursor: z.string().nullable() }).readonly();
}

/** user_create. */
export const userCreateOutput = z.object({ user_id: z.string() }).readonly();

/** user_rename. */
export const userRenameOutput = z.object({ user_id: z.string(), name: z.string() }).readonly();

/** session_revoke. */
export const sessionRevokeOutput = z.object({ user_id: z.string(), sessions_deleted: z.int().min(0) }).readonly();

const userSummary = z
  .object({ user_id: z.string(), name: z.string(), enablement, created_at: unixSeconds, passkey_count: z.int().min(0) })
  .readonly();

/** users_list. */
export const usersListOutput = page(userSummary);

const passkeySummary = z
  .object({
    credential_id: z.string(),
    created_at: unixSeconds,
    last_used_at: unixSeconds.nullable(),
    created_via: z.enum(["enroll", "self"]),
    backup_eligible: z.boolean(),
    backup_state: z.boolean(),
  })
  .readonly();

/** user_get. */
export const userGetOutput = z
  .object({ user_id: z.string(), name: z.string(), enablement, created_at: unixSeconds, passkeys: z.array(passkeySummary).readonly() })
  .readonly();

/** user_enable, user_disable, client_enable, client_disable, group_enable, group_disable. */
export const enablementOutput = z.object({ id: z.string(), enablement, occurred_at: unixSeconds }).readonly();

/** enroll_link_issue; the link is a secret returned once. */
export const enrollLinkIssueOutput = z.object({ user_id: z.string(), enrollment_link: z.string(), expires_at: unixSeconds }).readonly();

/** passkey_revoke. */
export const passkeyRevokeOutput = z.object({ user_id: z.string(), credential_id: z.string() }).readonly();

/** group_create. */
export const groupCreateOutput = z.object({ group_id: z.string() }).readonly();

/** group_rename. */
export const groupRenameOutput = z.object({ group_id: z.string(), name: z.string() }).readonly();

/** group_member_add. */
export const groupMemberAddOutput = z.object({ group_id: z.string(), user_id: z.string(), newly_enabled: z.array(accessPair).readonly() }).readonly();

/** group_member_remove. */
export const groupMemberRemoveOutput = z.object({ group_id: z.string(), user_id: z.string() }).readonly();

const groupSummary = z
  .object({ group_id: z.string(), name: z.string(), enablement, created_at: unixSeconds, members: stringList, clients: stringList })
  .readonly();

/** groups_list. */
export const groupsListOutput = page(groupSummary);

/** client_create; `client_secret` is present, once, only for a confidential client. */
export const clientCreateOutput = z.object({ client_id: z.string(), client_type: clientType, client_secret: z.string().exactOptional() }).readonly();

/** client_rename. */
export const clientRenameOutput = z.object({ client_id: z.string(), name: z.string() }).readonly();

/** client_set_redirects. */
export const clientSetRedirectsOutput = z.object({ client_id: z.string(), redirect_uris: stringList }).readonly();

/** client_rotate_secret; the secret is returned once. */
export const clientRotateSecretOutput = z.object({ client_id: z.string(), client_secret: z.string() }).readonly();

/** client_set_id_token_alg. */
export const clientSetIdTokenAlgOutput = z.object({ client_id: z.string(), id_token_alg: idTokenAlg }).readonly();

const clientSummary = z
  .object({
    client_id: z.string(),
    name: z.string(),
    client_type: clientType,
    enablement,
    redirect_uris: stringList,
    id_token_alg: idTokenAlg,
    created_at: unixSeconds,
  })
  .readonly();

/** clients_list. */
export const clientsListOutput = page(clientSummary);

/** grant_add. */
export const grantAddOutput = z.object({ client_id: z.string(), principal: principalRef, newly_enabled: z.array(accessPair).readonly() }).readonly();

/** grant_remove. */
export const grantRemoveOutput = z.object({ client_id: z.string(), principal: principalRef }).readonly();

const grantSummary = z.object({ principal: principalRef, client_id: z.string(), created_at: unixSeconds }).readonly();

/** grants_list. */
export const grantsListOutput = page(grantSummary);

const accessGrant = z.discriminatedUnion("via", [
  z.object({ via: z.literal("direct"), principal: principalRef, counts: z.boolean() }).readonly(),
  z.object({ via: z.literal("group"), principal: principalRef, group_enablement: enablement, counts: z.boolean() }).readonly(),
]);

/** access_check. */
export const accessCheckOutput = z
  .object({
    user_id: z.string(),
    client_id: z.string(),
    allowed: z.boolean(),
    user_enablement: enablement,
    client_enablement: enablement,
    grants: z.array(accessGrant).readonly(),
    denied_because: z.array(z.enum(["user-disabled", "client-disabled", "no-grant", "group-disabled"])).readonly(),
  })
  .readonly();

const auditEvent = z
  .object({
    id: z.int().min(1),
    occurred_at: unixSeconds,
    actor: z.enum(["admin", "user", "break_glass"]),
    admin_name: z.string().nullable(),
    admin_cert_sha256: z.string().nullable(),
    writer_version: z.string(),
    operation: z.string(),
    target: auditTarget,
    result: z.enum(["success", "failure"]),
    detail: z.record(z.string(), z.unknown()).readonly(),
  })
  .readonly();

/** audit_tail. */
export const auditTailOutput = page(auditEvent);
