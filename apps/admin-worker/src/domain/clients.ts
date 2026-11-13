// RP management (docs/design/idpctl.md, docs/design/clients.md): register, rename, set redirect URIs, rotate the
// secret, set the ID token algorithm, enable and disable, and list. Clients are never deleted, so a client ID is
// never reused.
import { clientCreateOutput, clientRenameOutput, clientRotateSecretOutput, clientSetIdTokenAlgOutput, clientSetPostLogoutRedirectsOutput, clientSetRedirectsOutput, clientsListOutput } from "./outputs.js";
import { z } from "zod";
import { sha256Base64url } from "@idp/jwk-thumbprint";
import {
  POST_LOGOUT_REDIRECT_URI_RULES,
  classifyRedirectUri,
  isPostLogoutRedirectUriRegistrable,
  isRedirectUriAllowed,
  type ClientType,
} from "@idp/core/clients";
import { randomToken } from "@idp/core/identifiers";
import type { SqlCondition, SqlRow } from "@idp/core/db";
import { enablementOperation, type Enablement } from "./enablement.js";
import type { AdminContext, ReadOperation, WriteOperation } from "./operation.js";
import { readPage, type Page, type PageQuery } from "./paging.js";
import { AdminProblem } from "./problem.js";
import { clientIdSchema, nameSchema, pageInputShape, type PageInput } from "./schemas.js";

/** The most redirect URIs one client may register. */
export const MAX_REDIRECT_URIS = 10;

/** The ID token signing algorithms a client may register (docs/design/tokens.md). */
export type IdTokenAlg = "Ed25519" | "RS256";

const idTokenAlgSchema = z.enum(["Ed25519", "RS256"]);

const redirectUrisSchema = z
  .array(z.string().refine((uri) => classifyRedirectUri(uri) !== null, { message: "must be a registrable redirect URI" }))
  .min(1)
  .max(MAX_REDIRECT_URIS)
  .refine((uris) => new Set(uris).size === uris.length, { message: "must not repeat a URI" });

/** The most post-logout redirect URIs one client may register; the same bound as the redirect URIs. */
export const MAX_POST_LOGOUT_REDIRECT_URIS = 10;

// RP-Initiated Logout 1.0 §3.1 (authentication.md, "RP からのログアウト"): the https form of the redirect URI rules,
// for every client type. A post-logout redirect carries no code, so the loopback and custom-scheme forms native apps
// need are not admitted; zero URIs (no redirect) is allowed. The rule itself, including the ban on a `state` query
// parameter, is isPostLogoutRedirectUriRegistrable, shared with the audit check.
const postLogoutRedirectUrisSchema = z
  .array(z.string().refine(isPostLogoutRedirectUriRegistrable, { message: `must be ${POST_LOGOUT_REDIRECT_URI_RULES}` }))
  .max(MAX_POST_LOGOUT_REDIRECT_URIS)
  .refine((uris) => new Set(uris).size === uris.length, { message: "must not repeat a URI" })
  .describe(`Up to ${MAX_POST_LOGOUT_REDIRECT_URIS} distinct URIs, each ${POST_LOGOUT_REDIRECT_URI_RULES}.`);

function redirectTypeProblem(uris: readonly string[], clientType: ClientType): AdminProblem | undefined {
  const pointers = uris.flatMap((uri, i) => (isRedirectUriAllowed(uri, clientType) ? [] : [`/redirect_uris/${i}`]));
  if (pointers.length === 0) return undefined;
  return new AdminProblem("validation-failed", "A confidential client may register only https redirect URIs", { pointers });
}

// Fail-closed (idpctl.md): the caller passes rs256Enabled = false when it cannot tell from the IdP Worker's discovery.
function requireAlgorithmEnabled(ctx: AdminContext, alg: IdTokenAlg): void {
  if (alg === "RS256" && !ctx.rs256Enabled) {
    throw new AdminProblem("algorithm-disabled", "RS256 ID tokens are not enabled in this deployment");
  }
}

type ClientCreateInput = {
  readonly client_id: string;
  readonly name: string;
  readonly client_type: ClientType;
  readonly redirect_uris: readonly string[];
  readonly post_logout_redirect_uris: readonly string[];
  readonly id_token_alg: IdTokenAlg;
};

/** The result of client_create; `client_secret` is present, once, only for a confidential client. */
export type ClientCreateResult = {
  readonly client_id: string;
  readonly client_type: ClientType;
  readonly client_secret?: string;
};

/**
 * client_create: registers a client with its first `enabled` event. A confidential client's secret is generated
 * here, returned once, and stored only as its hash; such a response is never kept for Idempotency-Key replay.
 * The ID token algorithm is always written explicitly, Ed25519 when not given (OIDC DCR §2 defaults to RS256).
 */
export const clientCreate: WriteOperation<ClientCreateInput, ClientCreateResult> = {
  name: "client_create",
  class: { access: "write", concern: "rp" },
  establishesIdentity: false,
  idempotent: true,
  target: { kind: "client", field: "client_id" },
  input: z
    .strictObject({
      client_id: clientIdSchema,
      name: nameSchema,
      client_type: z.enum(["confidential", "public"]),
      redirect_uris: redirectUrisSchema,
      post_logout_redirect_uris: postLogoutRedirectUrisSchema.default([]),
      id_token_alg: idTokenAlgSchema.default("Ed25519"),
    })
    .superRefine((value, ctx) => {
      value.redirect_uris.forEach((uri, i) => {
        if (!isRedirectUriAllowed(uri, value.client_type)) {
          ctx.addIssue({ code: "custom", message: "confidential clients may register only https", path: ["redirect_uris", i] });
        }
      });
    }),
  http: { method: "POST", path: "/v1/clients", status: 201 },
  output: clientCreateOutput,
  async plan(ctx, input) {
    requireAlgorithmEnabled(ctx, input.id_token_alg);
    const now = ctx.now();
    const id = input.client_id;
    const secret = input.client_type === "confidential" ? randomToken() : undefined;
    const secretHash = secret === undefined ? null : await sha256Base64url(secret);
    const guard = { sql: "NOT EXISTS (SELECT 1 FROM clients WHERE id = ?)", params: [id] };
    // A client that existed before has at least its first event, so "no event yet" identifies the row just inserted.
    const created: SqlCondition = {
      sql: "EXISTS (SELECT 1 FROM clients WHERE id = ?) AND NOT EXISTS (SELECT 1 FROM client_enablement_events WHERE client_id = ?)",
      params: [id, id],
    };
    const result: ClientCreateResult =
      secret === undefined ? { client_id: id, client_type: input.client_type } : { client_id: id, client_type: input.client_type, client_secret: secret };
    return {
      target: `client:${id}`,
      probe: { sql: "SELECT EXISTS (SELECT 1 FROM clients WHERE id = ?) AS taken", params: [id] },
      guard,
      writes: [
        {
          sql:
            "INSERT INTO clients (id, name, client_type, secret_hash, redirect_uris_json, post_logout_redirect_uris_json, " +
            `id_token_signed_response_alg, created_at) SELECT ?, ?, ?, ?, ?, ?, ?, ? WHERE ${guard.sql}`,
          params: [
            id,
            input.name,
            input.client_type,
            secretHash,
            JSON.stringify(input.redirect_uris),
            JSON.stringify(input.post_logout_redirect_uris),
            input.id_token_alg,
            now,
            ...guard.params,
          ],
        },
        {
          sql: `INSERT INTO client_enablement_events (client_id, enablement, occurred_at) SELECT ?, 'enabled', ? WHERE ${created.sql}`,
          params: [id, now, ...created.params],
        },
      ],
      // An empty post-logout list is the default, so it is recorded only when one was given (idpctl.md).
      detail: {
        client_type: input.client_type,
        id_token_alg: input.id_token_alg,
        redirect_uris: input.redirect_uris,
        ...(input.post_logout_redirect_uris.length === 0 ? {} : { post_logout_redirect_uris: input.post_logout_redirect_uris }),
      },
      secret: secret !== undefined,
      settle(probe) {
        if (probe["taken"] === 1) throw new AdminProblem("already-exists", "A client with this ID already exists");
        return "write";
      },
      result: () => result,
    };
  },
};

/** The result of client_rename. */
export type ClientRenameResult = { readonly client_id: string; readonly name: string };

/** client_rename: changes the display name; the audit row records only that a rename happened. */
export const clientRename: WriteOperation<{ readonly client_id: string; readonly name: string }, ClientRenameResult> = {
  name: "client_rename",
  class: { access: "write", concern: "rp" },
  establishesIdentity: false,
  idempotent: false,
  target: { kind: "client", field: "client_id" },
  input: z.strictObject({ client_id: clientIdSchema, name: nameSchema }),
  http: { method: "PUT", path: "/v1/clients/{id}/name", status: 200 },
  output: clientRenameOutput,
  async plan(_ctx, input) {
    const id = input.client_id;
    const guard = { sql: "EXISTS (SELECT 1 FROM clients WHERE id = ? AND name IS NOT ?)", params: [id, input.name] };
    return {
      target: `client:${id}`,
      probe: {
        sql: "SELECT EXISTS (SELECT 1 FROM clients WHERE id = ?) AS found, EXISTS (SELECT 1 FROM clients WHERE id = ? AND name = ?) AS same",
        params: [id, id, input.name],
      },
      guard,
      writes: [{ sql: "UPDATE clients SET name = ? WHERE id = ? AND name IS NOT ?", params: [input.name, id, input.name] }],
      detail: {},
      settle(probe) {
        if (probe["found"] !== 1) throw new AdminProblem("not-found", "The client does not exist");
        return probe["same"] === 1 ? "noop" : "write";
      },
      result: () => ({ client_id: id, name: input.name }),
    };
  },
};

/** The result of client_set_redirects. */
export type ClientSetRedirectsResult = { readonly client_id: string; readonly redirect_uris: readonly string[] };

async function readClientType(ctx: AdminContext, id: string): Promise<ClientType> {
  const [result] = await ctx.db.batch([{ sql: "SELECT client_type FROM clients WHERE id = ?", params: [id] }]);
  const type = result?.rows[0]?.["client_type"];
  if (type === undefined) throw new AdminProblem("not-found", "The client does not exist");
  return type as ClientType;
}

/**
 * client_set_redirects: replaces the redirect URI list, checked against the client's type. The same list (same
 * order) succeeds without writing. The new list is recorded: redirect URIs carry no personal data (data-model.md).
 */
export const clientSetRedirects: WriteOperation<
  { readonly client_id: string; readonly redirect_uris: readonly string[] },
  ClientSetRedirectsResult
> = {
  name: "client_set_redirects",
  class: { access: "write", concern: "rp" },
  establishesIdentity: false,
  idempotent: false,
  target: { kind: "client", field: "client_id" },
  input: z.strictObject({ client_id: clientIdSchema, redirect_uris: redirectUrisSchema }),
  http: { method: "PUT", path: "/v1/clients/{id}/redirect-uris", status: 200 },
  output: clientSetRedirectsOutput,
  async plan(ctx, input) {
    const id = input.client_id;
    const clientType = await readClientType(ctx, id);
    const problem = redirectTypeProblem(input.redirect_uris, clientType);
    if (problem !== undefined) throw problem;
    const json = JSON.stringify(input.redirect_uris);
    // client_type never changes, but repeating it keeps the type check and the write in one condition.
    const guard = {
      sql: "EXISTS (SELECT 1 FROM clients WHERE id = ? AND client_type = ? AND redirect_uris_json IS NOT ?)",
      params: [id, clientType, json],
    };
    return {
      target: `client:${id}`,
      probe: {
        sql: "SELECT EXISTS (SELECT 1 FROM clients WHERE id = ?) AS found, EXISTS (SELECT 1 FROM clients WHERE id = ? AND redirect_uris_json = ?) AS same",
        params: [id, id, json],
      },
      guard,
      writes: [{ sql: `UPDATE clients SET redirect_uris_json = ? WHERE id = ? AND ${guard.sql}`, params: [json, id, ...guard.params] }],
      detail: { redirect_uris: input.redirect_uris },
      settle(probe) {
        if (probe["found"] !== 1) throw new AdminProblem("not-found", "The client does not exist");
        return probe["same"] === 1 ? "noop" : "write";
      },
      result: () => ({ client_id: id, redirect_uris: input.redirect_uris }),
    };
  },
};

/** The result of client_set_post_logout_redirects. */
export type ClientSetPostLogoutRedirectsResult = { readonly client_id: string; readonly post_logout_redirect_uris: readonly string[] };

/**
 * client_set_post_logout_redirects: replaces the RP-Initiated Logout post-logout redirect URI list (https only, for
 * every client type). An empty list stops post-logout redirects; the same list (same order) succeeds without writing.
 * The new list is recorded, like the redirect URIs.
 */
export const clientSetPostLogoutRedirects: WriteOperation<
  { readonly client_id: string; readonly post_logout_redirect_uris: readonly string[] },
  ClientSetPostLogoutRedirectsResult
> = {
  name: "client_set_post_logout_redirects",
  class: { access: "write", concern: "rp" },
  establishesIdentity: false,
  idempotent: false,
  target: { kind: "client", field: "client_id" },
  input: z.strictObject({ client_id: clientIdSchema, post_logout_redirect_uris: postLogoutRedirectUrisSchema }),
  http: { method: "PUT", path: "/v1/clients/{id}/post-logout-redirect-uris", status: 200 },
  output: clientSetPostLogoutRedirectsOutput,
  async plan(_ctx, input) {
    const id = input.client_id;
    const json = JSON.stringify(input.post_logout_redirect_uris);
    const guard = { sql: "EXISTS (SELECT 1 FROM clients WHERE id = ? AND post_logout_redirect_uris_json IS NOT ?)", params: [id, json] };
    return {
      target: `client:${id}`,
      probe: {
        sql:
          "SELECT EXISTS (SELECT 1 FROM clients WHERE id = ?) AS found, " +
          "EXISTS (SELECT 1 FROM clients WHERE id = ? AND post_logout_redirect_uris_json = ?) AS same",
        params: [id, id, json],
      },
      guard,
      writes: [
        {
          sql: "UPDATE clients SET post_logout_redirect_uris_json = ? WHERE id = ? AND post_logout_redirect_uris_json IS NOT ?",
          params: [json, id, json],
        },
      ],
      detail: { post_logout_redirect_uris: input.post_logout_redirect_uris },
      settle(probe) {
        if (probe["found"] !== 1) throw new AdminProblem("not-found", "The client does not exist");
        return probe["same"] === 1 ? "noop" : "write";
      },
      result: () => ({ client_id: id, post_logout_redirect_uris: input.post_logout_redirect_uris }),
    };
  },
};

/** The result of client_rotate_secret; the secret is returned once and never stored in plain text. */
export type ClientRotateSecretResult = { readonly client_id: string; readonly client_secret: string };

/**
 * client_rotate_secret: replaces a confidential client's secret, so the old one stops working at once. A public
 * client has no secret and is state-conflict.
 */
export const clientRotateSecret: WriteOperation<{ readonly client_id: string }, ClientRotateSecretResult> = {
  name: "client_rotate_secret",
  class: { access: "write", concern: "rp" },
  establishesIdentity: false,
  idempotent: true,
  target: { kind: "client", field: "client_id" },
  input: z.strictObject({ client_id: clientIdSchema }),
  http: { method: "POST", path: "/v1/clients/{id}/secrets", status: 201 },
  output: clientRotateSecretOutput,
  async plan(_ctx, input) {
    const id = input.client_id;
    const secret = randomToken();
    const hash = await sha256Base64url(secret);
    const guard = { sql: "EXISTS (SELECT 1 FROM clients WHERE id = ? AND client_type = 'confidential')", params: [id] };
    return {
      target: `client:${id}`,
      probe: { sql: "SELECT (SELECT client_type FROM clients WHERE id = ?) AS client_type", params: [id] },
      guard,
      writes: [{ sql: "UPDATE clients SET secret_hash = ? WHERE id = ? AND client_type = 'confidential'", params: [hash, id] }],
      detail: {},
      secret: true,
      settle(probe) {
        if (probe["client_type"] === null) throw new AdminProblem("not-found", "The client does not exist");
        if (probe["client_type"] !== "confidential") throw new AdminProblem("state-conflict", "A public client has no secret");
        return "write";
      },
      result: () => ({ client_id: id, client_secret: secret }),
    };
  },
};

/** The result of client_set_id_token_alg. */
export type ClientSetIdTokenAlgResult = { readonly client_id: string; readonly id_token_alg: IdTokenAlg };

/**
 * client_set_id_token_alg: changes the ID token algorithm, recording the old and new values. RS256 is rejected when
 * the deployment has not enabled it; the same value succeeds without writing.
 */
export const clientSetIdTokenAlg: WriteOperation<{ readonly client_id: string; readonly id_token_alg: IdTokenAlg }, ClientSetIdTokenAlgResult> = {
  name: "client_set_id_token_alg",
  class: { access: "write", concern: "rp" },
  establishesIdentity: false,
  idempotent: false,
  target: { kind: "client", field: "client_id" },
  input: z.strictObject({ client_id: clientIdSchema, id_token_alg: idTokenAlgSchema }),
  http: { method: "PUT", path: "/v1/clients/{id}/id-token-alg", status: 200 },
  output: clientSetIdTokenAlgOutput,
  async plan(ctx, input) {
    requireAlgorithmEnabled(ctx, input.id_token_alg);
    const id = input.client_id;
    const alg = input.id_token_alg;
    const guard = { sql: "EXISTS (SELECT 1 FROM clients WHERE id = ? AND id_token_signed_response_alg IS NOT ?)", params: [id, alg] };
    return {
      target: `client:${id}`,
      probe: { sql: "SELECT (SELECT id_token_signed_response_alg FROM clients WHERE id = ?) AS alg", params: [id] },
      guard,
      writes: [{ sql: "UPDATE clients SET id_token_signed_response_alg = ? WHERE id = ? AND id_token_signed_response_alg IS NOT ?", params: [alg, id, alg] }],
      // There are two algorithms, so a write that happens always comes from the other one.
      detail: { previous_id_token_alg: alg === "Ed25519" ? "RS256" : "Ed25519", id_token_alg: alg },
      settle(probe) {
        if (probe["alg"] === null) throw new AdminProblem("not-found", "The client does not exist");
        return probe["alg"] === alg ? "noop" : "write";
      },
      result: () => ({ client_id: id, id_token_alg: alg }),
    };
  },
};

/** client_disable: appends `disabled`; grants and redirect URIs stay, so client_enable restores the client. */
export const clientDisable = enablementOperation("client", "disabled");

/** client_enable: appends `enabled`. */
export const clientEnable = enablementOperation("client", "enabled");

/** One client in clients_list. */
export type ClientSummary = {
  readonly client_id: string;
  readonly name: string;
  readonly client_type: ClientType;
  readonly enablement: Enablement;
  readonly redirect_uris: readonly string[];
  readonly post_logout_redirect_uris: readonly string[];
  readonly id_token_alg: IdTokenAlg;
  readonly created_at: number;
};

type ClientsListInput = PageInput & { readonly id_token_alg?: IdTokenAlg | undefined };

function clientsPage(input: ClientsListInput): PageQuery {
  return {
    columns:
      "c.id, c.name, c.client_type, c.redirect_uris_json, c.post_logout_redirect_uris_json, c.id_token_signed_response_alg, c.created_at, " +
      "COALESCE(ce.enablement, 'disabled') AS enablement",
    from: "clients c LEFT JOIN client_enablement ce ON ce.client_id = c.id",
    filters: input.id_token_alg === undefined ? [] : [{ sql: "c.id_token_signed_response_alg = ?", params: [input.id_token_alg] }],
    key: [
      { sql: "c.created_at", column: "created_at", type: "integer" },
      { sql: "c.id", column: "id", type: "text" },
    ],
    order: "asc",
  };
}

function toClientSummary(row: SqlRow): ClientSummary {
  return {
    client_id: row["id"] as string,
    name: row["name"] as string,
    client_type: row["client_type"] as ClientType,
    enablement: row["enablement"] as Enablement,
    redirect_uris: JSON.parse(row["redirect_uris_json"] as string) as string[],
    post_logout_redirect_uris: JSON.parse(row["post_logout_redirect_uris_json"] as string) as string[],
    id_token_alg: row["id_token_signed_response_alg"] as IdTokenAlg,
    created_at: row["created_at"] as number,
  };
}

/** clients_list: clients in creation order; `id_token_alg` filters, so RS256 clients can be found before disabling RS256. */
export const clientsList: ReadOperation<ClientsListInput, Page<ClientSummary>> = {
  name: "clients_list",
  class: { access: "read" },
  establishesIdentity: false,
  input: z.strictObject({ ...pageInputShape, id_token_alg: idTokenAlgSchema.optional() }),
  http: { method: "GET", path: "/v1/clients", status: 200 },
  output: clientsListOutput,
  read: (ctx, input) => readPage(ctx.db, clientsPage(input), input, toClientSummary),
};
