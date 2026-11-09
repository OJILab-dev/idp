// The admin API over HTTP (docs/design/idpctl.md, "管理 API の形"). This layer only routes, assembles the input from
// the path, query, and body, and serialises the outcome; every rule, including validation, Idempotency-Key, and the
// audit rows, is the core's, reached through executeOperation exactly once per request.
import { Hono, type Context } from "hono";
import {
  AdminProblem,
  enablementEventSchema,
  enablementOperationName,
  executeOperation,
  findOperation,
  parseInput,
  type AdminContext,
  type AdminIdentity,
  type AdminOperation,
} from "@idp/core/admin";
import { isAcceptedTlsVersion } from "@idp/core/shared";
import { createD1Database } from "@idp/d1-adapter";
import { adminConfig, InvalidConfigError, type AdminConfig, type Env } from "./config.js";
import { isAdminHost, resolveAdmin } from "./gate.js";
import { rs256Enabled } from "./rs256.js";
import { inputField, pathParams, ROUTES, type Route } from "./routes.js";

type AppEnv = { Bindings: Env; Variables: { config: AdminConfig; admin: AdminIdentity } };

// The two operations that may name RS256; only they pay for the discovery subrequest.
const NAMES_ALGORITHM = new Set(["client_create", "client_set_id_token_alg"]);

// One structured line per request (docs/design/deployment.md, "ログ"); never a body, token, or secret.
function log(fields: Readonly<Record<string, unknown>>): void {
  console.log(JSON.stringify(fields));
}

function describe(error: unknown): string {
  const parts: string[] = [];
  for (let e: unknown = error; e !== undefined && parts.length < 5; e = e instanceof Error ? e.cause : undefined) {
    parts.push(e instanceof Error ? `${e.name}: ${e.message}` : String(e));
  }
  return parts.join(" <- ");
}

function problemResponse(problem: AdminProblem): Response {
  const body = problem.toProblemDetails();
  return new Response(JSON.stringify(body), { status: body.status, headers: { "content-type": "application/problem+json" } });
}

// One body for every refusal of the gate, so the response never tells which check failed (idpctl.md, "forbidden").
function forbidden(): Response {
  return problemResponse(new AdminProblem("forbidden", "Forbidden"));
}

function pointer(key: string): string {
  return `/${key.replace(/~/g, "~0").replace(/\//g, "~1")}`;
}

function invalid(detail: string, pointers: readonly string[]): AdminProblem {
  return new AdminProblem("validation-failed", detail, { pointers });
}

/** The pieces of a request, before the operation input is merged from them. */
type RequestParts = {
  readonly path: Readonly<Record<string, string>>;
  readonly query: Readonly<Record<string, string>>;
  readonly body: Readonly<Record<string, unknown>>;
  /** A structural problem; the parts are then as far as they could be read. */
  readonly rejection?: AdminProblem;
};

async function readBody(request: Request): Promise<{ readonly body: Readonly<Record<string, unknown>>; readonly rejection?: AdminProblem }> {
  const text = await request.text();
  // A POST that carries nothing but its path (enrollment-links, secrets) may send no body at all.
  if (text === "") return { body: {} };
  const mediaType = (request.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase();
  if (mediaType !== "application/json") return { body: {}, rejection: invalid("The body must be application/json", [""]) };
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { body: {}, rejection: invalid("The body is not JSON", [""]) };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { body: {}, rejection: invalid("The body must be a JSON object", [""]) };
  }
  return { body: parsed as Record<string, unknown> };
}

async function readParts(c: Context<AppEnv>, route: Route): Promise<RequestParts> {
  const params = c.req.param() as Record<string, string>;
  // Null-prototype records, so a key such as __proto__ is stored as an own member instead of replacing the prototype.
  const path: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const name of pathParams(route.path)) {
    const value = params[name];
    if (value !== undefined) path[inputField(route.path, name)] = value;
  }
  const query: Record<string, string> = Object.create(null) as Record<string, string>;
  let rejection: AdminProblem | undefined;
  for (const [key, value] of new URL(c.req.url).searchParams) {
    // A repeated parameter has no single value for the core's schema to check.
    if (Object.hasOwn(query, key)) rejection ??= invalid("A query parameter is repeated", [pointer(key)]);
    query[key] = value;
  }
  if (route.method === "GET" || route.method === "DELETE") return { path, query, body: {}, ...(rejection === undefined ? {} : { rejection }) };
  const read = await readBody(c.req.raw);
  rejection ??= read.rejection;
  return { path, query, body: read.body, ...(rejection === undefined ? {} : { rejection }) };
}

// No operation input has these members. On an ordinary object, assigning __proto__ replaces the prototype instead
// of adding a member, which would hide it from the duplicate check below and from the core's strict schemas, so
// they are refused by name wherever they appear (a body, a query, or a nested body member the core never reads).
const RESERVED_KEYS: ReadonlySet<string> = new Set(["__proto__", "constructor", "prototype"]);

function plainCopy(input: Readonly<Record<string, unknown>>): Record<string, unknown> {
  // Object.fromEntries defines own members, so the copy keeps exactly the checked members with Object's prototype.
  return Object.fromEntries(Object.entries(input));
}

// The core validates one merged input (idpctl.md, "Idempotency-Key"); a member named by two sources is refused, so
// a body can never redirect the operation to another ID than the path names.
function merge(sources: readonly Readonly<Record<string, unknown>>[]): { readonly input: Record<string, unknown>; readonly rejection?: AdminProblem } {
  const input: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const source of sources) {
    for (const [key, value] of Object.entries(source)) {
      if (RESERVED_KEYS.has(key)) return { input: plainCopy(input), rejection: invalid("A member name is reserved", [pointer(key)]) };
      if (Object.hasOwn(input, key)) return { input: plainCopy(input), rejection: invalid("A member is given more than once", [pointer(key)]) };
      input[key] = value;
    }
  }
  return { input: plainCopy(input) };
}

/** The operation a request runs, its merged input, and any problem found before the core sees it. */
type Planned = { readonly operation: AdminOperation; readonly input: Record<string, unknown>; readonly rejection?: AdminProblem };

function planRequest(route: Route, parts: RequestParts): Planned {
  const [single] = route.operations;
  if (route.enablement === undefined) {
    if (single === undefined) throw new Error(`${route.operationId} has no operation`);
    const merged = merge([parts.path, parts.query, parts.body]);
    const rejection = parts.rejection ?? merged.rejection;
    return { operation: single, input: merged.input, ...(rejection === undefined ? {} : { rejection }) };
  }
  // The body picks enable or disable; until it parses, there is no operation to record a failure under.
  if (parts.rejection !== undefined) throw parts.rejection;
  const body = merge([parts.body]);
  if (body.rejection !== undefined) throw body.rejection;
  const { enablement } = parseInput(enablementEventSchema, body.input);
  const operation = findOperation(enablementOperationName(route.enablement, enablement));
  if (operation === undefined) throw new Error(`${route.operationId} has no ${enablement} operation`);
  const merged = merge([parts.path, parts.query]);
  return { operation, input: merged.input, ...(merged.rejection === undefined ? {} : { rejection: merged.rejection }) };
}

async function handle(c: Context<AppEnv>, route: Route): Promise<Response> {
  const config = c.get("config");
  const admin = c.get("admin");
  const line = { route: route.operationId, admin_name: admin.name };
  let planned: Planned;
  try {
    planned = planRequest(route, await readParts(c, route));
  } catch (error) {
    if (!(error instanceof AdminProblem)) throw error;
    log({ ...line, status: error.toProblemDetails().status, problem: error.kind });
    return problemResponse(error);
  }
  const { operation } = planned;
  const now = Math.floor(Date.now() / 1000);
  const ctx: AdminContext = {
    db: createD1Database(config.db),
    admin,
    writerVersion: config.writerVersion,
    now: () => now,
    rs256Enabled: NAMES_ALGORITHM.has(operation.name)
      ? await rs256Enabled(config.idp, config.issuer, (reason) => log({ ...line, operation: operation.name, rs256: reason }))
      : false,
    issuer: config.issuer,
    onFailureAuditError: (error) => log({ ...line, operation: operation.name, failure_audit_error: describe(error) }),
  };
  try {
    const outcome = await executeOperation(ctx, operation, planned.input, {
      idempotencyKey: c.req.header("idempotency-key"),
      rejection: planned.rejection,
    });
    log({ ...line, operation: operation.name, status: outcome.status, replayed: outcome.replayed });
    return new Response(JSON.stringify(outcome.body), { status: outcome.status, headers: { "content-type": "application/json" } });
  } catch (error) {
    if (!(error instanceof AdminProblem)) throw error;
    log({
      ...line,
      operation: operation.name,
      status: error.toProblemDetails().status,
      problem: error.kind,
      ...(error.kind === "internal" ? { error: describe(error.cause) } : {}),
    });
    return problemResponse(error);
  }
}

/**
 * Builds the admin API application.
 *
 * @returns The Hono app; every request passes the config, host, mTLS, and allowlist checks before routing.
 */
export function createApp(): Hono<AppEnv> {
  const app = new Hono<AppEnv>();

  app.use("*", async (c, next) => {
    let config: AdminConfig;
    try {
      config = adminConfig(c.env);
    } catch (error) {
      if (!(error instanceof InvalidConfigError)) throw error;
      log({ result: "refused", reason: "config", error: error.message });
      return problemResponse(new AdminProblem("internal", "The admin Worker is misconfigured"));
    }
    if (!isAdminHost(new URL(c.req.url), config)) {
      log({ result: "refused", reason: "host" });
      return forbidden();
    }
    // The zone's minimum TLS version is not the IdP's to set when the zone is shared, so TLS below 1.2 is refused
    // here, before the certificate is even looked at (docs/design/idpctl.md, "管理者の認証（mTLS）").
    if (!isAcceptedTlsVersion(c.req.raw.cf)) {
      log({ result: "refused", reason: "tls" });
      return forbidden();
    }
    const gate = resolveAdmin(c.req.raw.cf, config);
    if (!gate.ok) {
      log({ result: "refused", reason: gate.reason, ...(gate.fingerprint === undefined ? {} : { cert_sha256: gate.fingerprint }) });
      return forbidden();
    }
    c.set("config", config);
    c.set("admin", gate.admin);
    await next();
  });

  for (const route of ROUTES) {
    app.on(route.method, route.path.replace(/\{([^}]+)\}/g, ":$1"), (c) => handle(c, route));
  }

  app.notFound(() => problemResponse(new AdminProblem("not-found", "No such endpoint")));
  app.onError((error) => {
    log({ result: "error", error: describe(error) });
    return problemResponse(new AdminProblem("internal", "The request failed", { cause: error }));
  });
  return app;
}
