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
} from "./domain/index.js";
import { createD1Database } from "@idp/cloudflare/d1";
import { adminConfig, InvalidConfigError, type AdminConfig, type Env } from "./config.js";
import { admitRequest } from "./gate.js";
import { inputField, pathParams, ROUTES, type Route } from "./routes.js";

/** What the gate hands to the routes: the configuration, the admin, the clock, and the body it already read. */
type AppEnv = { Bindings: Env; Variables: { config: AdminConfig; admin: AdminIdentity; now: number; body: Uint8Array } };

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

// The body is the bytes the gate read and whose digest the signature covers, never a second read of the request.
function readBody(request: Request, bytes: Uint8Array): { readonly body: Readonly<Record<string, unknown>>; readonly rejection?: AdminProblem } {
  // A POST that carries nothing but its path (enrollment-links, secrets) may send no body at all.
  if (bytes.length === 0) return { body: {} };
  const mediaType = (request.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase();
  if (mediaType !== "application/json") return { body: {}, rejection: invalid("The body must be application/json", [""]) };
  let parsed: unknown;
  try {
    // fatal: bytes that are not UTF-8 are refused, not replaced; ignoreBOM keeps a BOM, which JSON.parse refuses. The
    // operation sees exactly the bytes that were signed.
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes));
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
  const read = readBody(c.req.raw, c.get("body"));
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
  // The clock the signature was checked against, so the window and the operation see the same second.
  const now = c.get("now");
  const ctx: AdminContext = {
    db: createD1Database(config.db),
    admin,
    writerVersion: config.writerVersion,
    now: () => now,
    rs256Enabled: config.rs256Enabled,
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
 * @returns The Hono app; every request passes the configuration check and the gate (host, TLS, rate limit, body
 *   size, RFC 9421 signature, nonce) before routing, so an unknown path is refused like any other request.
 */
export function createApp(): Hono<AppEnv> {
  const app = new Hono<AppEnv>();

  app.use("*", async (c, next) => {
    let config: AdminConfig;
    try {
      config = await adminConfig(c.env);
    } catch (error) {
      if (!(error instanceof InvalidConfigError)) throw error;
      log({ result: "refused", reason: "config", error: error.message });
      return problemResponse(new AdminProblem("internal", "The admin Worker is misconfigured"));
    }
    const now = Math.floor(Date.now() / 1000);
    const gate = await admitRequest(c.req.raw, config, now);
    if (!gate.ok) {
      if ("limited" in gate) {
        log({ result: "refused", reason: "rate_limited" });
        // No problem details and no Retry-After: idpctl does not retry a 429 (docs/design/hosting-modes.md 3.8).
        return new Response(null, { status: 429 });
      }
      if ("internal" in gate) {
        log({ result: "refused", reason: "internal", error: gate.internal });
        return problemResponse(new AdminProblem("internal", "The admin gate failed"));
      }
      // The reason and the claimed keyid go to the log only; the response is the same for every refusal.
      log({ result: "refused", reason: gate.refusal, ...(gate.keyid === undefined ? {} : { keyid: gate.keyid }) });
      return forbidden();
    }
    c.set("config", config);
    c.set("admin", gate.admin);
    c.set("now", now);
    c.set("body", gate.body);
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
