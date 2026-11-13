// The admin API's OpenAPI 3.1 spec, generated from the core's input schemas and the route table
// (docs/design/idpctl.md; docs/design/cross-language-contract.md). It is the Go/TypeScript contract that idpctl's
// types are generated from, checked in at contract/openapi/admin.json and compared in the tests.
import { z } from "zod";
import { PROBLEM_STATUS, enablementEventSchema, problemType } from "./domain/index.js";
import { PROBLEM_KINDS, type ProblemKind } from "@idp/core/problems";
import { inputField, pathParams, ROUTES, type Route } from "./routes.js";

type JsonSchema = Record<string, unknown>;

type ObjectSchema = { readonly properties: Readonly<Record<string, JsonSchema>>; readonly required: readonly string[] };

// Refinements (the UUIDv4 and client ID checks) have no JSON Schema form and are left to the server; the spec
// describes the input side, so a defaulted member is optional as the client sees it.
function toObjectSchema(schema: z.ZodType): ObjectSchema {
  const json = z.toJSONSchema(schema, { io: "input", unrepresentable: "any" }) as JsonSchema;
  if (json["type"] !== "object") throw new Error("an operation input must be an object schema");
  return {
    properties: (json["properties"] as Record<string, JsonSchema> | undefined) ?? {},
    required: (json["required"] as string[] | undefined) ?? [],
  };
}

function bodySchema(properties: Readonly<Record<string, JsonSchema>>, required: readonly string[]): JsonSchema {
  return { type: "object", properties, ...(required.length === 0 ? {} : { required }), additionalProperties: false };
}

const PROBLEM_RESPONSE = {
  description: "An RFC 9457 problem; branch on `type`.",
  content: { "application/problem+json": { schema: { $ref: "#/components/schemas/Problem" } } },
};

// Only the framework decides these kinds, so they can be narrowed per endpoint without per-operation metadata.
const IDEMPOTENCY_KINDS: ReadonlySet<ProblemKind> = new Set(["idempotency-key-reused", "secret-not-replayable"]);

/**
 * Lists the problem kinds an endpoint can answer, by status. Every endpoint can answer validation-failed, forbidden,
 * not-found, and internal; only writes can conflict (409); only an idempotent POST can answer the idempotency kinds.
 * Within a status the list is the core's, not narrowed per operation: idpctl branches on `type`, never on status.
 */
function problemKindsByStatus(route: Route): ReadonlyMap<number, readonly ProblemKind[]> {
  const write = route.operations.some((operation) => operation.class.access === "write");
  const byStatus = new Map<number, ProblemKind[]>();
  for (const kind of PROBLEM_KINDS) {
    const status = PROBLEM_STATUS[kind];
    if (IDEMPOTENCY_KINDS.has(kind) && !route.idempotent) continue;
    if (status === 409 && !write) continue;
    byStatus.set(status, [...(byStatus.get(status) ?? []), kind]);
  }
  return new Map([...byStatus].sort(([a], [b]) => a - b));
}

// A shared response component per distinct (status, kinds), named by status plus a suffix for a narrower variant,
// so the 27 endpoints reference a handful of components instead of repeating them.
function problemComponentName(status: number, kinds: readonly ProblemKind[]): string {
  const idempotent = kinds.some((kind) => IDEMPOTENCY_KINDS.has(kind));
  return `Problem${status}${status === 409 && idempotent ? "Idempotent" : ""}`;
}

function problemComponent(status: number, kinds: readonly ProblemKind[]): JsonSchema {
  return {
    description: `An RFC 9457 problem of kind ${kinds.join(", ")}.`,
    content: {
      "application/problem+json": {
        schema: {
          allOf: [
            { $ref: "#/components/schemas/Problem" },
            { type: "object", properties: { type: { enum: kinds.map(problemType) }, status: { const: status } } },
          ],
        },
      },
    },
  };
}

function problemResponses(route: Route): Record<string, JsonSchema> {
  const responses: Record<string, JsonSchema> = {};
  for (const [status, kinds] of problemKindsByStatus(route)) {
    responses[String(status)] = { $ref: `#/components/responses/${problemComponentName(status, kinds)}` };
  }
  return responses;
}

function problemComponents(): Record<string, JsonSchema> {
  const components: Record<string, JsonSchema> = {};
  for (const route of ROUTES) {
    for (const [status, kinds] of problemKindsByStatus(route)) {
      const name = problemComponentName(status, kinds);
      const component = problemComponent(status, kinds);
      const existing = components[name];
      // One name must mean one set of kinds; a clash means the naming above no longer captures the variants.
      if (existing !== undefined && JSON.stringify(existing) !== JSON.stringify(component)) throw new Error(`${name} has two variants`);
      components[name] = component;
    }
  }
  return Object.fromEntries(Object.entries(components).sort(([a], [b]) => (a < b ? -1 : 1)));
}

// The output side: what the server sends, so an optional member is one the server may omit.
function outputSchema(route: Route): JsonSchema {
  const schemas = route.operations.map((operation) => {
    const json = z.toJSONSchema(operation.output, { io: "output", unrepresentable: "any" }) as JsonSchema;
    delete json["$schema"];
    return json;
  });
  const [first] = schemas;
  // The enable and disable operations of one endpoint share a result type, so they must share the schema.
  if (first === undefined || schemas.some((s) => JSON.stringify(s) !== JSON.stringify(first))) {
    throw new Error(`${route.operationId} has no single output schema`);
  }
  return first;
}

function operationObject(route: Route): JsonSchema {
  const [first] = route.operations;
  if (first === undefined) throw new Error(`${route.operationId} has no operation`);
  const input = toObjectSchema(first.input);
  const names = pathParams(route.path);
  const pathFields = new Set(names.map((name) => inputField(route.path, name)));
  const parameters: JsonSchema[] = names.map((name) => ({
    name,
    in: "path",
    required: true,
    schema: input.properties[inputField(route.path, name)] ?? { type: "string" },
  }));
  if (route.idempotent) {
    parameters.push({
      name: "Idempotency-Key",
      in: "header",
      required: true,
      description: "32 random bytes as unpadded base64url, reused only by retries of the same request.",
      schema: { type: "string", pattern: "^[A-Za-z0-9_-]{43}$" },
    });
  }
  const rest = Object.entries(input.properties).filter(([key]) => !pathFields.has(key));
  let requestBody: JsonSchema | undefined;
  if (route.enablement !== undefined) {
    const body = toObjectSchema(enablementEventSchema);
    requestBody = { required: true, content: { "application/json": { schema: bodySchema(body.properties, body.required) } } };
  } else if (route.method === "GET" || route.method === "DELETE") {
    for (const [name, schema] of rest) parameters.push({ name, in: "query", required: input.required.includes(name), schema });
  } else if (rest.length > 0) {
    const required = input.required.filter((key) => !pathFields.has(key));
    requestBody = { required: true, content: { "application/json": { schema: bodySchema(Object.fromEntries(rest), required) } } };
  }
  return {
    operationId: route.operationId,
    "x-operation-names": route.operations.map((o) => o.name),
    ...(parameters.length === 0 ? {} : { parameters }),
    ...(requestBody === undefined ? {} : { requestBody }),
    responses: {
      [String(route.status)]: { description: "Success.", content: { "application/json": { schema: outputSchema(route) } } },
      ...problemResponses(route),
      default: PROBLEM_RESPONSE,
    },
  };
}

/**
 * Builds the OpenAPI document.
 *
 * @returns The OpenAPI 3.1 document as plain JSON.
 */
export function buildOpenApiDocument(): JsonSchema {
  const paths: Record<string, Record<string, JsonSchema>> = {};
  for (const route of ROUTES) {
    paths[route.path] = { ...paths[route.path], [route.method.toLowerCase()]: operationObject(route) };
  }
  return {
    openapi: "3.1.0",
    info: {
      title: "ojilab idp admin API",
      version: "1",
      description:
        "Served only on the admin host. Every request carries an RFC 9421 signature by an allowlisted ECDSA P-384 key; an unsigned or invalid request gets forbidden, and a rate-limited one a bodyless 429. Every response carries Cache-Control: no-store.",
    },
    paths,
    components: {
      responses: problemComponents(),
      schemas: {
        Problem: {
          type: "object",
          properties: {
            type: { type: "string", enum: PROBLEM_KINDS.map((kind) => `urn:ojilab:idp:problem:${kind}`) },
            title: { type: "string" },
            status: { type: "integer" },
            detail: { type: "string" },
            errors: { type: "array", items: { type: "string" }, description: "JSON Pointers of the failing input members (validation-failed only)." },
          },
          required: ["type", "title", "status", "detail"],
          additionalProperties: false,
        },
      },
    },
  };
}

/**
 * Renders the document as the checked-in file: two-space JSON with a trailing newline.
 *
 * @returns The file content.
 */
export function renderOpenApi(): string {
  return `${JSON.stringify(buildOpenApiDocument(), null, 2)}\n`;
}
