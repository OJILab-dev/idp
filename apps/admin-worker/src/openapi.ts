// The admin API's OpenAPI 3.1 spec, generated from the core's input schemas and the route table
// (docs/design/idpctl.md; docs/design/cross-language-contract.md). It is the Go/TypeScript contract that idpctl's
// types are generated from, checked in at contract/openapi/admin.json and compared in the tests.
import { z } from "zod";
import { enablementEventSchema } from "@idp/core/admin";
import { PROBLEM_KINDS } from "@idp/core/shared";
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
      [String(route.status)]: { description: "Success.", content: { "application/json": { schema: {} } } },
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
        "Served only on the admin host behind mTLS and the certificate allowlist. Every response carries Cache-Control: no-store.",
    },
    paths,
    components: {
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
