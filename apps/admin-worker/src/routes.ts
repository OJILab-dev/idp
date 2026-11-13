// The admin API's endpoints, derived from the core's registry (docs/design/idpctl.md, "管理 API の形"). The router
// and the OpenAPI spec both read this one table, so neither keeps its own list of operations.
import { ADMIN_OPERATIONS, type AdminOperation, type EnablementResource, type HttpMapping } from "./domain/index.js";

/** One endpoint of the admin API. */
export type Route = {
  readonly method: HttpMapping["method"];
  /** The path template of idpctl.md, with `{name}` parameters. */
  readonly path: string;
  /** The operation name, or `<resource>_enablement_switch` for an enablement-events endpoint. */
  readonly operationId: string;
  /** The one operation of the endpoint, or the enable and disable operations of an enablement-events endpoint. */
  readonly operations: readonly AdminOperation[];
  /** The resource of an enablement-events endpoint, whose body picks the operation; absent elsewhere. */
  readonly enablement?: EnablementResource;
  /** Whether the endpoint requires an Idempotency-Key. */
  readonly idempotent: boolean;
  readonly status: 200 | 201;
};

// The `{id}` of /v1/<resource>/{id} is the resource's own ID; the operation inputs name it by resource.
const RESOURCE_ID_FIELDS: Readonly<Record<string, string>> = { users: "user_id", clients: "client_id", groups: "group_id" };

const ENABLEMENT_RESOURCES: Readonly<Record<string, EnablementResource>> = { users: "user", clients: "client", groups: "group" };

/**
 * Names the operation input field a path parameter fills.
 *
 * @param path The path template.
 * @param param The parameter name in the template.
 * @returns The input field name.
 * @throws {Error} The template's resource has no ID field; the route table is then malformed.
 */
export function inputField(path: string, param: string): string {
  if (param !== "id") return param;
  const field = RESOURCE_ID_FIELDS[path.split("/")[2] ?? ""];
  if (field === undefined) throw new Error(`no ID field for ${path}`);
  return field;
}

/**
 * Lists the parameter names of a path template, in order.
 *
 * @param path The path template.
 * @returns The names between braces.
 */
export function pathParams(path: string): readonly string[] {
  return [...path.matchAll(/\{([^}]+)\}/g)].map((m) => m[1] ?? "");
}

function isWrite(operation: AdminOperation): boolean {
  return operation.class.access === "write";
}

function buildRoutes(): readonly Route[] {
  const groups = new Map<string, AdminOperation[]>();
  for (const operation of ADMIN_OPERATIONS) {
    const key = `${operation.http.method} ${operation.http.path}`;
    groups.set(key, [...(groups.get(key) ?? []), operation]);
  }
  return [...groups.values()].map((operations): Route => {
    const [first] = operations;
    if (first === undefined) throw new Error("empty route");
    const { method, path, status } = first.http;
    const idempotent = isWrite(first) && "idempotent" in first && first.idempotent;
    if (operations.length === 1) return { method, path, operationId: first.name, operations, idempotent, status };
    // Only an enablement-events endpoint may carry two operations (idpctl.md, the REST rule 2).
    const resource = ENABLEMENT_RESOURCES[path.split("/")[2] ?? ""];
    const names = operations.map((o) => o.name).sort();
    if (resource === undefined || !path.endsWith("/enablement-events") || names.join() !== `${resource}_disable,${resource}_enable`) {
      throw new Error(`${method} ${path} maps to more than one operation`);
    }
    return { method, path, operationId: `${resource}_enablement_switch`, operations, enablement: resource, idempotent, status };
  });
}

/** Every endpoint of the admin API, in registry order. */
export const ROUTES: readonly Route[] = buildRoutes();
