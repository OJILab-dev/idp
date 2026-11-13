// The OpenAPI spec is the Go/TypeScript contract (docs/design/cross-language-contract.md); it is generated from the
// core's schemas and checked in, so a schema change that is not regenerated fails here.
// Regenerate with `pnpm run openapi:generate`.
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { PROBLEM_KINDS } from "@idp/core/shared";
import { OPERATION_NAMES } from "@idp/core/admin";
import { buildOpenApiDocument, renderOpenApi } from "../src/openapi.js";

const SPEC_PATH = join(import.meta.dirname, "..", "..", "..", "contract", "openapi", "admin.json");

type Operation = {
  readonly operationId: string;
  readonly parameters?: readonly { readonly name: string; readonly in: string; readonly required?: boolean }[];
  readonly "x-operation-names": readonly string[];
};

function operations(): readonly (Operation & { readonly method: string; readonly path: string })[] {
  const doc = buildOpenApiDocument() as { paths: Record<string, Record<string, Operation>> };
  return Object.entries(doc.paths).flatMap(([path, methods]) => Object.entries(methods).map(([method, op]) => ({ ...op, method, path })));
}

describe("the OpenAPI spec", () => {
  it("matches the checked-in contract/openapi/admin.json", () => {
    const rendered = renderOpenApi();
    if (process.env["UPDATE_OPENAPI"] === "1") writeFileSync(SPEC_PATH, rendered);
    expect(readFileSync(SPEC_PATH, "utf8")).toBe(rendered);
  });

  it("has one operationId per endpoint, covering every operation name", () => {
    const ops = operations();
    const ids = ops.map((o) => o.operationId);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ops.flatMap((o) => o["x-operation-names"]).sort()).toEqual([...OPERATION_NAMES].sort());
    for (const op of ops) {
      if (op["x-operation-names"].length === 1) expect(op.operationId).toBe(op["x-operation-names"][0]);
      else expect(op.operationId).toMatch(/^(user|client|group)_enablement_switch$/);
    }
  });

  it("declares every path template parameter as a required path parameter", () => {
    for (const op of operations()) {
      const names = [...op.path.matchAll(/\{([^}]+)\}/g)].map((m) => m[1]);
      const path = (op.parameters ?? []).filter((p) => p.in === "path");
      expect(path.map((p) => p.name)).toEqual(names);
      expect(path.every((p) => p.required === true)).toBe(true);
    }
  });

  it("lists every problem kind of the core in the problem schema", () => {
    const doc = buildOpenApiDocument() as { components: { schemas: { Problem: { properties: { type: { enum: string[] } } } } } };
    expect(doc.components.schemas.Problem.properties.type.enum).toEqual(PROBLEM_KINDS.map((k) => `urn:ojilab:idp:problem:${k}`));
  });
});
