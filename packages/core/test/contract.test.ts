import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { MAX_PASSKEYS_PER_USER } from "../src/shared/index.js";

const vectors = JSON.parse(
  readFileSync(join(import.meta.dirname, "..", "..", "..", "contract", "testdata", "vectors.json"), "utf8"),
) as { readonly max_passkeys_per_user: number };

describe("shared contract values", () => {
  it("uses the passkey limit from contract/testdata/vectors.json", () => {
    expect(MAX_PASSKEYS_PER_USER).toBe(vectors.max_passkeys_per_user);
  });
});
