import { describe, expect, it } from "vitest";
import { MAX_PASSKEYS_PER_USER } from "../src/passkeys/index.js";
import { vectors } from "./vectors.js";

describe("shared contract values", () => {
  it("uses the passkey limit from contract/testdata/vectors.json", () => {
    expect(MAX_PASSKEYS_PER_USER).toBe(vectors.max_passkeys_per_user);
  });
});
