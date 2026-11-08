import { describe, expect, it } from "vitest";
import { isClientId, isRandomTokenFormat, isUuidV4, newUuidV4, randomToken } from "../src/shared/index.js";
import { vectors } from "./vectors.js";

describe("isUuidV4", () => {
  it.each(vectors.uuid_v4.valid)("accepts %s", (value) => {
    expect(isUuidV4(value)).toBe(true);
  });

  it.each(vectors.uuid_v4.invalid)("rejects '$value' ($reason)", ({ value }) => {
    expect(isUuidV4(value)).toBe(false);
  });

  it("accepts what newUuidV4 generates", () => {
    for (let i = 0; i < 100; i++) {
      expect(isUuidV4(newUuidV4())).toBe(true);
    }
  });
});

describe("isClientId", () => {
  it.each(vectors.client_id.valid)("accepts %s", (value) => {
    expect(isClientId(value)).toBe(true);
  });

  it.each(vectors.client_id.invalid)("rejects '$value' ($reason)", ({ value }) => {
    expect(isClientId(value)).toBe(false);
  });
});

describe("random tokens", () => {
  it.each(vectors.random_token.valid)("accepts %s", (value) => {
    expect(isRandomTokenFormat(value)).toBe(true);
  });

  it.each(vectors.random_token.invalid)("rejects '$value' ($reason)", ({ value }) => {
    expect(isRandomTokenFormat(value)).toBe(false);
  });

  it("generates distinct tokens in the contract format", () => {
    const tokens = Array.from({ length: 100 }, () => randomToken());
    for (const token of tokens) {
      expect(token).toHaveLength(43);
      expect(isRandomTokenFormat(token)).toBe(true);
    }
    expect(new Set(tokens).size).toBe(tokens.length);
  });
});
