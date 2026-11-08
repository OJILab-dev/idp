import { describe, expect, it } from "vitest";
import { matchesRegisteredRedirectUri } from "../src/user/index.js";
import { vectors } from "./vectors.js";

describe("matchesRegisteredRedirectUri (contract vectors)", () => {
  it.each(vectors.redirect_uri_match)("$case", ({ registered, requested, matches }) => {
    expect(matchesRegisteredRedirectUri(registered, requested)).toBe(matches);
  });
});
