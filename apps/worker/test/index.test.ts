import { describe, expect, it } from "vitest";
import worker from "../src/index.js";

describe("IdP Worker skeleton", () => {
  it("refuses every request until the endpoints exist (fail-closed)", async () => {
    const res = await worker.fetch(new Request("https://idp.invalid/.well-known/openid-configuration"));
    expect(res.status).toBe(503);
    expect(res.headers.get("cache-control")).toBe("no-store");
  });
});
