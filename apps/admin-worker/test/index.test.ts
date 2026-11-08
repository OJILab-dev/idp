import { describe, expect, it } from "vitest";
import worker from "../src/index.js";

describe("admin Worker skeleton", () => {
  it("refuses every request until the admin API exists (fail-closed)", async () => {
    const res = await worker.fetch(new Request("https://admin.invalid/v1/users"));
    expect(res.status).toBe(503);
    expect(res.headers.get("cache-control")).toBe("no-store");
  });
});
