import { describe, expect, it } from "vitest";
import { decodeCursor, encodeCursor, type Page, type UserSummary } from "../../src/domain/index.js";
import { userCreate, usersList } from "../../src/domain/users.js";
import { base64urlEncode } from "@idp/base64url";
import { T0, run, useHarness } from "./harness.js";

const h = useHarness();

const KEY = [
  { sql: "u.created_at", column: "created_at", type: "integer" },
  { sql: "u.id", column: "id", type: "text" },
] as const;

function raw(text: string): string {
  return base64urlEncode(new TextEncoder().encode(text));
}

describe("cursors", () => {
  it("round-trips the direction and key as base64url JSON", () => {
    const cursor = encodeCursor({ direction: "next", key: [T0, "abc"] });
    expect(cursor).toBe(raw(`{"d":"next","k":[${T0},"abc"]}`));
    expect(decodeCursor(cursor, KEY)).toEqual({ direction: "next", key: [T0, "abc"] });
  });

  it.each([
    ["not base64url", "a+b/"],
    ["padding", `${raw("{}")}=`],
    ["not JSON", raw("{")],
    ["not UTF-8", base64urlEncode(new Uint8Array([0xff, 0xfe]))],
    ["an array", raw("[]")],
    ["a bad direction", raw('{"d":"up","k":[1,"a"]}')],
    ["a short key", raw('{"d":"next","k":[1]}')],
    ["a key of the wrong types", raw('{"d":"next","k":["1","a"]}')],
    ["a fractional number", raw('{"d":"next","k":[1.5,"a"]}')],
    ["an extra member", raw('{"d":"next","k":[1,"a"],"x":1}')],
  ])("rejects %s with validation-failed at /cursor", (_reason, value) => {
    expect(() => decodeCursor(value, KEY)).toThrow(expect.objectContaining({ kind: "validation-failed", pointers: ["/cursor"] }));
  });
});

describe("list paging", () => {
  async function seed(count: number): Promise<readonly string[]> {
    const ids: string[] = [];
    for (let i = 0; i < count; i++) {
      // Two users share each second, so the ID breaks ties in the sort key.
      h().clock = T0 + Math.floor(i / 2);
      ids.push((await run(h(), userCreate, { name: `u${i}` })).body.user_id);
    }
    return ids;
  }

  async function page(input: Record<string, unknown>): Promise<Page<UserSummary>> {
    return (await run(h(), usersList, input, null)).body;
  }

  it("walks forward and back through the creation order without gaps or repeats", async () => {
    await seed(5);
    const all = (await page({})).items.map((u) => u.user_id);
    expect(all).toHaveLength(5);

    const p1 = await page({ limit: 2 });
    expect(p1.items.map((u) => u.user_id)).toEqual(all.slice(0, 2));
    expect(p1.prev_cursor).toBeNull();
    const p2 = await page({ limit: 2, cursor: p1.next_cursor });
    expect(p2.items.map((u) => u.user_id)).toEqual(all.slice(2, 4));
    const p3 = await page({ limit: 2, cursor: p2.next_cursor });
    expect(p3.items.map((u) => u.user_id)).toEqual(all.slice(4));
    expect(p3.next_cursor).toBeNull();

    const back2 = await page({ limit: 2, cursor: p3.prev_cursor });
    expect(back2.items.map((u) => u.user_id)).toEqual(all.slice(2, 4));
    const back1 = await page({ limit: 2, cursor: back2.prev_cursor });
    expect(back1.items.map((u) => u.user_id)).toEqual(all.slice(0, 2));
    expect(back1.prev_cursor).toBeNull();
    expect(back1.next_cursor).not.toBeNull();
  });

  it("does not shift pages when rows are added before the cursor's page is read", async () => {
    await seed(3);
    const p1 = await page({ limit: 2 });
    h().clock = T0 + 100;
    await run(h(), userCreate, { name: "late" });
    const p2 = await page({ limit: 2, cursor: p1.next_cursor });
    expect(p2.items.map((u) => u.name)).toEqual(["u2", "late"]);
  });

  it("returns an empty page with no cursors past the end", async () => {
    await seed(1);
    const past = encodeCursor({ direction: "next", key: [T0 + 999, "z"] });
    expect(await page({ cursor: past })).toEqual({ items: [], next_cursor: null, prev_cursor: null });
  });

  it.each([[0], [201], [1.5], ["201"], ["01"], [""]])("rejects the limit %j", async (limit) => {
    await expect(run(h(), usersList, { limit }, null)).rejects.toMatchObject({ kind: "validation-failed", pointers: ["/limit"] });
  });

  it("accepts the limit as a query-string number, up to 200, and defaults to 50", async () => {
    await seed(51);
    expect((await page({})).items).toHaveLength(50);
    expect((await page({ limit: "200" })).items).toHaveLength(51);
    expect((await page({ limit: "1" })).items).toHaveLength(1);
  });
});
