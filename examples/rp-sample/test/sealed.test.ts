import { describe, expect, it } from "vitest";
import { ConfigError } from "../src/config.js";
import { importSealingKey, seal, unseal } from "../src/sealed.js";
import { SESSION_KEY } from "./support/fake-idp.js";

const NOW = 1_800_000_000;

async function sealed(): Promise<{ key: CryptoKey; value: string }> {
  const key = await importSealingKey(SESSION_KEY);
  return { key, value: await seal(key, "__Host-session", { sub: "alice" }, NOW + 60) };
}

function flip(value: string, index: number): string {
  const char = value[index] === "A" ? "B" : "A";
  return `${value.slice(0, index)}${char}${value.slice(index + 1)}`;
}

describe("sealed cookies", () => {
  it("round-trips the payload before the expiry", async () => {
    const { key, value } = await sealed();
    await expect(unseal(key, "__Host-session", value, NOW)).resolves.toEqual({ sub: "alice" });
  });

  it("is encrypted: the payload is not readable from the cookie value", async () => {
    const { value } = await sealed();
    expect(value).not.toContain("alice");
    expect(atob(value.split(".")[2]?.replaceAll("-", "+").replaceAll("_", "/") ?? "")).not.toContain("alice");
  });

  it("refuses an expired value, and one at exactly the expiry", async () => {
    const { key, value } = await sealed();
    await expect(unseal(key, "__Host-session", value, NOW + 60)).resolves.toBeUndefined();
    await expect(unseal(key, "__Host-session", value, NOW + 3600)).resolves.toBeUndefined();
  });

  it("refuses a tampered value anywhere in the IV or the ciphertext", async () => {
    const { key, value } = await sealed();
    const start = value.indexOf(".") + 1;
    for (let index = start; index < value.length; index += 7) {
      if (value[index] === ".") continue;
      await expect(unseal(key, "__Host-session", flip(value, index), NOW)).resolves.toBeUndefined();
    }
  });

  it("refuses a value sealed for another cookie (the cookie name is the associated data)", async () => {
    const { key, value } = await sealed();
    await expect(unseal(key, "__Host-flow", value, NOW)).resolves.toBeUndefined();
  });

  it("refuses a value sealed with another key", async () => {
    const { value } = await sealed();
    const other = await importSealingKey(btoa(String.fromCharCode(...new Uint8Array(32).fill(7))));
    await expect(unseal(other, "__Host-session", value, NOW)).resolves.toBeUndefined();
  });

  it.each(["", "garbage", "v1..", "v2.AAAA.AAAA", "v1.!!!.AAAA"])("refuses the malformed value %j without throwing", async (value) => {
    const { key } = await sealed();
    await expect(unseal(key, "__Host-session", value, NOW)).resolves.toBeUndefined();
  });

  it.each([
    ["missing", undefined],
    ["empty", ""],
    ["not base64", "%%%"],
    ["16 bytes", btoa("0123456789abcdef")],
    ["33 bytes", btoa("0123456789abcdef0123456789abcdef!")],
  ])("refuses a %s SESSION_KEY: it must be 32 bytes of base64", async (_name, value) => {
    await expect(importSealingKey(value)).rejects.toBeInstanceOf(ConfigError);
  });
});
