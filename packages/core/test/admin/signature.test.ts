// The RFC 9421 verifier of the shared core (docs/design/hosting-modes.md 3.2 to 3.8, items 4 to 9), run in Node.
// The same vectors also run inside workerd in admin-signature-vectors.test.ts; this file pins the refusal reason
// of every case and the checks the vectors do not cover.
import { beforeAll, describe, expect, it } from "vitest";
import {
  ADMIN_SIGNATURE_WINDOW_SECONDS,
  signatureBase,
  verifyAdminSignature,
  type AdminSigningKey,
  type AdminSignatureRequest,
} from "../../src/admin/signature.js";
import { parseDictionary } from "@idp/structured-fields";
import { EXPECTED_REFUSALS, makeTestKeys, materialize, signBase, toHeaders, type TestKeys } from "../admin-signature-fixture.js";
import { vectors, type VerifyCase } from "../vectors.js";

const sig = vectors.admin_signature;
const NOW = sig.verify.now;

let keys: TestKeys;
let allowlist: ReadonlyMap<string, AdminSigningKey>;

beforeAll(async () => {
  keys = await makeTestKeys();
  allowlist = new Map([[keys.keyid, { keyid: keys.keyid, name: "alice", publicKey: keys.allowlisted.publicKey }]]);
});

async function requestOf(c: VerifyCase): Promise<AdminSignatureRequest> {
  const concrete = await materialize(c, keys);
  return { method: concrete.method, url: concrete.url, headers: toHeaders(concrete), body: new TextEncoder().encode(concrete.body_utf8) };
}

function createdOf(c: VerifyCase): number {
  const input = c.request.headers.find(([name]) => name === "Signature-Input")?.[1] ?? "";
  return Number(/;created=(\d+)/.exec(input)?.[1]);
}

function nonceOf(c: VerifyCase): string {
  const input = c.request.headers.find(([name]) => name === "Signature-Input")?.[1] ?? "";
  return /;nonce="([^"]+)"/.exec(input)?.[1] ?? "";
}

// A request signed with the allowlisted key over the base this test builds, for checks the vectors do not cover.
async function signedGet(signatureInput: string, base: string, method = "GET"): Promise<AdminSignatureRequest> {
  const signature = Buffer.from(await signBase(keys.allowlisted.privateKey, base)).toString("base64");
  return {
    method,
    url: "https://admin.example.com/v1/users",
    headers: new Headers({
      "Content-Digest": "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:",
      "Signature-Input": `sig1=${signatureInput}`,
      Signature: `sig1=:${signature}:`,
    }),
    body: new Uint8Array(),
  };
}

function baseFor(method: string, params: string): string {
  return [
    `"@method": ${method}`,
    '"@target-uri": https://admin.example.com/v1/users',
    '"@authority": admin.example.com',
    '"content-digest": sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:',
    `"@signature-params": ${params}`,
  ].join("\n");
}

const NONCE = "O8_3pm6onyoa4Tsu00sy8ZRUGjz50Rh7a91YS5s4Rhc";

describe("verifyAdminSignature: the contract vectors", () => {
  it.each(sig.verify.valid.map((c) => [c.case, c] as const))("accepts %s and names the admin, nonce, and expiry", async (_, c) => {
    const result = await verifyAdminSignature(await requestOf(c), allowlist, NOW);
    expect(result).toEqual({
      ok: true,
      admin: { name: "alice", keyid: keys.keyid },
      nonce: nonceOf(c),
      expiresAt: createdOf(c) + ADMIN_SIGNATURE_WINDOW_SECONDS,
    });
  });

  it.each(sig.verify.invalid.map((c) => [c.case, c.reason ?? "", c] as const))("rejects %s (%s)", async (name, _, c) => {
    const result = await verifyAdminSignature(await requestOf(c), allowlist, NOW);
    const reason = EXPECTED_REFUSALS[name];
    // The claimed keyid is reported only once the profile check passed, so it is always 64 lowercase hex.
    if (reason === "malformed" || reason === "profile") expect(result).toEqual({ ok: false, reason });
    else expect(result).toEqual({ ok: false, reason, keyid: expect.stringMatching(/^[0-9a-f]{64}$/) });
  });

});

describe("signatureBase: the signer vectors", () => {
  it.each(sig.signature_base.map((c) => [c.case, c] as const))("%s: builds the vector's base from the request", (_, c) => {
    const [member] = parseDictionary(c.signature_input);
    if (member === undefined || member[1].kind !== "inner-list") throw new Error("not an inner list");
    const input = member[1];
    const components = input.items.map((item) => String(item.value.value));
    const request = { method: c.request.method, url: c.request.url, headers: toHeaders(c.request), body: new TextEncoder().encode(c.request.body_utf8) };
    expect(signatureBase(request, components, input)).toBe(c.signature_base);
  });
});

describe("verifyAdminSignature: checks beyond the vectors", () => {
  const params = `("@method" "@target-uri" "@authority" "content-digest");created=${String(NOW)};nonce="${NONCE}";keyid="{keyid}";tag="idp-admin"`;

  it("accepts the parameters in another order, since the base serializes them as received", async () => {
    const reordered = `("@method" "@target-uri" "@authority" "content-digest");tag="idp-admin";keyid="${"{keyid}"}";nonce="${NONCE}";created=${String(NOW)}`.replace("{keyid}", keys.keyid);
    const request = await signedGet(reordered, baseFor("GET", reordered));
    expect((await verifyAdminSignature(request, allowlist, NOW)).ok).toBe(true);
  });

  it("refuses a signer that signed a non-canonical spelling of Signature-Input", async () => {
    const canonical = params.replace("{keyid}", keys.keyid);
    const spaced = canonical.replace('("@method" ', '( "@method"  ');
    const request = await signedGet(spaced, baseFor("GET", spaced));
    expect(await verifyAdminSignature(request, allowlist, NOW)).toEqual({ ok: false, reason: "signature", keyid: keys.keyid });
  });

  it("refuses a covered component with parameters (RFC 9421 §2.1), which the profile never uses", async () => {
    const withParam = params.replace('"@authority"', '"@authority";req').replace("{keyid}", keys.keyid);
    const request = await signedGet(withParam, baseFor("GET", withParam));
    expect(await verifyAdminSignature(request, allowlist, NOW)).toEqual({ ok: false, reason: "profile" });
  });

  it("refuses a method the admin API does not use", async () => {
    const canonical = params.replace("{keyid}", keys.keyid);
    const request = await signedGet(canonical, baseFor("PATCH", canonical), "PATCH");
    expect(await verifyAdminSignature(request, allowlist, NOW)).toEqual({ ok: false, reason: "profile" });
  });

  it("refuses a nonce longer than 32 bytes", async () => {
    const long = params.replace(NONCE, "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB").replace("{keyid}", keys.keyid);
    const request = await signedGet(long, baseFor("GET", long));
    expect(await verifyAdminSignature(request, allowlist, NOW)).toEqual({ ok: false, reason: "profile" });
  });

  it("refuses a negative created", async () => {
    const negative = params.replace(`created=${String(NOW)}`, "created=-1").replace("{keyid}", keys.keyid);
    const request = await signedGet(negative, baseFor("GET", negative));
    expect(await verifyAdminSignature(request, allowlist, 0)).toEqual({ ok: false, reason: "profile" });
  });

  it("refuses every request when the allowlisted key is not an ECDSA P-384 public key", async () => {
    const p256 = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const wrong = new Map([[keys.keyid, { keyid: keys.keyid, name: "alice", publicKey: p256.publicKey }]]);
    const canonical = params.replace("{keyid}", keys.keyid);
    const request = await signedGet(canonical, baseFor("GET", canonical));
    expect(await verifyAdminSignature(request, wrong, NOW)).toEqual({ ok: false, reason: "signature", keyid: keys.keyid });
    expect(await verifyAdminSignature(request, new Map([[keys.keyid, { keyid: keys.keyid, name: "alice", publicKey: keys.allowlisted.privateKey }]]), NOW)).toEqual({
      ok: false,
      reason: "signature",
      keyid: keys.keyid,
    });
  });

  it("does not want content-type on a POST without a body, which sends no Content-Type", async () => {
    const canonical = params.replace("{keyid}", keys.keyid);
    const request = await signedGet(canonical, baseFor("POST", canonical), "POST");
    expect((await verifyAdminSignature(request, allowlist, NOW)).ok).toBe(true);
  });

  it.each([
    ["NaN", Number.NaN],
    ["not an integer", NOW + 0.5],
  ])("refuses every request when the clock is %s (fail-closed)", async (_, now) => {
    const canonical = params.replace("{keyid}", keys.keyid);
    const request = await signedGet(canonical, baseFor("GET", canonical));
    expect(await verifyAdminSignature(request, allowlist, now)).toEqual({ ok: false, reason: "created", keyid: keys.keyid });
  });

  it("refuses a URL that is not absolute", async () => {
    const canonical = params.replace("{keyid}", keys.keyid);
    const request = { ...(await signedGet(canonical, baseFor("GET", canonical))), url: "/v1/users" };
    expect(await verifyAdminSignature(request, allowlist, NOW)).toEqual({ ok: false, reason: "malformed", keyid: keys.keyid });
  });
});
