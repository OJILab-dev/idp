// The RFC 9421 admin-signature vectors of contract/testdata/vectors.json (docs/design/hosting-modes.md 3.12).
// The verifier (plan step 3) and the Go signer (plan step 4) do not exist yet, so this file checks what can be
// checked without them: the vectors are consistent with RFC 9421 and RFC 9530, and workerd's WebCrypto verifies
// the chosen algorithm (operator decision 4). The verifier cases are listed as todo until step 3.
import { createHash } from "node:crypto";
import { Miniflare } from "miniflare";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { base64urlDecode } from "../src/shared/index.js";
import { type SignedRequest, type VerifyCase, vectors } from "./vectors.js";

const sig = vectors.admin_signature;
const subtle = crypto.subtle;

function sha256(bytes: Uint8Array): Buffer {
  return createHash("sha256").update(bytes).digest();
}

function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function header(request: SignedRequest, name: string): string {
  const found = request.headers.filter(([n]) => n.toLowerCase() === name);
  if (found.length !== 1) throw new Error(`expected one ${name} header, found ${String(found.length)}`);
  const [entry] = found;
  if (entry === undefined) throw new Error("unreachable");
  return entry[1].trim();
}

// A reference of RFC 9421 §2.5 limited to the components the profile allows, used only to check that the
// vectors' bases agree with their requests. The real builder belongs to the verifier and the signer.
function componentValue(request: SignedRequest, component: string): string {
  switch (component) {
    case "@method":
      return request.method;
    case "@target-uri":
      return request.url;
    case "@authority":
      return new URL(request.url).host.toLowerCase();
    default:
      return header(request, component);
  }
}

// Splits `sig1=(...);params` into the label and the inner list without a structured-field parser: the vectors'
// valid inputs have exactly one member, which is all this check needs.
function splitSignatureInput(value: string): { readonly label: string; readonly inner: string } {
  const at = value.indexOf("=");
  return { label: value.slice(0, at), inner: value.slice(at + 1) };
}

function coveredComponents(inner: string): readonly string[] {
  const list = /^\(([^)]*)\)/.exec(inner)?.[1] ?? "";
  return list === "" ? [] : list.split(" ").map((c) => c.slice(1, -1));
}

type TestKeys = {
  readonly allowlisted: CryptoKeyPair;
  readonly other: CryptoKeyPair;
  readonly keyid: string;
  readonly otherKeyid: string;
};

async function keyidOf(key: CryptoKey): Promise<string> {
  return sha256(new Uint8Array((await subtle.exportKey("spki", key)) as ArrayBuffer)).toString("hex");
}

function substitute(text: string, keys: TestKeys): string {
  return text
    .replaceAll("{keyid_upper}", keys.keyid.toUpperCase())
    .replaceAll("{other_keyid}", keys.otherKeyid)
    .replaceAll("{keyid}", keys.keyid);
}

function derInteger(bytes: Uint8Array): number[] {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start += 1;
  const body = [...bytes.subarray(start)];
  if ((body[0] ?? 0) & 0x80) body.unshift(0);
  return [0x02, body.length, ...body];
}

// ASN.1 DER form of an ECDSA signature, which RFC 9421 §3.3.5 does not allow on the wire.
function derEncode(raw: Uint8Array): Uint8Array {
  const half = raw.length / 2;
  const content = [...derInteger(raw.subarray(0, half)), ...derInteger(raw.subarray(half))];
  return Uint8Array.from([0x30, content.length, ...content]);
}

function tamper(signature: Uint8Array, how: VerifyCase["signature_tamper"]): Uint8Array {
  switch (how) {
    case undefined:
      return signature;
    case "flip_first_byte":
      return Uint8Array.from(signature, (b, i) => (i === 0 ? b ^ 1 : b));
    case "drop_last_byte":
      return signature.subarray(0, signature.length - 1);
    case "append_zero_byte":
      return Uint8Array.from([...signature, 0]);
    case "der_encode":
      return derEncode(signature);
  }
}

describe("admin signature vectors: profile", () => {
  it("fixes the algorithm, tag, label, window, and components of docs/design/hosting-modes.md 3", () => {
    expect(sig.profile).toEqual({
      label: "sig1",
      tag: "idp-admin",
      algorithm: "ecdsa-p384-sha384",
      fallback_algorithm: "ed25519",
      signature_bytes: 96,
      window_seconds: 60,
      nonce_bytes: 32,
      content_digest_algorithm: "sha-256",
      components: ["@method", "@target-uri", "@authority", "content-digest", "content-type", "idempotency-key"],
      parameters: ["created", "nonce", "keyid", "tag"],
    });
  });
});

describe("admin signature vectors: Content-Digest (RFC 9530)", () => {
  it.each(sig.content_digest.valid)("$source: the header is sha-256 of the body", ({ body_utf8, header: value }) => {
    expect(value).toBe(`sha-256=:${sha256(utf8(body_utf8)).toString("base64")}:`);
  });

  it.each(sig.content_digest.invalid)("$reason: is not the one accepted form", ({ body_utf8, header: value }) => {
    expect(value).not.toBe(`sha-256=:${sha256(utf8(body_utf8)).toString("base64")}:`);
  });
});

describe("admin signature vectors: keyid", () => {
  it.each(sig.keyid.valid)("$source: keyid is the SHA-256 of the SPKI DER in lowercase hex", ({ spki, keyid }) => {
    expect(sha256(Buffer.from(spki, "base64")).toString("hex")).toBe(keyid);
  });

  it.each(sig.keyid.invalid)("$reason: is not 64 lowercase hex characters", ({ value }) => {
    expect(value).not.toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("admin signature vectors: nonce", () => {
  it.each(sig.nonce.valid)("%s is strict base64url of 32 bytes", (value) => {
    expect(base64urlDecode(value)).toHaveLength(sig.profile.nonce_bytes);
  });

  it.each(sig.nonce.invalid)("$reason: is not strict base64url of 32 bytes", ({ value }) => {
    let length: number | undefined;
    try {
      length = base64urlDecode(value).length;
    } catch {
      length = undefined;
    }
    expect(length).not.toBe(sig.profile.nonce_bytes);
  });
});

describe("admin signature vectors: signature base (RFC 9421 §2.5)", () => {
  it.each(sig.signature_base)("$case: the base follows from the request and Signature-Input", (c) => {
    const { label, inner } = splitSignatureInput(c.signature_input);
    expect(label).toBe(sig.profile.label);
    expect(inner).toContain(`;created=${String(c.created)};nonce="${c.nonce}";keyid="${c.keyid}";tag="${sig.profile.tag}"`);
    const components = coveredComponents(inner);
    expect(sig.profile.components.filter((p) => components.includes(p))).toEqual(components);
    const lines = components.map((component) => `"${component}": ${componentValue(c.request, component)}`);
    expect(c.signature_base).toBe([...lines, `"@signature-params": ${inner}`].join("\n"));
    expect(header(c.request, "content-digest")).toBe(`sha-256=:${sha256(utf8(c.request.body_utf8)).toString("base64")}:`);
  });
});

// Operator decision 4: run the signatures through workerd's WebCrypto (the runtime of the admin Worker), not Node's.
describe("admin signature vectors: verification in workerd", () => {
  type Check = { readonly algorithm: string; readonly spki: string; readonly base: string; readonly signature: string };
  let mf: Miniflare;
  let keys: TestKeys;

  // The probe Worker only imports the SPKI and calls verify; a thrown error counts as a failed verification.
  const probe = `
    const bytes = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
    const params = (alg) => alg === "ed25519"
      ? [{ name: "Ed25519" }, { name: "Ed25519" }]
      : [{ name: "ECDSA", namedCurve: "P-384" }, { name: "ECDSA", hash: "SHA-384" }];
    export default { async fetch(request) {
      const checks = await request.json();
      const results = [];
      for (const c of checks) {
        try {
          const [importParams, verifyParams] = params(c.algorithm);
          const key = await crypto.subtle.importKey("spki", bytes(c.spki), importParams, false, ["verify"]);
          results.push(await crypto.subtle.verify(verifyParams, key, bytes(c.signature), new TextEncoder().encode(c.base)));
        } catch (error) {
          results.push(String(error));
        }
      }
      return Response.json(results);
    } };`;

  async function verifyInWorkerd(checks: readonly Check[]): Promise<readonly unknown[]> {
    const response = await mf.dispatchFetch("http://probe/", { method: "POST", body: JSON.stringify(checks) });
    return (await response.json()) as readonly unknown[];
  }

  async function spkiOf(key: CryptoKey): Promise<string> {
    return Buffer.from((await subtle.exportKey("spki", key)) as ArrayBuffer).toString("base64");
  }

  async function sign(key: CryptoKey, base: string): Promise<Uint8Array> {
    return new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-384" }, key, utf8(base)));
  }

  beforeAll(async () => {
    mf = new Miniflare({
      workers: [
        {
          config: {
            name: "admin-signature-probe",
            compatibilityDate: "2026-10-01",
            manifest: { mainModule: "index.js", modules: { "index.js": { type: "esm", contents: probe } } },
          },
        },
      ],
    });
    const p384 = { name: "ECDSA", namedCurve: "P-384" };
    const allowlisted = (await subtle.generateKey(p384, true, ["sign", "verify"])) as CryptoKeyPair;
    const other = (await subtle.generateKey(p384, true, ["sign", "verify"])) as CryptoKeyPair;
    keys = { allowlisted, other, keyid: await keyidOf(allowlisted.publicKey), otherKeyid: await keyidOf(other.publicKey) };
  });

  afterAll(async () => {
    await mf.dispose();
  });

  it("verifies the fixed interop signatures (P-384 made in Node, the RFC 9421 B.2.6 Ed25519 example)", async () => {
    const results = await verifyInWorkerd(
      sig.interop.map((c) => ({ algorithm: c.algorithm, spki: c.spki, base: c.signature_base, signature: c.signature })),
    );
    expect(results).toEqual(sig.interop.map(() => true));
    expect(sig.interop.filter((c) => c.algorithm === "ecdsa-p384-sha384").map((c) => Buffer.from(c.signature, "base64").length)).toEqual([96, 96]);
  });

  it("rejects the interop P-384 signatures over a base with one byte changed", async () => {
    const p384 = sig.interop.filter((c) => c.algorithm === "ecdsa-p384-sha384");
    const results = await verifyInWorkerd(
      p384.map((c) => ({ algorithm: c.algorithm, spki: c.spki, base: `${c.signature_base} `, signature: c.signature })),
    );
    expect(results).toEqual(p384.map(() => false));
  });

  it("verifies P-384 signatures made at test time over every valid verify base", async () => {
    const spki = await spkiOf(keys.allowlisted.publicKey);
    const checks: Check[] = [];
    for (const c of sig.verify.valid) {
      if (c.signature_base === undefined) throw new Error(`${c.case} has no signature base`);
      const base = substitute(c.signature_base, keys);
      const signature = await sign(keys.allowlisted.privateKey, base);
      expect(signature).toHaveLength(sig.profile.signature_bytes);
      checks.push({ algorithm: "ecdsa-p384-sha384", spki, base, signature: Buffer.from(signature).toString("base64") });
    }
    expect(await verifyInWorkerd(checks)).toEqual(checks.map(() => true));
  });

  it("does not verify the tampered and wrongly encoded signatures, or a signature by another key", async () => {
    const spki = await spkiOf(keys.allowlisted.publicKey);
    const cases = sig.verify.invalid.filter((c) => c.signature_tamper !== undefined || (c.key === "other" && c.signature_base !== undefined));
    const checks: Check[] = [];
    for (const c of cases) {
      const base = substitute(c.signature_base ?? "", keys);
      const signer = c.key === "other" ? keys.other : keys.allowlisted;
      const signature = tamper(await sign(signer.privateKey, base), c.signature_tamper);
      checks.push({ algorithm: "ecdsa-p384-sha384", spki, base, signature: Buffer.from(signature).toString("base64") });
    }
    expect(cases.length).toBeGreaterThanOrEqual(5);
    expect(await verifyInWorkerd(checks)).toEqual(checks.map(() => false));
  });
});

// Plan step 3 replaces these with calls to the shared core's verifier.
describe("admin signature vectors: verifier (plan step 3)", () => {
  for (const c of sig.verify.valid) it.todo(`accepts ${c.case}`);
  for (const c of sig.verify.invalid) it.todo(`rejects ${c.case} with forbidden (${c.reason ?? ""})`);
  it.todo(`rejects the second request of ${sig.verify.replay.case}`);
});
