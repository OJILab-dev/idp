// The RFC 9421 admin-signature vectors of contract/testdata/vectors.json (docs/design/hosting-modes.md 3.12).
// It checks that the vectors are consistent with RFC 9421 and RFC 9530, that workerd's WebCrypto verifies the chosen
// algorithm (operator decision 4), and that the shared core's verifier (plan step 3) accepts and refuses every
// verifier case inside workerd. The Go signer (plan step 4) checks the same vectors in its own tests.
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Miniflare } from "miniflare";
import { build } from "vite";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { migrationNames, readMigration, splitStatements } from "../../../contract/test/d1.js";
import { base64urlDecode } from "../src/shared/index.js";
import { EXPECTED_REFUSALS, makeTestKeys, materialize, signBase, spkiBase64, substitute, tamper, type TestKeys } from "./admin-signature-fixture.js";
import { type SignedRequest, type VerifyCase, vectors } from "./vectors.js";

const sig = vectors.admin_signature;

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

  const spkiOf = spkiBase64;
  const sign = signBase;

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
    keys = await makeTestKeys();
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

// Plan step 3: the shared core's verifier and the D1 nonce store, bundled into a Worker and run inside workerd on the
// requests workerd received, so @target-uri comes from the URL the runtime gives a Worker, not from the vector text.
describe("admin signature vectors: verifier in workerd (plan step 3)", () => {
  type ProbeAnswer = {
    readonly url: string;
    readonly result: { readonly ok: boolean; readonly reason?: string; readonly admin?: unknown; readonly nonce?: string };
    readonly claim: "fresh" | "replayed" | null;
  };
  let mf: Miniflare;
  let keys: TestKeys;
  let bundleDir: string;

  async function send(c: VerifyCase): Promise<ProbeAnswer> {
    const request = await materialize(c, keys);
    const body = request.body_utf8 === "" ? null : request.body_utf8;
    const response = await mf.dispatchFetch(request.url, { method: request.method, headers: request.headers.map(([n, v]) => [n, v]), body });
    return (await response.json()) as ProbeAnswer;
  }

  async function nonceRows(): Promise<number> {
    const db = await mf.getD1Database("DB");
    return (await db.prepare("SELECT COUNT(*) AS n FROM admin_request_nonces").first<number>("n")) ?? -1;
  }

  beforeAll(async () => {
    keys = await makeTestKeys();
    bundleDir = await mkdtemp(join(tmpdir(), "admin-signature-probe-"));
    await build({
      configFile: false,
      logLevel: "warn",
      publicDir: false,
      ssr: { noExternal: true, target: "webworker" },
      build: {
        outDir: bundleDir,
        ssr: join(import.meta.dirname, "support", "admin-signature-probe.ts"),
        target: "es2024",
        minify: false,
        rollupOptions: { output: { entryFileNames: "index.js", format: "es" } },
      },
    });
    const allowlist = [{ keyid: keys.keyid, name: "alice", public_key: await spkiBase64(keys.allowlisted.publicKey) }];
    mf = new Miniflare({
      workers: [
        {
          config: {
            name: "admin-signature-verifier",
            compatibilityDate: "2026-10-01",
            manifest: { mainModule: "index.js", modules: { "index.js": { type: "esm", contents: await readFile(join(bundleDir, "index.js"), "utf8") } } },
            env: {
              DB: { type: "d1", name: crypto.randomUUID() },
              NOW: { type: "text", value: String(sig.verify.now) },
              KEYS: { type: "text", value: JSON.stringify(allowlist) },
            },
          },
        },
      ],
    });
    const db = await mf.getD1Database("DB");
    const statements = migrationNames().flatMap((name) => splitStatements(readMigration(name)));
    await db.batch(statements.map((s) => db.prepare(s)));
  });

  afterAll(async () => {
    await mf.dispose();
    await rm(bundleDir, { recursive: true, force: true });
  });

  it.each(sig.verify.valid.map((c) => [c.case, c] as const))("accepts %s, with @target-uri as workerd hands it over", async (_, c) => {
    const answer = await send(c);
    // The verifier signs over request.url; workerd must not re-encode the vector's URL (docs/design/hosting-modes.md 3.12).
    expect(answer.url).toBe(c.request.url);
    expect(answer.result).toMatchObject({ ok: true, admin: { name: "alice", keyid: keys.keyid } });
    expect(answer.claim).toBe("fresh");
  });

  it.each(sig.verify.invalid.map((c) => [c.case, c.reason ?? "", c] as const))("rejects %s (%s) and writes nothing to D1", async (name, _, c) => {
    const before = await nonceRows();
    const answer = await send(c);
    // Only the refusal and, past the profile check, the claimed keyid: the log may show which key a request named.
    const { keyid, ...refusal } = answer.result as { readonly keyid?: unknown };
    expect(refusal).toEqual({ ok: false, reason: EXPECTED_REFUSALS[name] });
    if (keyid !== undefined) expect(keyid).toMatch(/^[0-9a-f]{64}$/);
    expect(answer.claim).toBeNull();
    expect(await nonceRows()).toBe(before);
  });

  it(`rejects the second request of ${sig.verify.replay.case} (${sig.verify.replay.reason ?? ""})`, async () => {
    const first = await send(sig.verify.replay);
    expect(first.result.ok).toBe(true);
    expect(first.claim).toBe("fresh");
    // The same signed request again: the signature still verifies, and the nonce store refuses it.
    const second = await send(sig.verify.replay);
    expect(second.result.ok).toBe(true);
    expect(second.claim).toBe("replayed");
  });
});
