import { describe, expect, it } from "vitest";
import { parseDictionary } from "@idp/structured-fields";
import { selectSignature, signatureBase, verifyEcdsaP384Sha384 } from "../src/index.js";

// The test-request of RFC 9421 Appendix B.2.
const TEST_REQUEST = {
  method: "POST",
  url: "https://example.com/foo?param=Value&Pet=dog",
  headers: new Headers({
    host: "example.com",
    date: "Tue, 20 Apr 2021 02:07:55 GMT",
    "content-type": "application/json",
    "content-digest": "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
    "content-length": "18",
  }),
};

// The signature bases of RFC 9421 Appendix B.2 whose components are ones this package derives.
const APPENDIX_B2 = [
  {
    section: "B.2.1",
    signatureInput: 'sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
    signature: "sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:",
    label: "sig-b21",
    base: '"@signature-params": ();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
  },
  {
    section: "B.2.5",
    signatureInput: 'sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
    signature: "sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:",
    label: "sig-b25",
    base: [
      '"date": Tue, 20 Apr 2021 02:07:55 GMT',
      '"@authority": example.com',
      '"content-type": application/json',
      '"@signature-params": ("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
    ].join("\n"),
  },
] as const;

describe("RFC 9421 Appendix B.2 signature bases", () => {
  it.each(APPENDIX_B2)("builds the base of $section", ({ signatureInput, signature, label, base }) => {
    const selected = selectSignature(parseDictionary(signatureInput), parseDictionary(signature), label);
    if (selected === undefined) throw new Error("no signature selected");
    const components = selected.input.items.map((item) => String(item.value.value));
    expect(signatureBase(TEST_REQUEST, components, selected.input)).toBe(base);
  });
});

describe("selectSignature", () => {
  const [b25] = APPENDIX_B2.slice(1);

  it("selects nothing for a label that only one field has", () => {
    expect(selectSignature(parseDictionary(b25?.signatureInput ?? ""), parseDictionary("other=:AA==:"), "sig-b25")).toBeUndefined();
  });

  it("selects nothing when Signature-Input is not an inner list or Signature is not a byte sequence", () => {
    expect(selectSignature(parseDictionary("a=1"), parseDictionary("a=:AA==:"), "a")).toBeUndefined();
    expect(selectSignature(parseDictionary("a=()"), parseDictionary('a="AA=="'), "a")).toBeUndefined();
  });
});

describe("signatureBase", () => {
  it("cannot derive @authority from a URL that is not absolute", () => {
    expect(signatureBase({ ...TEST_REQUEST, url: "/foo" }, ["@authority"], { kind: "inner-list", items: [], params: [] })).toBeUndefined();
  });

  it("cannot cover a header field that is absent", () => {
    expect(signatureBase(TEST_REQUEST, ["x-absent"], { kind: "inner-list", items: [], params: [] })).toBeUndefined();
  });
});

describe("verifyEcdsaP384Sha384 (RFC 9421 §3.3.5)", () => {
  async function pair(namedCurve: "P-384" | "P-256"): Promise<CryptoKeyPair> {
    return (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve }, false, ["sign", "verify"])) as CryptoKeyPair;
  }

  async function sign(key: CryptoKey, base: string): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-384" }, key, new TextEncoder().encode(base)));
  }

  it("verifies an r || s signature over the base", async () => {
    const keys = await pair("P-384");
    expect(await verifyEcdsaP384Sha384(keys.publicKey, await sign(keys.privateKey, "base"), "base")).toBe(true);
  });

  it("rejects a signature over another base", async () => {
    const keys = await pair("P-384");
    expect(await verifyEcdsaP384Sha384(keys.publicKey, await sign(keys.privateKey, "base"), "other")).toBe(false);
  });

  it("rejects a signature that is not 96 bytes", async () => {
    const keys = await pair("P-384");
    expect(await verifyEcdsaP384Sha384(keys.publicKey, new Uint8Array(95), "base")).toBe(false);
  });

  it("takes the algorithm from the key: a P-256 key never verifies", async () => {
    const keys = await pair("P-256");
    expect(await verifyEcdsaP384Sha384(keys.publicKey, new Uint8Array(96), "base")).toBe(false);
  });
});
