// The request body limit holds whether or not the client declares a Content-Length: a chunked body is read as a
// stream and abandoned as soon as it passes the limit, so it is refused like an oversized declared one.
import { describe, expect, it } from "vitest";
import { ISSUER, expectSecurityHeaders, fromEdge, useFixture, type Fixture } from "./fixture.js";

const LIMIT = 64 * 1024;

/** A body sent in chunks with no Content-Length, as a chunked transfer encoding arrives at the Worker. */
function chunked(text: string): { readonly body: ReadableStream<Uint8Array>; readonly pulled: () => number } {
  const bytes = new TextEncoder().encode(text);
  let offset = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (offset >= bytes.length) {
        controller.close();
        return;
      }
      const end = Math.min(offset + 4096, bytes.length);
      controller.enqueue(bytes.slice(offset, end));
      offset = end;
    },
  });
  return { body, pulled: () => offset };
}

async function post(f: Fixture, path: string, contentType: string, body: BodyInit, headers: Readonly<Record<string, string>> = {}): Promise<Response> {
  const request = new Request(`${ISSUER}${path}`, {
    method: "POST",
    headers: { "sec-fetch-site": "same-origin", "content-type": contentType, ...headers },
    body,
    redirect: "manual",
    duplex: "half",
  } as RequestInit);
  if (body instanceof ReadableStream && headers["content-length"] === undefined) expect(request.headers.get("content-length")).toBeNull();
  const response = await f.handler.fetch(fromEdge(request), f.env, {} as ExecutionContext);
  expectSecurityHeaders(response);
  return response;
}

const TOKEN = "ZW5yb2xsLXRva2VuLWVucm9sbC10b2tlbi1lbnJvbGw";

function jsonOf(size: number): string {
  const head = `{"token":"${TOKEN}","pad":"`;
  return `${head}${"x".repeat(Math.max(0, size - head.length - 2))}"}`;
}

function formOf(size: number): string {
  const head = "grant_type=authorization_code&code=abc&pad=";
  return `${head}${"x".repeat(Math.max(0, size - head.length))}`;
}

describe("request body limit", () => {
  const fixture = useFixture();

  it("refuses a chunked JSON body over the limit exactly as an oversized declared one, without reading it all", async () => {
    const f = fixture();
    const declared = await post(f, "/webauthn/register/options", "application/json", jsonOf(LIMIT + 1));
    expect(declared.status).toBe(400);
    expect(await declared.json()).toEqual({ error: "invalid_request" });

    const stream = chunked(jsonOf(4 * LIMIT));
    const res = await post(f, "/webauthn/register/options", "application/json", stream.body);
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_request" });
    // Reading stopped soon after the limit, not at the end of the body.
    expect(stream.pulled()).toBeLessThan(2 * LIMIT);
  });

  it("reads a chunked JSON body under the limit", async () => {
    const f = fixture();
    // The token is unknown, so the core refuses it: proof that the body was parsed and handed on.
    const res = await post(f, "/webauthn/register/options", "application/json", chunked(jsonOf(LIMIT - 1)).body);
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "passkey_rejected" });
  });

  it("refuses a chunked /token form over the limit exactly as an oversized declared one", async () => {
    const f = fixture();
    const declared = await post(f, "/token", "application/x-www-form-urlencoded", formOf(LIMIT + 1));
    expect(declared.status).toBe(400);
    expect(await declared.json()).toEqual({ error: "invalid_request" });

    const stream = chunked(formOf(4 * LIMIT));
    const res = await post(f, "/token", "application/x-www-form-urlencoded", stream.body);
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_request" });
    expect(stream.pulled()).toBeLessThan(2 * LIMIT);
  });

  it("reads a chunked /token form under the limit", async () => {
    const f = fixture();
    // No client authentication, so the core answers invalid_client: the form itself was accepted.
    const res = await post(f, "/token", "application/x-www-form-urlencoded", chunked(formOf(LIMIT - 1)).body);
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid_client" });
  });

  it("treats a POST /authorize form over the limit, chunked or declared, as a request without parameters", async () => {
    const f = fixture();
    for (const body of [formOf(LIMIT + 1), chunked(formOf(4 * LIMIT)).body]) {
      const res = await post(f, "/authorize", "application/x-www-form-urlencoded", body);
      // Without a client_id there is no redirect target to trust, so the error page is shown.
      expect(res.status).toBe(400);
      expect(res.headers.get("location")).toBeNull();
    }
  });

  it("refuses a body whose declared Content-Length is over the limit before reading it", async () => {
    const f = fixture();
    const stream = chunked(jsonOf(LIMIT - 1));
    const res = await post(f, "/webauthn/register/options", "application/json", stream.body, { "content-length": String(LIMIT + 1) });
    expect(res.status).toBe(400);
    expect(stream.pulled()).toBeLessThanOrEqual(4096);
  });
});
