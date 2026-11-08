// The IdP Worker: OIDC endpoints, the passkey API, and the static pages.
// Until they are implemented, every request is refused (design principle 4: fail-closed).

/** Handles every request to the issuer host. */
async function fetch(_request: Request): Promise<Response> {
  return new Response(null, { status: 503, headers: { "cache-control": "no-store" } });
}

export default { fetch } satisfies ExportedHandler;
