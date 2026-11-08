// The admin Worker: the admin API behind edge mTLS and the certificate allowlist.
// Until it is implemented, every request is refused (design principle 4: fail-closed).

/** Handles every request to the admin host. */
async function fetch(_request: Request): Promise<Response> {
  return new Response(null, { status: 503, headers: { "cache-control": "no-store" } });
}

export default { fetch } satisfies ExportedHandler;
