// The checks on the authorization response at /callback, before anything is sent to the IdP: state binds the
// response to this browser's login (RFC 6749 §10.12), and iss to this IdP (RFC 9207 §2.4, against mix-up attacks).
// An `error` response is believed only after both.

/** Why an authorization response was refused. */
export type CallbackFailure = "state" | "iss" | "code" | "idp_error" | "repeated";

/** The authorization response was refused. */
export class CallbackError extends Error {
  override readonly name = "CallbackError";
  readonly reason: CallbackFailure;
  /** The IdP's `error` code, only when it is a plain OAuth error code and state and iss matched. */
  readonly idpError: string | undefined;

  constructor(reason: CallbackFailure, idpError?: string) {
    super(`authorization response refused: ${reason}`);
    this.reason = reason;
    this.idpError = idpError;
  }
}

// RFC 6749 §4.1.2.1: error codes are %x20-21 / %x23-5B / %x5D-7E; this IdP only uses lowercase codes with "_".
const USED_PARAMETERS = ["state", "iss", "code", "error"] as const;

const ERROR_CODE =/^[a-z_]{1,64}$/;

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index += 1) difference |= a.charCodeAt(index) ^ b.charCodeAt(index);
  return difference === 0;
}

/**
 * Checks the query of the redirect back from the IdP.
 *
 * @param params The callback's query.
 * @param state The state this login sent, from the sealed flow cookie.
 * @param issuer The configured issuer.
 * @returns The authorization code.
 * @throws {CallbackError} A parameter repeats, state or iss does not match, the IdP returned an error, or there is no
 *   code.
 */
export function checkAuthorizationResponse(params: URLSearchParams, state: string, issuer: string): { readonly code: string } {
  // RFC 6749 §3.1 forbids the sender to repeat a parameter, and §4.1.2 requires the client to ignore parameters it
  // does not recognise; so only a repeated parameter this RP reads is refused, as it could be read either way.
  if (USED_PARAMETERS.some((name) => params.getAll(name).length > 1)) throw new CallbackError("repeated");
  if (!constantTimeEqual(params.get("state") ?? "", state)) throw new CallbackError("state");
  // Simple string comparison, no normalisation (RFC 9207 §2.4). The IdP advertises
  // authorization_response_iss_parameter_supported, so a response without iss is refused too.
  if (params.get("iss") !== issuer) throw new CallbackError("iss");
  const error = params.get("error");
  if (error !== null) throw new CallbackError("idp_error", ERROR_CODE.test(error) ? error : undefined);
  const code = params.get("code");
  if (code === null || code === "") throw new CallbackError("code");
  return { code };
}
