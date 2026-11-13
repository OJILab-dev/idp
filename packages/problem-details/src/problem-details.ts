// Problem Details for HTTP APIs (RFC 9457): the JSON object an API returns to describe an error, and its media type.
// The standard members are all optional (RFC 9457 §3.1); an API narrows them and adds its own extension members
// (§3.2) through the type parameter.

/** The media type of a problem details object serialized as JSON (RFC 9457 §3). */
export const PROBLEM_JSON_MEDIA_TYPE = "application/problem+json";

/**
 * A problem details object: what kind of problem occurred, a short summary that does not change between occurrences,
 * the HTTP status, an explanation of this occurrence, and a reference to it (RFC 9457 §3.1), plus any extension
 * members the API defines (§3.2).
 */
export type ProblemDetails<Extensions extends object = Record<never, never>> = {
  /** A URI reference identifying the problem type; "about:blank" when absent (§3.1.1). */
  readonly type?: string;
  /** The HTTP status code generated for this occurrence (§3.1.2). */
  readonly status?: number;
  /** A short, human-readable summary of the problem type (§3.1.3). */
  readonly title?: string;
  /** A human-readable explanation of this occurrence (§3.1.4). */
  readonly detail?: string;
  /** A URI reference identifying this occurrence (§3.1.5). */
  readonly instance?: string;
} & Extensions;
