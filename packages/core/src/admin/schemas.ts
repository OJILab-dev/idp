// Input schemas shared by the admin operations. The formats come from src/identifiers (the contract), so a value the
// schema accepts is exactly a value the IdP Worker accepts; zod only adds the field structure and JSON Pointers.
import { z } from "zod";
import { isClientId, isUuidV4 } from "../identifiers/index.js";
import { AdminProblem } from "./problem.js";

/** The largest page an admin list returns (docs/design/idpctl.md, "一覧のページング"). */
export const MAX_PAGE_LIMIT = 200;

/** The page size when `limit` is absent. */
export const DEFAULT_PAGE_LIMIT = 50;

/** The longest display name or group name, in code points. */
export const MAX_NAME_LENGTH = 64;

/** A user ID or group ID: a lowercase UUIDv4. */
export const uuidSchema = z.string().refine(isUuidV4, { message: "must be a lowercase UUIDv4" });

/** A client ID: 3 to 64 lowercase letters, digits, or hyphens, starting and ending with a letter or digit. */
export const clientIdSchema = z.string().refine(isClientId, { message: "must be a client ID" });

// Control, format, surrogate, private-use, and unassigned code points (\p{C}) and line or paragraph separators
// would let a name render differently from what was stored, or break a terminal line in idpctl.
const NAME_FORBIDDEN = /[\p{C}\p{Zl}\p{Zp}]/u;

/**
 * A display name (users.name, clients.name) or group name: 1 to 64 code points of printable text in Unicode NFC,
 * without leading or trailing whitespace. NFC makes two spellings of the same text compare equal, which matters
 * for the unique group name.
 */
export const nameSchema = z
  .string()
  .refine((value) => value.trim() === value && value !== "", { message: "must be non-empty without surrounding whitespace" })
  .refine((value) => [...value].length <= MAX_NAME_LENGTH, { message: `must be at most ${MAX_NAME_LENGTH} characters` })
  .refine((value) => !NAME_FORBIDDEN.test(value), { message: "must not contain control or separator characters" })
  .refine((value) => value.normalize("NFC") === value, { message: "must be in Unicode NFC" });

// Query parameters arrive as strings and a JSON body as numbers; both spell the same limit.
const LIMIT_STRING = /^[1-9][0-9]{0,2}$/;

/** The `limit` of a list: an integer from 1 to 200, or its decimal string; 50 when absent. */
export const limitSchema = z
  .union([z.int(), z.string().regex(LIMIT_STRING).transform(Number)])
  .pipe(z.int().min(1).max(MAX_PAGE_LIMIT))
  .default(DEFAULT_PAGE_LIMIT);

/** The input members of every list. */
export const pageInputShape = {
  limit: limitSchema,
  /** The opaque cursor of a previous page; validated when the list decodes it. */
  cursor: z.string().min(1).optional(),
};

/** The validated paging members. */
export type PageInput = {
  readonly limit: number;
  readonly cursor?: string | undefined;
};

/**
 * Escapes one path segment as a JSON Pointer reference token (RFC 6901 §3).
 *
 * @param segment A property name or array index.
 * @returns The token with `~` and `/` escaped.
 */
function pointerToken(segment: PropertyKey): string {
  return String(segment).replace(/~/g, "~0").replace(/\//g, "~1");
}

/**
 * Validates an operation input against its schema.
 *
 * @param schema The operation's input schema.
 * @param input The untrusted input (path parameters, query, and body merged by the HTTP layer).
 * @returns The validated, transformed input.
 * @throws {AdminProblem} `validation-failed`, listing the failing fields as JSON Pointers (RFC 6901).
 */
export function parseInput<I>(schema: z.ZodType<I>, input: unknown): I {
  const parsed = schema.safeParse(input);
  if (parsed.success) return parsed.data;
  const pointers = [...new Set(parsed.error.issues.map((issue) => issue.path.map((p) => `/${pointerToken(p)}`).join("")))];
  throw new AdminProblem("validation-failed", "The input failed validation", { pointers });
}
