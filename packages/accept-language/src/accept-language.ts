// The Accept-Language request header (RFC 9110 §12.5.4): a comma-separated list of language ranges, each optionally
// weighted by a quality value. This module turns the header into the ranges in order of preference; matching them
// against the languages a server has is the server's business.

/** One language range of the header with its quality. */
export type LanguagePreference = {
  /** The language range as sent, for example `en-gb` or `*` (RFC 4647 §2.1). */
  readonly range: string;
  /** The quality, from just above 0 to 1 (RFC 9110 §12.4.2). */
  readonly q: number;
};

// A qvalue is 0 to 1 with at most three decimals (RFC 9110 §12.4.2).
const QVALUE = /^(?:0(?:\.\d{0,3})?|1(?:\.0{0,3})?)$/;

/**
 * Reads an Accept-Language header into the language ranges the client accepts, most preferred first.
 *
 * Ranges keep the order they were sent in when their qualities are equal. A range with quality 0 means "not
 * acceptable" and is left out; an entry whose quality is malformed is dropped rather than guessed at. Parameters other
 * than `q` are ignored.
 *
 * @param header The header value.
 * @returns The acceptable ranges, highest quality first.
 */
export function parseAcceptLanguage(header: string): readonly LanguagePreference[] {
  const entries: { readonly range: string; readonly q: number; readonly index: number }[] = [];
  header.split(",").forEach((raw, index) => {
    const [range, ...params] = raw.split(";").map((part) => part.trim());
    if (range === undefined || range === "") return;
    let q = 1;
    for (const param of params) {
      const [name, value] = param.split("=").map((part) => part.trim());
      if (name?.toLowerCase() !== "q") continue;
      if (value === undefined || !QVALUE.test(value)) return;
      q = Number(value);
    }
    if (q > 0) entries.push({ range, q, index });
  });
  return entries.sort((a, b) => b.q - a.q || a.index - b.index).map(({ range, q }) => ({ range, q }));
}
