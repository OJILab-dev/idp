import { describe, expect, it } from "vitest";
import { selectUiLocale } from "../src/user/index.js";
import { vectors } from "./vectors.js";

describe("selectUiLocale (contract vectors)", () => {
  it.each(vectors.ui_locale)("$case", ({ ui_locales, accept_language, locale }) => {
    expect(selectUiLocale(ui_locales ?? undefined, accept_language ?? undefined)).toBe(locale);
  });
});
