// The static pages' own safety: no inline script or style in the files, and the CSP and framing rules of _headers.
// The Worker runs first and sets the same headers on every response it returns, the pages included; _headers stays
// so that the pages keep them should the Worker ever stop running first.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { en } from "../pages/locales/en.js";
import { ja } from "../pages/locales/ja.js";

const pagesDir = join(import.meta.dirname, "..", "pages");
const PAGES = ["signin", "enroll", "account"] as const;

function read(name: string): string {
  return readFileSync(join(pagesDir, name), "utf8");
}

describe("static pages", () => {
  it.each(PAGES)("%s.html loads only its own module script and stylesheet", (page) => {
    const html = read(`${page}.html`);
    const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)];
    expect(scripts).toHaveLength(1);
    expect(scripts[0]?.[1]).toContain(`type="module" src="./${page}.ts"`);
    expect(scripts[0]?.[2]?.trim()).toBe("");
    expect(html).not.toMatch(/<style|style=|\son[a-z]+=|javascript:/i);
    expect(html).not.toMatch(/https?:\/\//);
  });

  it("_headers gives every page a strict CSP and denies framing", () => {
    const headers = read("public/_headers");
    for (const page of PAGES) {
      const block = headers.split(/\n(?=\S)/).find((b) => b.startsWith(`/${page}\n`));
      expect(block, page).toBeDefined();
      expect(block).toContain("Content-Security-Policy: default-src 'self'; frame-ancestors 'none'");
      expect(block).toContain("X-Frame-Options: DENY");
      expect(block).toContain("X-Content-Type-Options: nosniff");
      expect(block).toContain("Referrer-Policy: no-referrer");
    }
  });

  it("has the same messages in every language", () => {
    expect(Object.keys(ja).sort()).toEqual(Object.keys(en).sort());
  });

  it("type-checks the browser code against the DOM library", () => {
    const configPath = join(pagesDir, "tsconfig.json");
    const config = ts.getParsedCommandLineOfConfigFile(configPath, {}, { ...ts.sys, onUnRecoverableConfigFileDiagnostic: () => undefined });
    if (config === undefined) throw new Error("pages/tsconfig.json is unreadable");
    const program = ts.createProgram(config.fileNames, config.options);
    const diagnostics = ts.getPreEmitDiagnostics(program).map((d) => ts.flattenDiagnosticMessageText(d.messageText, "\n"));
    expect(diagnostics).toEqual([]);
    expect(config.fileNames.map((name) => name.slice(pagesDir.length + 1)).sort()).toEqual(
      expect.arrayContaining(["account.ts", "enroll.ts", "signin.ts"]),
    );
  }, 60_000);
});
