// The hosting mode's host rules (docs/design/hosting-modes.md 1.3 and 1.4): the mode is checked against the issuer and
// the admin host so that a configuration mixing the two modes refuses to run.
import { describe, expect, it } from "vitest";
import { InvalidHostingError, checkHostingHosts, parseHostingMode } from "../src/index.js";

describe("parseHostingMode", () => {
  it.each(["custom_domain", "workers_dev"])("accepts %s", (mode) => {
    expect(parseHostingMode(mode)).toBe(mode);
  });

  // No default: a deployment that forgot the mode must stop, not run as one of them (1.1).
  it.each([undefined, "", "CUSTOM_DOMAIN", "custom-domain", "workers.dev", " workers_dev"])("refuses %j", (value) => {
    expect(() => parseHostingMode(value)).toThrow(InvalidHostingError);
  });
});

describe("checkHostingHosts", () => {
  it("accepts custom domains outside workers.dev in the custom_domain mode", () => {
    expect(() => checkHostingHosts("custom_domain", "idp.example.com", "admin.example.com")).not.toThrow();
  });

  it.each([
    ["an issuer under workers.dev", "idp.team.workers.dev", "admin.example.com"],
    ["an admin host under workers.dev", "idp.example.com", "idp-admin.team.workers.dev"],
    ["workers.dev itself", "workers.dev", "admin.example.com"],
  ])("refuses %s in the custom_domain mode", (_label, issuer, admin) => {
    expect(() => checkHostingHosts("custom_domain", issuer, admin)).toThrow(InvalidHostingError);
  });

  it("accepts the derived hosts of one subdomain in the workers_dev mode", () => {
    expect(() => checkHostingHosts("workers_dev", "idp.team-1.workers.dev", "idp-admin.team-1.workers.dev")).not.toThrow();
  });

  it.each([
    ["a custom issuer", "idp.example.com", "idp-admin.team.workers.dev"],
    ["a custom admin host", "idp.team.workers.dev", "admin.example.com"],
    ["another Worker name for the issuer", "auth.team.workers.dev", "idp-admin.team.workers.dev"],
    ["another Worker name for the admin host", "idp.team.workers.dev", "admin.team.workers.dev"],
    ["two subdomains", "idp.team.workers.dev", "idp-admin.other.workers.dev"],
    ["a nested subdomain", "idp.a.team.workers.dev", "idp-admin.a.team.workers.dev"],
    ["a subdomain with a leading hyphen", "idp.-team.workers.dev", "idp-admin.-team.workers.dev"],
    ["a subdomain with a trailing hyphen", "idp.team-.workers.dev", "idp-admin.team-.workers.dev"],
    ["a subdomain of 64 characters", `idp.${"a".repeat(64)}.workers.dev`, `idp-admin.${"a".repeat(64)}.workers.dev`],
  ])("refuses %s in the workers_dev mode", (_label, issuer, admin) => {
    expect(() => checkHostingHosts("workers_dev", issuer, admin)).toThrow(InvalidHostingError);
  });

  it("checks the issuer alone when there is no admin host (the IdP Worker)", () => {
    expect(() => checkHostingHosts("workers_dev", "idp.team.workers.dev")).not.toThrow();
    expect(() => checkHostingHosts("custom_domain", "idp.team.workers.dev")).toThrow(InvalidHostingError);
  });
});
