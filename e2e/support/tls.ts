// The issuer must be exactly https://<host> (the Worker refuses anything else), so the local IdP is served over TLS
// with a certificate generated for this run only; the RP stand-in serves the same one. It never leaves e2e/.output and
// is never committed.
import { execFile } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

/** A throwaway certificate for one host, and the key that goes with it. */
export type TestCertificate = {
  readonly keyPem: string;
  readonly certPem: string;
  /** base64(SHA-256(SubjectPublicKeyInfo)), the form Chromium's --ignore-certificate-errors-spki-list takes. */
  readonly spkiSha256: string;
};

/**
 * Generates a self-signed P-256 certificate for the hosts, valid for one day, with openssl.
 *
 * @param hosts The DNS names in the subjectAltName; the first is also the CN.
 * @param dir The directory the PEM files are written to.
 * @returns The PEM strings and the SPKI hash.
 * @throws {Error} openssl is missing or fails.
 */
export async function generateCertificate(hosts: readonly [string, ...string[]], dir: string): Promise<TestCertificate> {
  await mkdir(dir, { recursive: true });
  const keyFile = join(dir, "key.pem");
  const certFile = join(dir, "cert.pem");
  await promisify(execFile)("openssl", [
    "req",
    "-x509",
    "-newkey",
    "ec",
    "-pkeyopt",
    "ec_paramgen_curve:prime256v1",
    "-nodes",
    "-keyout",
    keyFile,
    "-out",
    certFile,
    "-days",
    "1",
    "-subj",
    `/CN=${hosts[0]}`,
    "-addext",
    `subjectAltName=${hosts.map((host) => `DNS:${host}`).join(",")}`,
  ]);
  const [keyPem, certPem] = await Promise.all([readFile(keyFile, "utf8"), readFile(certFile, "utf8")]);
  const spki = new X509Certificate(certPem).publicKey.export({ type: "spki", format: "der" });
  return { keyPem, certPem, spkiSha256: createHash("sha256").update(spki).digest("base64") };
}
