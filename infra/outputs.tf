# Only non-secret values: certificates and fingerprints are public by design (docs/design/idpctl.md).

output "admin_client_certificates" {
  description = "Per admin: the PEM client certificate for idpctl and the SHA-256 fingerprint for admin_allowlist."
  value = {
    for name, certificate in cloudflare_client_certificate.admin : name => {
      certificate = certificate.certificate
      # ADMIN_ALLOWLIST takes lowercase hex without separators; normalise whatever form the API returns.
      fingerprint_sha256 = lower(replace(certificate.fingerprint_sha256, ":", ""))
      expires_on         = certificate.expires_on
    }
  }
}
