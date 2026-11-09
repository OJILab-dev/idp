# Only non-secret values: certificates and fingerprints are public by design (docs/design/idpctl.md), and the zone
# rules are visible to anyone who probes the hostnames.

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

# Always output, whoever owns the zone: with zone_singletons_owner = "external" the zone's owner adds these rules
# to its entry point rulesets (keyed by phase) and these hostnames to its mTLS association; with "idp" it records
# what this Terraform applied (docs/design/domain-placement.md, 2).
output "zone_singletons" {
  description = "The IdP's zone singletons: the owner, the mTLS hostnames, and the rules per entry point phase."
  value = {
    owner          = var.zone_singletons_owner
    zone           = var.zone
    mtls_hostnames = local.zone_singletons.mtls_hostnames
    rulesets       = local.zone_singletons.rulesets
  }
}
