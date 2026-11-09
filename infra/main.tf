# What Terraform owns is fixed by docs/design/deployment.md "Terraform とスクリプトの分担": the client certificates
# issued from CSRs, and the mTLS hostname association of the admin host. Nothing else in the zone.
#
# The zone may be shared with the service the IdP serves, and its other records and rules are managed elsewhere
# (docs/design/domain-placement.md, A2). The IdP therefore holds no zone ruleset at all: a zone's entry point
# ruleset exists once per phase and Terraform owns it whole, so owning one would take the service's rules with it.
# The Workers enforce what the zone rules used to (docs/design/domain-placement.md, 3 and 4):
# - plain HTTP: the IdP Worker runs first on every request and redirects or refuses it; the admin Worker refuses it.
# - TLS below 1.2: both Workers refuse it.
# - requests without a valid admin certificate: the admin Worker's gate refuses them.
# - floods: the IdP Worker's Rate Limiting binding.
# No zone-wide setting (Always Use HTTPS, minimum TLS version) is set here either: those belong to the zone's owner.
#
# Not here, on purpose:
# - D1: created by scripts/bootstrap-d1.sh so that the plan token needs no D1 permission at all.
# - Worker custom domains and their DNS records: cloudflare.config.ts owns them and `cf deploy` attaches them.

locals {
  # Short enough that a forgotten certificate stops working within a year; long enough that renewal is a yearly chore.
  admin_certificate_validity_days = 365
}

data "cloudflare_zone" "this" {
  filter = {
    name = var.zone
    account = {
      id = var.account_id
    }
  }
}

# Issued from the admin's own CSR, so the private key never reaches Cloudflare or Terraform state
# (docs/design/idpctl.md). The certificate and the CSR are not secrets.
resource "cloudflare_client_certificate" "admin" {
  for_each = var.admin_client_certificates

  zone_id       = data.cloudflare_zone.this.zone_id
  csr           = each.value
  validity_days = local.admin_certificate_validity_days
}

# Enables mTLS on the admin hostname with the Cloudflare managed CA (no mtls_certificate_id means the managed CA), so
# that the edge asks for a client certificate and reports the result to the admin Worker in request.cf. Nothing at
# the edge blocks a request without one; the admin Worker's gate does (docs/design/idpctl.md).
#
# This resource holds the complete list of hostnames associated with the managed CA in the zone. The IdP owns it
# because nothing else in the zone uses mTLS; bootstrap checks that before the first apply, and a service that
# later needs mTLS in the same zone reopens this decision (docs/design/domain-placement.md, 2).
resource "cloudflare_certificate_authorities_hostname_associations" "admin" {
  zone_id   = data.cloudflare_zone.this.zone_id
  hostnames = [var.admin_host]
}

# The association used to be counted by zone_singletons_owner; a state that already holds it keeps it rather than
# replacing it (a replacement would briefly leave the admin host without mTLS).
moved {
  from = cloudflare_certificate_authorities_hostname_associations.admin[0]
  to   = cloudflare_certificate_authorities_hostname_associations.admin
}
