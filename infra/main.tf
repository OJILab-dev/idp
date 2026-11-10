# What Terraform owns is fixed by docs/design/deployment.md "Terraform とスクリプトの分担". Today that is nothing in
# the zone: the IdP looks the zone up and owns no resource there.
#
# The zone may be shared with the service the IdP serves, and its other records and rules are managed elsewhere
# (docs/design/domain-placement.md, A2). The IdP therefore holds no zone ruleset and no zone singleton at all: a
# zone's entry point ruleset, or its list of hostnames associated with the managed CA, exists once per zone and
# Terraform owns it whole, so owning one would take the service's settings with it.
# The Workers enforce what the zone rules used to (docs/design/domain-placement.md, 3 and 4):
# - plain HTTP: the IdP Worker runs first on every request and redirects or refuses it; the admin Worker refuses it.
# - TLS below 1.2: both Workers refuse it.
# - requests without a valid admin signature: the admin Worker's gate refuses them (RFC 9421,
#   docs/design/hosting-modes.md 3).
# - floods: the Rate Limiting bindings of both Workers.
# No zone-wide setting (Always Use HTTPS, minimum TLS version) is set here either: those belong to the zone's owner.
#
# The admin host's mTLS association and the admin client certificates were removed with mTLS (plan step 7 of
# docs/design/hosting-modes.md). They are deleted, not kept as `removed` blocks: no deployment ever applied them,
# so no state can hold them (docs/design/hosting-modes.md 10).
#
# Not here, on purpose:
# - D1: created by scripts/bootstrap-d1.sh so that the plan token needs no D1 permission at all.
# - Worker custom domains and their DNS records: cloudflare.config.ts owns them and `cf deploy` attaches them.

# Looked up so that a zone name outside the account stops the plan, and so that DNS records or fail-closed settings
# can be added here later without a new input (docs/design/deployment.md). Only in the custom_domain mode: the
# workers_dev mode has no zone, and its tokens hold no zone permission (docs/design/hosting-modes.md 1.2).
data "cloudflare_zone" "this" {
  count = var.hosting_mode == "custom_domain" ? 1 : 0

  filter = {
    name = var.zone
    account = {
      id = var.account_id
    }
  }
}
