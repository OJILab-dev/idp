# What Terraform owns is fixed by docs/design/deployment.md "Terraform とスクリプトの分担":
# the WAF custom rule (mTLS), the rate limiting rule, the mTLS hostname association, and the client
# certificates issued from CSRs, plus the zone settings Always Use HTTPS and the minimum TLS version.
# Not here, on purpose:
# - D1: created by scripts/bootstrap-d1.sh so that the plan token needs no D1 permission at all.
# - Worker custom domains and their DNS records: cloudflare.config.ts owns them and `cf deploy` attaches them.
# - Fail closed: provider 5.28.1 has no such attribute (cloudflare_workers_route has only pattern and script),
#   and both Workers use custom domains, not routes (docs/design/open-questions.md).

locals {
  # Free plan rate limiting fixes the counting period and the mitigation timeout to 10 seconds and counts per
  # IP per data center (Cloudflare "Rate limiting rules", Availability; docs/design/free-tier.md).
  rate_limit_period_seconds = 10

  # Provisional: a sign-in reaches the Worker about 4 to 5 times from the browser (/authorize,
  # /webauthn/auth/options, /webauthn/auth/verify, /authorize/resume), so 10 lets a person retry once within a
  # period. Replace it with the measured value (docs/design/open-questions.md, the request count of one sign-in).
  rate_limit_requests_per_period = 10

  # The Free plan allows only the path (and Verified Bot) in a rate limiting expression, never the host, so the
  # rule covers every hostname of the zone. The admin API (/v1/*) is added here because the admin hostname cannot
  # be named; the IdP Worker has no /v1/* path. Static asset pages are left out: assets are free and unlimited.
  rate_limited_exact_paths = [
    "/authorize",
    "/authorize/resume",
    "/token",
    "/userinfo",
    "/logout",
    "/jwks",
    "/.well-known/openid-configuration",
  ]
  rate_limited_path_wildcards = [
    "/webauthn/*",
    "/v1/*",
  ]

  rate_limit_expression = join(" or ", concat(
    [format("(http.request.uri.path in {%s})", join(" ", [for path in local.rate_limited_exact_paths : jsonencode(path)]))],
    [for pattern in local.rate_limited_path_wildcards : format("(http.request.uri.path wildcard %s)", jsonencode(pattern))],
  ))

  # cert_verified is true for a valid certificate even after it is revoked, so revocation must be checked in the
  # same rule (Cloudflare "mTLS related features", WAF for Client Certificates and Certificate Revocation).
  # http.host is the Host header as sent, so the match ignores case (admin_host is validated as lowercase) and also
  # takes the explicit default port. An odd form would otherwise skip the rule and reach the Worker: its own check
  # still refuses it, but the request has then used the daily request limit (docs/design/free-tier.md).
  admin_mtls_block_expression = format(
    "(lower(http.host) in {%s %s} and (not cf.tls_client_auth.cert_verified or cf.tls_client_auth.cert_revoked))",
    jsonencode(var.admin_host),
    jsonencode("${var.admin_host}:443"),
  )

  # Short enough that a forgotten certificate stops working within a year; long enough that renewal is a yearly chore.
  admin_certificate_validity_days = 365
}

# Plain http:// requests are redirected at the edge and never reach a Worker. The issuer, RP ID, and WebAuthn
# origin are all https (docs/design/deployment.md), and the Workers also refuse other schemes themselves.
resource "cloudflare_zone_setting" "always_use_https" {
  zone_id    = data.cloudflare_zone.this.zone_id
  setting_id = "always_use_https"
  value      = "on"
}

# RFC 8996 §§4-5: TLS 1.0 and 1.1 MUST NOT be used.
resource "cloudflare_zone_setting" "min_tls_version" {
  zone_id    = data.cloudflare_zone.this.zone_id
  setting_id = "min_tls_version"
  value      = "1.2"
}

data "cloudflare_zone" "this" {
  filter = {
    name = var.zone
    account = {
      id = var.account_id
    }
  }
}

# Enables mTLS on the admin hostname with the Cloudflare managed CA (no mtls_certificate_id means the managed CA).
# This resource holds the complete list of hostnames associated with the managed CA in the zone.
resource "cloudflare_certificate_authorities_hostname_associations" "admin" {
  zone_id   = data.cloudflare_zone.this.zone_id
  hostnames = [var.admin_host]
}

# Issued from the admin's own CSR, so the private key never reaches Cloudflare or Terraform state
# (docs/design/idpctl.md). The certificate and the CSR are not secrets.
resource "cloudflare_client_certificate" "admin" {
  for_each = var.admin_client_certificates

  zone_id       = data.cloudflare_zone.this.zone_id
  csr           = each.value
  validity_days = local.admin_certificate_validity_days
}

# The zone entry point ruleset of the custom rules phase. There is one per zone and phase, so this resource owns
# every custom rule of the zone.
resource "cloudflare_ruleset" "custom_rules" {
  zone_id     = data.cloudflare_zone.this.zone_id
  name        = "idp custom rules"
  description = "Blocks admin requests without a valid, unrevoked client certificate before they reach the Worker"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  rules = [
    {
      ref         = "idp_admin_mtls"
      description = "Admin hostname: block requests without a verified, unrevoked client certificate"
      expression  = local.admin_mtls_block_expression
      action      = "block"
      enabled     = true
    },
  ]
}

# The zone entry point ruleset of the rate limiting phase. The Free plan allows one rule, and this is it.
# Requests blocked here never reach a Worker, so they do not use the account's daily request limit.
resource "cloudflare_ruleset" "rate_limit" {
  zone_id     = data.cloudflare_zone.this.zone_id
  name        = "idp rate limiting"
  description = "Stops simple floods on the Worker endpoints before they use up the daily request limit"
  kind        = "zone"
  phase       = "http_ratelimit"

  rules = [
    {
      ref         = "idp_worker_endpoints"
      description = "IdP and admin Worker endpoints"
      expression  = local.rate_limit_expression
      action      = "block"
      enabled     = true
      ratelimit = {
        characteristics     = ["cf.colo.id", "ip.src"]
        period              = local.rate_limit_period_seconds
        requests_per_period = local.rate_limit_requests_per_period
        mitigation_timeout  = local.rate_limit_period_seconds
      }
    },
  ]
}
