# What Terraform owns is fixed by docs/design/deployment.md "Terraform とスクリプトの分担": the client certificates
# issued from CSRs, and the IdP's zone rules (the admin mTLS custom rule, the rate limiting rule, the issuer's
# HTTPS redirect) with the mTLS hostname association.
#
# The zone may be shared with the service the IdP serves (docs/design/domain-placement.md, A2), so:
# - Every rule is scoped to the IdP's hostnames wherever Cloudflare allows it.
# - No zone-wide setting (Always Use HTTPS, minimum TLS version) is set here: those belong to the zone's owner and
#   would change the service's other hostnames. The Workers refuse plain HTTP and TLS below 1.2 themselves.
# - The entry point rulesets and the mTLS hostname association exist once per zone (Cloudflare "Rulesets", entry
#   point ruleset), so exactly one repository may own them. zone_singletons_owner picks it: "idp" creates them
#   here; "external" only outputs their definitions (output zone_singletons) for the zone's owner to apply.
#
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
  # The IdP Worker's Rate Limiting binding uses the same period and limit (apps/worker/cloudflare.config.ts).
  rate_limit_requests_per_period = 10

  # The Free plan allows only the path (and Verified Bot) in a rate limiting expression, never the host, so the
  # rule covers every hostname of the zone, the service's included (docs/design/domain-placement.md, 4). The
  # admin API (/v1/*) is added here because the admin hostname cannot be named; the IdP Worker has no /v1/*
  # path. Static asset pages are left out: assets are free and unlimited.
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

  # A Single Redirect in the wildcard form, the form the Free plan supports (wildcards yes, regular expressions no;
  # Cloudflare "URL forwarding", Availability). http.request.full_uri carries the query string, so the wildcard
  # captures it and the query is not preserved a second time. Only the issuer host matches: the service's other
  # hostnames keep whatever the zone's owner decides, and the admin host needs no redirect because a plain request
  # carries no client certificate and the mTLS rule blocks it. Whether the API accepts this form on a Free zone
  # is checked at the first apply (docs/design/open-questions.md).
  issuer_http_pattern  = "http://${var.issuer_host}/*"
  issuer_https_target  = "https://${var.issuer_host}/$${1}"
  issuer_redirect_from = format("(http.request.full_uri wildcard %s)", jsonencode(local.issuer_http_pattern))
  issuer_redirect_to = format(
    "wildcard_replace(http.request.full_uri, %s, %s)",
    jsonencode(local.issuer_http_pattern),
    jsonencode(local.issuer_https_target),
  )

  # Short enough that a forgotten certificate stops working within a year; long enough that renewal is a yearly chore.
  admin_certificate_validity_days = 365

  # The single source of the IdP's zone singletons. The resources below apply these exact values when the IdP
  # owns the zone, and output.zone_singletons hands the same values to an external owner, so the definition is
  # reviewed in this repository either way (docs/design/domain-placement.md, 2).
  zone_singletons = {
    mtls_hostnames = [var.admin_host]
    rulesets = {
      http_request_firewall_custom = [
        {
          ref         = "idp_admin_mtls"
          description = "IdP admin hostname: block requests without a verified, unrevoked client certificate"
          expression  = local.admin_mtls_block_expression
          action      = "block"
          enabled     = true
        },
      ]
      http_ratelimit = [
        {
          ref         = "idp_worker_endpoints"
          description = "IdP and admin Worker endpoints (path only on the Free plan)"
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
      http_request_dynamic_redirect = [
        {
          ref         = "idp_issuer_https"
          description = "IdP issuer hostname: redirect plain HTTP to HTTPS"
          expression  = local.issuer_redirect_from
          action      = "redirect"
          enabled     = true
          action_parameters = {
            from_value = {
              status_code           = 301
              preserve_query_string = false
              target_url = {
                expression = local.issuer_redirect_to
              }
            }
          }
        },
      ]
    }
  }

  owns_zone_singletons = var.zone_singletons_owner == "idp"
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
# (docs/design/idpctl.md). The certificate and the CSR are not secrets. Each certificate is its own resource, not a
# zone singleton, so the IdP keeps them whoever owns the zone's rules.
resource "cloudflare_client_certificate" "admin" {
  for_each = var.admin_client_certificates

  zone_id       = data.cloudflare_zone.this.zone_id
  csr           = each.value
  validity_days = local.admin_certificate_validity_days
}

# Enables mTLS on the admin hostname with the Cloudflare managed CA (no mtls_certificate_id means the managed CA).
# This resource holds the complete list of hostnames associated with the managed CA in the zone.
resource "cloudflare_certificate_authorities_hostname_associations" "admin" {
  count = local.owns_zone_singletons ? 1 : 0

  zone_id   = data.cloudflare_zone.this.zone_id
  hostnames = local.zone_singletons.mtls_hostnames
}

# The zone entry point ruleset of the custom rules phase; it owns every custom rule of the zone.
resource "cloudflare_ruleset" "custom_rules" {
  count = local.owns_zone_singletons ? 1 : 0

  zone_id     = data.cloudflare_zone.this.zone_id
  name        = "idp custom rules"
  description = "Blocks admin requests without a valid, unrevoked client certificate before they reach the Worker"
  kind        = "zone"
  phase       = "http_request_firewall_custom"
  rules       = local.zone_singletons.rulesets.http_request_firewall_custom
}

# The zone entry point ruleset of the rate limiting phase. The Free plan allows one rule, and this is it.
# Requests blocked here never reach a Worker, so they do not use the account's daily request limit.
resource "cloudflare_ruleset" "rate_limit" {
  count = local.owns_zone_singletons ? 1 : 0

  zone_id     = data.cloudflare_zone.this.zone_id
  name        = "idp rate limiting"
  description = "Stops simple floods on the Worker endpoints before they use up the daily request limit"
  kind        = "zone"
  phase       = "http_ratelimit"
  rules       = local.zone_singletons.rulesets.http_ratelimit
}

# The zone entry point ruleset of the Single Redirects phase, in place of the zone-wide Always Use HTTPS.
resource "cloudflare_ruleset" "redirect" {
  count = local.owns_zone_singletons ? 1 : 0

  zone_id     = data.cloudflare_zone.this.zone_id
  name        = "idp redirects"
  description = "Redirects plain HTTP on the issuer hostname to HTTPS before it reaches the Worker"
  kind        = "zone"
  phase       = "http_request_dynamic_redirect"
  rules       = local.zone_singletons.rulesets.http_request_dynamic_redirect
}
