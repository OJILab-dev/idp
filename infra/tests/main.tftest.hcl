# Runs offline: the mock provider answers every resource and data source, so no credential or network is used.
# These tests pin the rule expressions and the fail-closed input checks; whether Cloudflare accepts the rules on
# the Free plan is checked at bootstrap (docs/design/open-questions.md).

mock_provider "cloudflare" {
  # The provider checks the shape of zone_id even at plan time, so the mock must return a well-formed one.
  mock_data "cloudflare_zone" {
    defaults = {
      zone_id = "fedcba9876543210fedcba9876543210"
    }
  }
}

variables {
  account_id  = "0123456789abcdef0123456789abcdef"
  zone        = "example.com"
  issuer_host = "id.example.com"
  admin_host  = "admin.id.example.com"
  # "idp" is the mode that creates resources, so most runs check it; the "external" runs override it.
  zone_singletons_owner = "idp"
  admin_client_certificates = {
    alice = "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n"
  }
  admin_allowlist = [
    { sha256 = "0000000000000000000000000000000000000000000000000000000000000000", name = "alice" },
  ]
  d1_database_name                  = "idp"
  rate_limit_namespace_id           = "1001"
  state_bucket_name                 = "idp-tfstate"
  onepassword_vault                 = "idp-test"
  onepassword_cloudflare_item       = "cloudflare"
  onepassword_signing_key_item      = "signing-key"
  onepassword_admin_key_item_prefix = "admin-key-"
  onepassword_deploy_environment    = "idp-test-deploy"
  onepassword_plan_environment      = "idp-test-plan"
  github_deploy_environment         = "test-deploy"
  github_plan_environment           = "test-plan"
}

run "admin_rule_blocks_unverified_or_revoked_certificates_on_the_admin_host_only" {
  command = plan

  assert {
    condition     = cloudflare_ruleset.custom_rules[0].rules[0].expression == "(lower(http.host) in {\"admin.id.example.com\" \"admin.id.example.com:443\"} and (not cf.tls_client_auth.cert_verified or cf.tls_client_auth.cert_revoked))"
    error_message = "The admin mTLS rule expression changed."
  }

  # The Host header is not normalised: a client can send it in another case or with the default port. Both forms
  # must still hit the rule, or the request reaches the Worker and uses the daily request limit.
  assert {
    condition     = strcontains(cloudflare_ruleset.custom_rules[0].rules[0].expression, "lower(http.host)")
    error_message = "The admin host match must ignore case."
  }

  assert {
    condition     = strcontains(cloudflare_ruleset.custom_rules[0].rules[0].expression, "\"admin.id.example.com:443\"")
    error_message = "The admin host match must cover the explicit default port."
  }

  assert {
    condition     = cloudflare_ruleset.custom_rules[0].rules[0].action == "block" && cloudflare_ruleset.custom_rules[0].phase == "http_request_firewall_custom"
    error_message = "The admin mTLS rule must block in the custom rules phase."
  }

  assert {
    condition     = cloudflare_certificate_authorities_hostname_associations.admin[0].hostnames == tolist(["admin.id.example.com"])
    error_message = "mTLS must be enabled on the admin hostname only."
  }

  assert {
    condition     = cloudflare_certificate_authorities_hostname_associations.admin[0].mtls_certificate_id == null
    error_message = "mTLS must use the Cloudflare managed CA."
  }
}

run "rate_limit_rule_fits_the_free_plan_and_covers_the_worker_endpoints" {
  command = plan

  assert {
    condition     = cloudflare_ruleset.rate_limit[0].rules[0].expression == "(http.request.uri.path in {\"/authorize\" \"/authorize/resume\" \"/token\" \"/userinfo\" \"/logout\" \"/jwks\" \"/.well-known/openid-configuration\"}) or (http.request.uri.path wildcard \"/webauthn/*\") or (http.request.uri.path wildcard \"/v1/*\")"
    error_message = "The rate limiting expression changed."
  }

  assert {
    condition     = !strcontains(cloudflare_ruleset.rate_limit[0].rules[0].expression, "http.host")
    error_message = "Free plan rate limiting rules cannot use the hostname."
  }

  assert {
    condition = (
      cloudflare_ruleset.rate_limit[0].rules[0].ratelimit.period == 10 &&
      cloudflare_ruleset.rate_limit[0].rules[0].ratelimit.mitigation_timeout == 10 &&
      cloudflare_ruleset.rate_limit[0].rules[0].ratelimit.characteristics == tolist(["cf.colo.id", "ip.src"])
    )
    error_message = "Free plan rate limiting fixes the period and timeout to 10 seconds and counts per IP."
  }
}

run "issuer_redirect_sends_plain_http_on_the_issuer_host_only_to_https" {
  command = plan

  assert {
    condition     = cloudflare_ruleset.redirect[0].phase == "http_request_dynamic_redirect" && cloudflare_ruleset.redirect[0].rules[0].action == "redirect"
    error_message = "The HTTPS redirect must be a Single Redirect."
  }

  # The wildcard form is the one the Free plan supports; the host is in the pattern, so no other hostname of a
  # shared zone matches.
  assert {
    condition     = cloudflare_ruleset.redirect[0].rules[0].expression == "(http.request.full_uri wildcard \"http://id.example.com/*\")"
    error_message = "The redirect must match plain HTTP on the issuer host only."
  }

  assert {
    condition     = cloudflare_ruleset.redirect[0].rules[0].action_parameters.from_value.target_url.expression == "wildcard_replace(http.request.full_uri, \"http://id.example.com/*\", \"https://id.example.com/$${1}\")"
    error_message = "The redirect must keep the host, path, and query and change only the scheme."
  }

  # full_uri already carries the query string, which the wildcard captures; preserving it again would duplicate it.
  assert {
    condition = (
      cloudflare_ruleset.redirect[0].rules[0].action_parameters.from_value.status_code == 301 &&
      cloudflare_ruleset.redirect[0].rules[0].action_parameters.from_value.preserve_query_string == false
    )
    error_message = "The redirect must be a permanent 301 that does not append the query a second time."
  }

  assert {
    condition     = !strcontains(cloudflare_ruleset.redirect[0].rules[0].expression, "admin.id.example.com")
    error_message = "The admin host gets no redirect: the mTLS rule blocks plain requests there."
  }
}

run "idp_owner_creates_every_zone_singleton_from_the_output_definitions" {
  command = plan

  assert {
    condition = (
      length(cloudflare_ruleset.custom_rules) == 1 &&
      length(cloudflare_ruleset.rate_limit) == 1 &&
      length(cloudflare_ruleset.redirect) == 1 &&
      length(cloudflare_certificate_authorities_hostname_associations.admin) == 1
    )
    error_message = "With zone_singletons_owner = idp, Terraform owns all four zone singletons."
  }

  # The resources and the output share one definition, so what an external owner receives is what "idp" applies.
  assert {
    condition = (
      cloudflare_ruleset.custom_rules[0].rules[0].expression == output.zone_singletons.rulesets.http_request_firewall_custom[0].expression &&
      cloudflare_ruleset.rate_limit[0].rules[0].expression == output.zone_singletons.rulesets.http_ratelimit[0].expression &&
      cloudflare_ruleset.redirect[0].rules[0].expression == output.zone_singletons.rulesets.http_request_dynamic_redirect[0].expression &&
      output.zone_singletons.mtls_hostnames == ["admin.id.example.com"]
    )
    error_message = "The applied rules must equal the output definitions."
  }
}

run "external_owner_gets_only_the_definitions_and_keeps_the_client_certificates" {
  command = plan

  variables {
    zone_singletons_owner = "external"
  }

  assert {
    condition = (
      length(cloudflare_ruleset.custom_rules) == 0 &&
      length(cloudflare_ruleset.rate_limit) == 0 &&
      length(cloudflare_ruleset.redirect) == 0 &&
      length(cloudflare_certificate_authorities_hostname_associations.admin) == 0
    )
    error_message = "With zone_singletons_owner = external, Terraform must not create any zone singleton."
  }

  assert {
    condition     = keys(cloudflare_client_certificate.admin) == ["alice"]
    error_message = "The client certificates are not zone singletons; the IdP keeps issuing them."
  }

  assert {
    condition = (
      output.zone_singletons.owner == "external" &&
      output.zone_singletons.zone == "example.com" &&
      output.zone_singletons.mtls_hostnames == ["admin.id.example.com"] &&
      keys(output.zone_singletons.rulesets) == ["http_ratelimit", "http_request_dynamic_redirect", "http_request_firewall_custom"] &&
      strcontains(output.zone_singletons.rulesets.http_request_firewall_custom[0].expression, "cf.tls_client_auth.cert_revoked") &&
      output.zone_singletons.rulesets.http_ratelimit[0].ratelimit.requests_per_period == 10 &&
      output.zone_singletons.rulesets.http_request_dynamic_redirect[0].action_parameters.from_value.status_code == 301
    )
    error_message = "The external owner must receive every rule definition and the mTLS hostname."
  }
}

run "rejects_an_unknown_zone_singletons_owner" {
  command = plan

  variables {
    zone_singletons_owner = "service"
  }

  expect_failures = [var.zone_singletons_owner]
}

run "rejects_a_rate_limit_namespace_id_that_is_not_a_positive_integer" {
  command = plan

  variables {
    rate_limit_namespace_id = "0"
  }

  expect_failures = [var.rate_limit_namespace_id]
}

run "rejects_an_uppercase_admin_host" {
  command = plan

  variables {
    admin_host = "ADMIN.id.example.com"
  }

  expect_failures = [var.admin_host]
}

run "client_certificates_are_issued_from_the_configured_csrs" {
  command = plan

  assert {
    condition     = keys(cloudflare_client_certificate.admin) == ["alice"]
    error_message = "One client certificate per configured admin CSR."
  }
}

run "rejects_an_account_id_that_is_not_32_hex" {
  command = plan

  variables {
    account_id = "not-an-account"
  }

  expect_failures = [var.account_id]
}

run "rejects_an_admin_host_equal_to_the_issuer_host" {
  command = plan

  variables {
    admin_host = "id.example.com"
  }

  expect_failures = [var.admin_host]
}

run "rejects_an_admin_host_outside_the_zone" {
  command = plan

  variables {
    admin_host = "admin.example.net"
  }

  expect_failures = [var.admin_host]
}

run "rejects_an_issuer_host_outside_the_zone" {
  command = plan

  variables {
    issuer_host = "id.example.net"
    admin_host  = "admin.id.example.com"
  }

  expect_failures = [var.issuer_host]
}

run "rejects_an_uppercase_or_separated_allowlist_fingerprint" {
  command = plan

  variables {
    admin_allowlist = [
      { sha256 = "AA:BB", name = "alice" },
    ]
  }

  expect_failures = [var.admin_allowlist]
}

run "rejects_a_repeated_allowlist_fingerprint" {
  command = plan

  variables {
    admin_allowlist = [
      { sha256 = "0000000000000000000000000000000000000000000000000000000000000000", name = "alice" },
      { sha256 = "0000000000000000000000000000000000000000000000000000000000000000", name = "bob" },
    ]
  }

  expect_failures = [var.admin_allowlist]
}

run "rejects_a_csr_that_is_not_pem" {
  command = plan

  variables {
    admin_client_certificates = {
      alice = "not a csr"
    }
  }

  expect_failures = [var.admin_client_certificates]
}

run "rejects_a_plan_environment_equal_to_the_deploy_environment" {
  command = plan

  variables {
    github_plan_environment = "test-deploy"
  }

  expect_failures = [var.github_plan_environment]
}
