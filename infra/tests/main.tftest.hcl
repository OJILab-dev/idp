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
  admin_client_certificates = {
    alice = "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n"
  }
  admin_allowlist = [
    { sha256 = "0000000000000000000000000000000000000000000000000000000000000000", name = "alice" },
  ]
  d1_database_name                  = "idp"
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
    condition     = cloudflare_ruleset.custom_rules.rules[0].expression == "(http.host eq \"admin.id.example.com\" and (not cf.tls_client_auth.cert_verified or cf.tls_client_auth.cert_revoked))"
    error_message = "The admin mTLS rule expression changed."
  }

  assert {
    condition     = cloudflare_ruleset.custom_rules.rules[0].action == "block" && cloudflare_ruleset.custom_rules.phase == "http_request_firewall_custom"
    error_message = "The admin mTLS rule must block in the custom rules phase."
  }

  assert {
    condition     = cloudflare_certificate_authorities_hostname_associations.admin.hostnames == tolist(["admin.id.example.com"])
    error_message = "mTLS must be enabled on the admin hostname only."
  }

  assert {
    condition     = cloudflare_certificate_authorities_hostname_associations.admin.mtls_certificate_id == null
    error_message = "mTLS must use the Cloudflare managed CA."
  }
}

run "rate_limit_rule_fits_the_free_plan_and_covers_the_worker_endpoints" {
  command = plan

  assert {
    condition     = cloudflare_ruleset.rate_limit.rules[0].expression == "(http.request.uri.path in {\"/authorize\" \"/authorize/resume\" \"/token\" \"/userinfo\" \"/logout\" \"/jwks\" \"/.well-known/openid-configuration\"}) or (http.request.uri.path wildcard \"/webauthn/*\") or (http.request.uri.path wildcard \"/v1/*\")"
    error_message = "The rate limiting expression changed."
  }

  assert {
    condition     = !strcontains(cloudflare_ruleset.rate_limit.rules[0].expression, "http.host")
    error_message = "Free plan rate limiting rules cannot use the hostname."
  }

  assert {
    condition = (
      cloudflare_ruleset.rate_limit.rules[0].ratelimit.period == 10 &&
      cloudflare_ruleset.rate_limit.rules[0].ratelimit.mitigation_timeout == 10 &&
      cloudflare_ruleset.rate_limit.rules[0].ratelimit.characteristics == tolist(["cf.colo.id", "ip.src"])
    )
    error_message = "Free plan rate limiting fixes the period and timeout to 10 seconds and counts per IP."
  }
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
