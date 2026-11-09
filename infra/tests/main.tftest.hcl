# Runs offline: the mock provider answers every resource and data source, so no credential or network is used.
# These tests pin what the IdP owns in the zone (the client certificates and the admin host's mTLS association,
# nothing else) and the fail-closed input checks (docs/design/domain-placement.md, 2).

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

run "mtls_is_enabled_on_the_admin_hostname_only_with_the_managed_ca" {
  command = plan

  # The association holds the zone's complete list, so the issuer host (and any of the service's hosts) must not be
  # in it: a browser on the issuer would otherwise be asked for a client certificate.
  assert {
    condition     = cloudflare_certificate_authorities_hostname_associations.admin.hostnames == tolist(["admin.id.example.com"])
    error_message = "mTLS must be enabled on the admin hostname only."
  }

  assert {
    condition     = cloudflare_certificate_authorities_hostname_associations.admin.mtls_certificate_id == null
    error_message = "mTLS must use the Cloudflare managed CA."
  }

  assert {
    condition     = cloudflare_certificate_authorities_hostname_associations.admin.zone_id == "fedcba9876543210fedcba9876543210"
    error_message = "The association must be made in the deployment's zone."
  }
}

run "client_certificates_are_issued_from_the_configured_csrs" {
  command = plan

  assert {
    condition     = keys(cloudflare_client_certificate.admin) == ["alice"]
    error_message = "One client certificate per configured admin CSR."
  }

  assert {
    condition     = cloudflare_client_certificate.admin["alice"].validity_days == 365
    error_message = "An admin certificate is valid for one year."
  }
}

run "no_admin_certificate_still_keeps_the_admin_host_under_mtls" {
  command = plan

  variables {
    admin_client_certificates = {}
  }

  assert {
    condition     = length(cloudflare_client_certificate.admin) == 0 && cloudflare_certificate_authorities_hostname_associations.admin.hostnames == tolist(["admin.id.example.com"])
    error_message = "The mTLS association does not depend on how many certificates are issued."
  }
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
