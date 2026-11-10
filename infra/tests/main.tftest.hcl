# Runs offline: the mock provider answers every resource and data source, so no credential or network is used.
# These tests pin what the IdP owns in the zone (the client certificates and the admin host's mTLS association,
# nothing else) and the fail-closed input checks (docs/design/domain-placement.md, 2, and the admin_signing_keys
# and admin_rate_limit_namespace_id inputs of docs/design/hosting-modes.md 3.7 and 6.2).

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
  # The P-384 keyid vector of contract/testdata/vectors.json (a public key only).
  admin_signing_keys = [
    {
      keyid      = "5021275a9b968d7d198d5a7b402cee7ea30edd3e47811b1b2736ea7f8f185767"
      name       = "alice"
      public_key = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEZ26eOyy4/KQpxMCdT6VmqrMErkGHgSxubfgw/6bNU5YWsJaYOmEAq08VjZEJLiCYGqnDBAMnb3jDkOgxpxX6KvnW5H7LYjsz4lsJrXx/VrZJwwjK12UjHtec+hf5HoLT"
    },
  ]
  d1_database_name                  = "idp"
  rate_limit_namespace_id           = "1001"
  admin_rate_limit_namespace_id     = "1002"
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

# The admin Worker reads the list and refuses every request while it is empty (docs/design/hosting-modes.md 1.4).
run "rejects_an_empty_admin_signing_keys_list" {
  command = plan

  variables {
    admin_signing_keys = []
  }

  expect_failures = [var.admin_signing_keys]
}

run "accepts_two_keys_of_one_admin" {
  command = plan

  # The second key is the P-384 public key of RFC 6979 Appendix A.2.6, a published value. Its keyid is not its
  # SHA-256: Terraform cannot hash the decoded bytes, so that check is the script's and the admin Worker's.
  variables {
    admin_signing_keys = [
      {
        keyid      = "5021275a9b968d7d198d5a7b402cee7ea30edd3e47811b1b2736ea7f8f185767"
        name       = "alice"
        public_key = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEZ26eOyy4/KQpxMCdT6VmqrMErkGHgSxubfgw/6bNU5YWsJaYOmEAq08VjZEJLiCYGqnDBAMnb3jDkOgxpxX6KvnW5H7LYjsz4lsJrXx/VrZJwwjK12UjHtec+hf5HoLT"
      },
      {
        keyid      = "1111111111111111111111111111111111111111111111111111111111111111"
        name       = "alice"
        public_key = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE7DpOQVtOGaRWhhgCn0J/pdqai8SukuAuBqrlKGswDGTe+PDqkFWGYGSiVFFUgLwTgBXZty19VyROqO+awMYhiWcIpZNn+d+59UyoSz8cnbEoiyMcOuDU/nNE/SUzJkcg"
      },
    ]
  }
}

run "rejects_an_admin_signing_key_with_another_member" {
  command = plan

  variables {
    admin_signing_keys = [
      {
        keyid      = "5021275a9b968d7d198d5a7b402cee7ea30edd3e47811b1b2736ea7f8f185767"
        name       = "alice"
        public_key = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEZ26eOyy4/KQpxMCdT6VmqrMErkGHgSxubfgw/6bNU5YWsJaYOmEAq08VjZEJLiCYGqnDBAMnb3jDkOgxpxX6KvnW5H7LYjsz4lsJrXx/VrZJwwjK12UjHtec+hf5HoLT"
        alg        = "ecdsa-p384-sha384"
      },
    ]
  }

  expect_failures = [var.admin_signing_keys]
}

run "rejects_an_admin_signing_key_without_a_name" {
  command = plan

  variables {
    admin_signing_keys = [
      {
        keyid      = "5021275a9b968d7d198d5a7b402cee7ea30edd3e47811b1b2736ea7f8f185767"
        public_key = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEZ26eOyy4/KQpxMCdT6VmqrMErkGHgSxubfgw/6bNU5YWsJaYOmEAq08VjZEJLiCYGqnDBAMnb3jDkOgxpxX6KvnW5H7LYjsz4lsJrXx/VrZJwwjK12UjHtec+hf5HoLT"
      },
    ]
  }

  expect_failures = [var.admin_signing_keys]
}

run "rejects_an_uppercase_keyid" {
  command = plan

  variables {
    admin_signing_keys = [
      {
        keyid      = "5021275A9B968D7D198D5A7B402CEE7EA30EDD3E47811B1B2736EA7F8F185767"
        name       = "alice"
        public_key = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEZ26eOyy4/KQpxMCdT6VmqrMErkGHgSxubfgw/6bNU5YWsJaYOmEAq08VjZEJLiCYGqnDBAMnb3jDkOgxpxX6KvnW5H7LYjsz4lsJrXx/VrZJwwjK12UjHtec+hf5HoLT"
      },
    ]
  }

  expect_failures = [var.admin_signing_keys]
}

run "rejects_an_invalid_admin_name_in_admin_signing_keys" {
  command = plan

  variables {
    admin_signing_keys = [
      {
        keyid      = "5021275a9b968d7d198d5a7b402cee7ea30edd3e47811b1b2736ea7f8f185767"
        name       = "Alice"
        public_key = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEZ26eOyy4/KQpxMCdT6VmqrMErkGHgSxubfgw/6bNU5YWsJaYOmEAq08VjZEJLiCYGqnDBAMnb3jDkOgxpxX6KvnW5H7LYjsz4lsJrXx/VrZJwwjK12UjHtec+hf5HoLT"
      },
    ]
  }

  expect_failures = [var.admin_signing_keys]
}

run "rejects_a_public_key_that_is_not_p384" {
  command = plan

  # The Ed25519 key of RFC 9421 Appendix B.1.4 (contract/testdata/vectors.json).
  variables {
    admin_signing_keys = [
      {
        keyid      = "34571606cb7a0d71be377e671ddcccae2a169ed7733598214129231cd30c4a3c"
        name       = "alice"
        public_key = "MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs="
      },
    ]
  }

  expect_failures = [var.admin_signing_keys]
}

run "rejects_a_public_key_split_over_lines" {
  command = plan

  variables {
    admin_signing_keys = [
      {
        keyid      = "5021275a9b968d7d198d5a7b402cee7ea30edd3e47811b1b2736ea7f8f185767"
        name       = "alice"
        public_key = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEZ26eOyy4/KQpxMCdT6VmqrMErkGHgSxubfgw\n/6bNU5YWsJaYOmEAq08VjZEJLiCYGqnDBAMnb3jDkOgxpxX6KvnW5H7LYjsz4lsJrXx/VrZJwwjK12UjHtec+hf5HoLT"
      },
    ]
  }

  expect_failures = [var.admin_signing_keys]
}

run "rejects_a_keyid_with_a_trailing_newline" {
  command = plan

  variables {
    admin_signing_keys = [
      {
        keyid      = "5021275a9b968d7d198d5a7b402cee7ea30edd3e47811b1b2736ea7f8f185767\n"
        name       = "alice"
        public_key = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEZ26eOyy4/KQpxMCdT6VmqrMErkGHgSxubfgw/6bNU5YWsJaYOmEAq08VjZEJLiCYGqnDBAMnb3jDkOgxpxX6KvnW5H7LYjsz4lsJrXx/VrZJwwjK12UjHtec+hf5HoLT"
      },
    ]
  }

  expect_failures = [var.admin_signing_keys]
}

run "rejects_a_repeated_keyid" {
  command = plan

  variables {
    admin_signing_keys = [
      {
        keyid      = "5021275a9b968d7d198d5a7b402cee7ea30edd3e47811b1b2736ea7f8f185767"
        name       = "alice"
        public_key = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEZ26eOyy4/KQpxMCdT6VmqrMErkGHgSxubfgw/6bNU5YWsJaYOmEAq08VjZEJLiCYGqnDBAMnb3jDkOgxpxX6KvnW5H7LYjsz4lsJrXx/VrZJwwjK12UjHtec+hf5HoLT"
      },
      {
        keyid      = "5021275a9b968d7d198d5a7b402cee7ea30edd3e47811b1b2736ea7f8f185767"
        name       = "bob"
        public_key = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEZ26eOyy4/KQpxMCdT6VmqrMErkGHgSxubfgw/6bNU5YWsJaYOmEAq08VjZEJLiCYGqnDBAMnb3jDkOgxpxX6KvnW5H7LYjsz4lsJrXx/VrZJwwjK12UjHtec+hf5HoLT"
      },
    ]
  }

  expect_failures = [var.admin_signing_keys]
}

run "rejects_an_admin_rate_limit_namespace_id_that_is_not_a_positive_integer" {
  command = plan

  variables {
    admin_rate_limit_namespace_id = "01002"
  }

  expect_failures = [var.admin_rate_limit_namespace_id]
}

run "rejects_an_admin_rate_limit_namespace_id_equal_to_the_idp_one" {
  command = plan

  variables {
    admin_rate_limit_namespace_id = "1001"
  }

  expect_failures = [var.admin_rate_limit_namespace_id]
}

run "rejects_a_plan_environment_equal_to_the_deploy_environment" {
  command = plan

  variables {
    github_plan_environment = "test-deploy"
  }

  expect_failures = [var.github_plan_environment]
}
