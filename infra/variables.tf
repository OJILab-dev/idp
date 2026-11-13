# Every value that differs between deployments is a variable here, with no default: a missing input must stop
# Terraform before it changes anything (fail-closed, docs/design/deployment.md "デプロイごとの入力"). The removed
# inputs at the end are the exception: they default to null so that only their absence passes.
#
# All variables except account_id come from deployments/<deployment>.tfvars.json via -var-file. The scripts and
# CI read the same file, so Terraform declares every key in it, including the ones only they use; an
# undeclared key would only warn, and a typo in a key would then go unnoticed.

variable "account_id" {
  description = "Cloudflare account ID. Comes from 1Password as TF_VAR_account_id and is never written to the repository."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.account_id))
    error_message = "account_id must be a Cloudflare account ID (32 lowercase hex characters)."
  }
}

# The hosting mode decides which of the inputs below a deployment must have and which it must not
# (docs/design/hosting-modes.md 1.1). It has no default. The inputs of only one mode default to null, so that the
# other mode can leave them out, and each one checks against the mode that it is present exactly when its mode needs
# it. Terraform cannot tell an explicit null from a missing key, so `"zone": null` passes here in the workers_dev
# mode; scripts/lib.sh (check_hosting_inputs) is the authority on whether a key is present and stops on it first.

variable "hosting_mode" {
  description = "Where the two Workers are served: custom_domain (custom domains in the zone) or workers_dev (<worker>.<workers_dev_subdomain>.workers.dev, no zone). No default (docs/design/hosting-modes.md 1.1)."
  type        = string
  nullable    = false

  validation {
    condition     = contains(["custom_domain", "workers_dev"], var.hosting_mode)
    error_message = "hosting_mode must be custom_domain or workers_dev (docs/design/hosting-modes.md 1.1)."
  }
}

variable "zone" {
  description = "custom_domain only: the zone (domain) that holds the issuer and admin hostnames. The zone ID is looked up from it."
  type        = string
  default     = null

  validation {
    condition     = (var.hosting_mode == "custom_domain") == (var.zone != null)
    error_message = "zone is required in the custom_domain mode and forbidden in the workers_dev mode (docs/design/hosting-modes.md 1.1)."
  }

  validation {
    condition     = var.zone == null || can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$", var.zone))
    error_message = "zone must be a lowercase domain name."
  }

  # The issuer and admin hosts are inside the zone, so this keeps every custom_domain host off workers.dev, where
  # the hosts belong to the other mode (docs/design/hosting-modes.md 1.4).
  validation {
    condition     = var.zone == null || !try(var.zone == "workers.dev" || endswith(var.zone, ".workers.dev"), true)
    error_message = "zone must not be workers.dev or under it; use the workers_dev mode instead (docs/design/hosting-modes.md 1.4)."
  }
}

variable "issuer_host" {
  description = "custom_domain only: hostname of the IdP Worker (the issuer is https://<issuer_host>). The Worker's custom domain owns its DNS record. In workers_dev the host is derived from workers_dev_subdomain."
  type        = string
  default     = null

  validation {
    condition     = (var.hosting_mode == "custom_domain") == (var.issuer_host != null)
    error_message = "issuer_host is required in the custom_domain mode and forbidden in the workers_dev mode, where it is derived (docs/design/hosting-modes.md 1.3)."
  }

  # Skipped without a zone: the zone's own check reports that.
  validation {
    condition     = var.issuer_host == null || var.zone == null || try(var.issuer_host == var.zone || endswith(var.issuer_host, ".${var.zone}"), false)
    error_message = "issuer_host must be the zone itself or a name inside it."
  }
}

variable "admin_host" {
  description = "custom_domain only: hostname of the admin Worker. Terraform only checks it; the admin Worker's custom domain owns its DNS record. In workers_dev the host is derived from workers_dev_subdomain."
  type        = string
  default     = null

  validation {
    condition     = (var.hosting_mode == "custom_domain") == (var.admin_host != null)
    error_message = "admin_host is required in the custom_domain mode and forbidden in the workers_dev mode, where it is derived (docs/design/hosting-modes.md 1.3)."
  }

  # Lowercase only: the admin Worker compares it with the request URL's host, which is always lowercase.
  validation {
    condition     = var.admin_host == null || can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$", var.admin_host))
    error_message = "admin_host must be a lowercase hostname without a port."
  }

  validation {
    condition     = var.admin_host == null || var.zone == null || try(endswith(var.admin_host, ".${var.zone}") && var.admin_host != var.issuer_host, false)
    error_message = "admin_host must be a name inside the zone and must differ from issuer_host (docs/design/idpctl.md)."
  }
}

variable "workers_dev_subdomain" {
  description = "workers_dev only: the account's workers.dev subdomain label (<label>.workers.dev). The issuer is https://idp.<label>.workers.dev and the admin host idp-admin.<label>.workers.dev (docs/design/hosting-modes.md 1.3). Terraform does not use it; scripts/check-workers-dev-subdomain.sh compares it with the account."
  type        = string
  default     = null

  validation {
    condition     = (var.hosting_mode == "workers_dev") == (var.workers_dev_subdomain != null)
    error_message = "workers_dev_subdomain is required in the workers_dev mode and forbidden in the custom_domain mode (docs/design/hosting-modes.md 1.1)."
  }

  validation {
    condition     = var.workers_dev_subdomain == null || can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.workers_dev_subdomain))
    error_message = "workers_dev_subdomain must be one DNS label: lowercase letters, digits, and hyphens, 1 to 63 characters, no hyphen at either end."
  }
}

variable "admin_signing_keys" {
  description = "ADMIN_SIGNING_KEYS of the admin Worker: rows of keyid, name, and public_key written by scripts/generate-admin-key.sh. Terraform does not use it; it is declared so the shared deployment file is checked here too."
  # A list of maps, not of objects: converting to an object type silently drops unknown members, and a row with an
  # extra member must stop here, as it stops the admin Worker (docs/design/hosting-modes.md 3.7). map(string) still
  # converts a JSON number or boolean member to a string; the script and the admin Worker refuse those.
  type     = list(map(string))
  nullable = false

  # An empty list is refused: the admin Worker reads this list as ADMIN_SIGNING_KEYS and refuses every request while
  # it is empty (docs/design/hosting-modes.md 1.1 and 1.4). A new deployment adds its first row with
  # scripts/generate-admin-key.sh (docs/deployment/runbook.md, stage 4a) before Terraform runs (stage 4b).
  validation {
    condition     = length(var.admin_signing_keys) > 0
    error_message = "admin_signing_keys must not be empty; add a row with scripts/generate-admin-key.sh (docs/deployment/runbook.md, stage 4a)."
  }

  validation {
    # Compared as one string: a list never equals a tuple literal in Terraform.
    condition     = alltrue([for row in var.admin_signing_keys : join(",", sort(keys(row))) == "keyid,name,public_key"])
    error_message = "admin_signing_keys rows must have exactly the members keyid, name, and public_key (docs/design/hosting-modes.md 3.7)."
  }

  validation {
    condition = alltrue([for row in var.admin_signing_keys :
      can(regex("^[0-9a-f]{64}$", row["keyid"])) && can(regex("^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$", row["name"]))
    ])
    error_message = "admin_signing_keys rows must have a lowercase 64-hex keyid and an admin name (docs/design/idpctl.md)."
  }

  # Terraform cannot hash the decoded bytes, so here public_key is only held to the base64 form of a P-384
  # SubjectPublicKeyInfo with an uncompressed point: these 32 characters encode its fixed 24-byte DER prefix, and
  # the 120-byte DER is 160 characters. scripts/generate-admin-key.sh checks that keyid is the SHA-256 of the DER
  # and that the point is on the curve, and so does the admin Worker at start.
  validation {
    condition     = alltrue([for row in var.admin_signing_keys : can(regex("^MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE[A-Za-z0-9+/]{128}$", row["public_key"]))])
    error_message = "admin_signing_keys public_key must be the one-line base64 SPKI DER of an ECDSA P-384 public key."
  }

  validation {
    condition     = length(distinct([for row in var.admin_signing_keys : lookup(row, "keyid", "")])) == length(var.admin_signing_keys)
    error_message = "admin_signing_keys must not repeat a keyid."
  }
}

# The inputs below are used by the scripts and CI only (docs/design/deployment.md "デプロイごとの入力").

variable "d1_database_name" {
  description = "Name of the D1 database. Scripts create it and look its ID up by name; Terraform never manages D1."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,62}$", var.d1_database_name))
    error_message = "d1_database_name must be lowercase letters, digits, and hyphens."
  }
}

variable "rate_limit_namespace_id" {
  description = "Namespace ID of the IdP Worker's Rate Limiting binding. Unique within the account, so it must not be one the service's Workers use. Terraform does not use it; the deploy passes it to the IdP Worker."
  type        = string
  nullable    = false

  # Cloudflare takes a positive integer as a string (Workers "Rate Limiting", Configuration).
  validation {
    condition     = can(regex("^[1-9][0-9]{0,17}$", var.rate_limit_namespace_id))
    error_message = "rate_limit_namespace_id must be a positive integer written as a string, without leading zeros."
  }
}

variable "admin_rate_limit_namespace_id" {
  description = "Namespace ID of the admin Worker's Rate Limiting binding. The same rule as rate_limit_namespace_id, and a different value, so admin requests and sign-ins never share a count (docs/design/hosting-modes.md 6.2). Terraform does not use it."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[1-9][0-9]{0,17}$", var.admin_rate_limit_namespace_id))
    error_message = "admin_rate_limit_namespace_id must be a positive integer written as a string, without leading zeros."
  }

  validation {
    condition     = var.admin_rate_limit_namespace_id != var.rate_limit_namespace_id
    error_message = "admin_rate_limit_namespace_id must differ from rate_limit_namespace_id (docs/design/hosting-modes.md 6.2)."
  }
}

variable "rs256_enabled" {
  description = "Whether RS256 ID tokens are enabled, the one source of truth for both Workers (docs/design/tokens.md). true requires the RSA key Secret on the IdP Worker, which otherwise refuses every request; false leaves any RSA Secret unread. Terraform does not use it; the deploy passes it to both Workers and checks discovery against it."
  type        = bool
  nullable    = false
}

variable "state_bucket_name" {
  description = "Name of the R2 bucket for Terraform state. scripts/bootstrap-state-bucket.sh creates it before the first init."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.state_bucket_name))
    error_message = "state_bucket_name must be a valid R2 bucket name."
  }
}

variable "onepassword_vault" {
  description = "1Password Vault that holds the human-used items of this deployment."
  type        = string
  nullable    = false

  validation {
    condition     = length(var.onepassword_vault) > 0
    error_message = "onepassword_vault must not be empty."
  }
}

variable "onepassword_cloudflare_item" {
  description = "Vault item with the account ID, the Terraform API token, and the R2 credentials for the state bucket."
  type        = string
  nullable    = false

  validation {
    condition     = length(var.onepassword_cloudflare_item) > 0
    error_message = "onepassword_cloudflare_item must not be empty."
  }
}

variable "onepassword_signing_key_item" {
  description = "Vault item that holds the Ed25519 signing key (the source and backup of the Worker Secret)."
  type        = string
  nullable    = false

  validation {
    condition     = length(var.onepassword_signing_key_item) > 0
    error_message = "onepassword_signing_key_item must not be empty."
  }
}

variable "onepassword_admin_key_item_prefix" {
  description = "Prefix of the Vault items that hold the admin private keys; the admin name follows it."
  type        = string
  nullable    = false

  validation {
    condition     = length(var.onepassword_admin_key_item_prefix) > 0
    error_message = "onepassword_admin_key_item_prefix must not be empty."
  }
}

variable "onepassword_deploy_environment" {
  description = "1Password Environment for the deploy workflow."
  type        = string
  nullable    = false

  validation {
    condition     = length(var.onepassword_deploy_environment) > 0
    error_message = "onepassword_deploy_environment must not be empty."
  }
}

variable "onepassword_plan_environment" {
  description = "Read-only 1Password Environment for the PR terraform plan (the exception in docs/design/deployment.md)."
  type        = string
  nullable    = false

  validation {
    condition     = length(var.onepassword_plan_environment) > 0 && var.onepassword_plan_environment != var.onepassword_deploy_environment
    error_message = "onepassword_plan_environment must not be empty and must differ from onepassword_deploy_environment."
  }
}

variable "github_deploy_environment" {
  description = "GitHub Environment of the deploy job."
  type        = string
  nullable    = false

  validation {
    condition     = length(var.github_deploy_environment) > 0
    error_message = "github_deploy_environment must not be empty."
  }
}

variable "github_plan_environment" {
  description = "GitHub Environment of the PR plan job. It must not be the deploy one."
  type        = string
  nullable    = false

  validation {
    condition     = length(var.github_plan_environment) > 0 && var.github_plan_environment != var.github_deploy_environment
    error_message = "github_plan_environment must not be empty and must differ from github_deploy_environment."
  }
}

# Removed inputs. They are declared only to refuse them: an undeclared key in -var-file would only warn, and a
# deployment file that still carries the mTLS inputs would then pass review as if the admin host were still behind
# mTLS (docs/design/hosting-modes.md 1.1 and 1.4, fail-closed against stale configs). These are the only variables
# with a default, and the default is null so that their absence passes. Terraform cannot tell an explicit null from
# a missing key, so `"admin_allowlist": null` passes here; scripts/lib.sh (reject_removed_inputs) is the authority on
# whether a key is present, null included, and every script stops on it before Terraform runs.

variable "admin_allowlist" {
  description = "Removed with mTLS (docs/design/hosting-modes.md plan step 7). Must not be in the deployment file; admin_signing_keys replaces it."
  type        = any
  default     = null

  validation {
    condition     = var.admin_allowlist == null
    error_message = "admin_allowlist was removed with mTLS; delete it from the deployment file (admin_signing_keys replaces it, docs/design/hosting-modes.md 3.7)."
  }
}

variable "zone_singletons_owner" {
  description = "Removed with ③ (docs/design/domain-placement.md): the IdP owns no zone singleton. Must not be in the deployment file."
  type        = any
  default     = null

  validation {
    condition     = var.zone_singletons_owner == null
    error_message = "zone_singletons_owner was removed; delete it from the deployment file (docs/design/hosting-modes.md 1.1)."
  }
}

variable "admin_client_certificates" {
  description = "Removed with mTLS (docs/design/hosting-modes.md plan step 7). Must not be in the deployment file; no client certificate is issued any more."
  type        = any
  default     = null

  validation {
    condition     = var.admin_client_certificates == null
    error_message = "admin_client_certificates was removed with mTLS; delete it from the deployment file (docs/design/hosting-modes.md 3.10)."
  }
}
