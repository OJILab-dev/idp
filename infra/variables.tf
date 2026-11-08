# Every value that differs between deployments is a variable here, with no default: a missing input must stop
# Terraform before it changes anything (fail-closed, docs/design/deployment.md "デプロイごとの入力").
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

variable "zone" {
  description = "The zone (domain) that holds the issuer and admin hostnames. The zone ID is looked up from it."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$", var.zone))
    error_message = "zone must be a lowercase domain name."
  }
}

variable "issuer_host" {
  description = "Hostname of the IdP Worker (the issuer is https://<issuer_host>). The Worker's custom domain owns its DNS record."
  type        = string
  nullable    = false

  validation {
    condition     = var.issuer_host == var.zone || endswith(var.issuer_host, ".${var.zone}")
    error_message = "issuer_host must be the zone itself or a name inside it."
  }
}

variable "admin_host" {
  description = "Hostname of the admin Worker. Terraform enables mTLS and the WAF custom rule on it."
  type        = string
  nullable    = false

  validation {
    condition     = endswith(var.admin_host, ".${var.zone}") && var.admin_host != var.issuer_host
    error_message = "admin_host must be a name inside the zone and must differ from issuer_host (docs/design/idpctl.md)."
  }
}

variable "admin_client_certificates" {
  description = "Admin name to the PEM CSR made by scripts/generate-admin-key.sh. Terraform issues each client certificate from the managed CA."
  type        = map(string)
  nullable    = false

  validation {
    condition     = alltrue([for name in keys(var.admin_client_certificates) : can(regex("^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$", name))])
    error_message = "admin_client_certificates keys must follow the admin name rule of ADMIN_ALLOWLIST (docs/design/idpctl.md)."
  }

  validation {
    condition     = alltrue([for csr in values(var.admin_client_certificates) : startswith(csr, "-----BEGIN CERTIFICATE REQUEST-----\n")])
    error_message = "admin_client_certificates values must be PEM certificate signing requests."
  }
}

variable "admin_allowlist" {
  description = "ADMIN_ALLOWLIST of the admin Worker. Terraform does not use it; it is declared so the shared deployment file is checked here too."
  type = list(object({
    sha256 = string
    name   = string
  }))
  nullable = false

  validation {
    condition     = alltrue([for entry in var.admin_allowlist : can(regex("^[0-9a-f]{64}$", entry.sha256)) && can(regex("^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$", entry.name))])
    error_message = "admin_allowlist entries must have a lowercase 64-hex sha256 and an admin name (docs/design/idpctl.md)."
  }

  validation {
    condition     = length(distinct([for entry in var.admin_allowlist : entry.sha256])) == length(var.admin_allowlist)
    error_message = "admin_allowlist must not repeat a fingerprint."
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
  description = "Prefix of the Vault items that hold the admin mTLS private keys; the admin name follows it."
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
