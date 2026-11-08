# The Terraform version is pinned in mise.toml and the provider version in .terraform.lock.hcl
# (docs/design/deployment.md "Terraform とスクリプトの分担").
terraform {
  required_version = "= 1.15.2"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "= 5.28.1"
    }
  }

  # State lives in the R2 bucket of the target account (Cloudflare "Remote R2 backend").
  # A backend block cannot use variables, so the bucket and the endpoint (built from the account ID)
  # come from `terraform init -backend-config` via scripts/terraform.sh. Only values that are the same
  # for every deployment are written here; credentials arrive as environment variables at run time.
  backend "s3" {
    key    = "idp/terraform.tfstate"
    region = "auto"

    # R2 is not AWS: skip the AWS-only checks that would otherwise fail against the R2 endpoint.
    skip_credentials_validation = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
    skip_metadata_api_check     = true
    skip_s3_checksum            = true
    use_path_style              = true

    # A lock object guards against two applies at once (the CI apply on main and a local apply).
    use_lockfile = true
  }
}

# The provider reads CLOUDFLARE_API_TOKEN from the environment, so no credential appears in code or state.
provider "cloudflare" {}
