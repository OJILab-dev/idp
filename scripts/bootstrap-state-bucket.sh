#!/usr/bin/env bash
# Creates the R2 bucket that holds the Terraform state (bootstrap stage 1). It must exist before the first
# `terraform init`, so cf creates it instead of Terraform (docs/design/deployment.md).
set -euxo pipefail

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  printf '%s\n' \
    "Usage: scripts/bootstrap-state-bucket.sh <deployment>" \
    "" \
    "Creates the R2 bucket state_bucket_name of deployments/<deployment>.tfvars.json in the deployment's account," \
    "with the APAC location hint. An existing bucket is left as it is, so the script can be rerun." \
    "" \
    "  -h, --help Show this help."
}

main() {
  case "${1-}" in
    -h | --help)
      usage
      return 0
      ;;
    "" | -*)
      usage >&2
      return 2
      ;;
  esac
  [[ "$#" -eq 1 ]] || {
    usage >&2
    return 2
  }
  local deployment="${1}"

  require_command jq op pnpm
  local config
  local vault
  local cloudflare_item
  local bucket
  config="$(deployment_config_path "${deployment}")"
  vault="$(config_string "${config}" onepassword_vault)"
  cloudflare_item="$(config_string "${config}" onepassword_cloudflare_item)"
  bucket="$(config_string "${config}" state_bucket_name)"
  require_op_session

  IDP_ACCOUNT_ID="$(read_account_id "${vault}" "${cloudflare_item}")"
  verify_cf_account

  if cf_cli r2 buckets get "${bucket}" >/dev/null 2>&1; then
    note "R2 bucket ${bucket} already exists; leaving it as it is"
  else
    cf_cli r2 buckets create --name "${bucket}" --location-hint apac >/dev/null
    note "created R2 bucket ${bucket}"
  fi
  cf_cli r2 buckets get "${bucket}" >/dev/null || fail "R2 bucket ${bucket} is not readable after creation"
}

main "$@"
