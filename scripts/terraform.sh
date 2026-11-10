#!/usr/bin/env bash
# Runs Terraform in infra/ for one deployment from the operator's machine (bootstrap stage 4).
#
# xtrace stays on: no secret value passes through this script. The Terraform API token and the R2 credentials
# are given to `op run` as op:// references, and op resolves them inside the Terraform process and masks them in
# its output. The account ID is not a secret; it only stays out of the repository (docs/design/deployment.md).
set -euxo pipefail

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  printf '%s\n' \
    "Usage: scripts/terraform.sh <deployment> <init|plan|apply>" \
    "" \
    "  init    terraform init with the state bucket of the deployment (R2 S3-compatible backend)" \
    "  plan    terraform plan with deployments/<deployment>.tfvars.json" \
    "  apply   terraform apply with deployments/<deployment>.tfvars.json; Terraform asks for approval" \
    "" \
    "Credentials come from the 1Password item onepassword_cloudflare_item at run time and are never written down." \
    "" \
    "  -h, --help Show this help."
}

main() {
  case "${1-}" in
    -h | --help)
      usage
      return 0
      ;;
  esac
  [[ "$#" -eq 2 ]] || {
    usage >&2
    return 2
  }
  local deployment="${1}"
  local action="${2}"

  require_command curl jq op terraform
  local config
  local vault
  local cloudflare_item
  local bucket
  config="$(deployment_config_path "${deployment}")"
  vault="$(config_string "${config}" onepassword_vault)"
  cloudflare_item="$(config_string "${config}" onepassword_cloudflare_item)"
  bucket="$(config_string "${config}" state_bucket_name)"
  require_op_session

  local account_id
  account_id="$(read_account_id "${vault}" "${cloudflare_item}")"
  # The S3 backend reads the endpoint from this variable, so the account ID never goes into a backend file.
  export AWS_ENDPOINT_URL_S3="https://${account_id}.r2.cloudflarestorage.com"
  export TF_VAR_account_id="${account_id}"

  # In the workers_dev mode the issuer is derived from the account's workers.dev subdomain, so a plan or apply against
  # an account whose subdomain differs stops before Terraform runs (docs/design/hosting-modes.md 1.4).
  local mode
  mode="$(hosting_mode "${config}")"
  if [[ "${mode}" == "workers_dev" && "${action}" != "init" ]]; then
    verify_workers_dev_subdomain "${config}" "${vault}" "${cloudflare_item}" "${account_id}"
  fi

  local reference="op://${vault}/${cloudflare_item}"
  local terraform_command=(
    env
    "CLOUDFLARE_API_TOKEN=${reference}/${OP_FIELD_TERRAFORM_API_TOKEN}"
    "AWS_ACCESS_KEY_ID=${reference}/${OP_FIELD_R2_ACCESS_KEY_ID}"
    "AWS_SECRET_ACCESS_KEY=${reference}/${OP_FIELD_R2_SECRET_ACCESS_KEY}"
    op run --
    terraform "-chdir=${IDP_REPO_ROOT}/infra"
  )

  case "${action}" in
    init)
      "${terraform_command[@]}" init -input=false -reconfigure "-backend-config=bucket=${bucket}"
      ;;
    plan)
      "${terraform_command[@]}" plan -input=false "-var-file=${config}"
      ;;
    apply)
      # No -auto-approve: the operator reads the plan and approves it. CI applies on main later (stage 5).
      "${terraform_command[@]}" apply "-var-file=${config}"
      ;;
    *)
      usage >&2
      return 2
      ;;
  esac
}

main "$@"
