#!/usr/bin/env bash
# Runs Terraform in infra/ for one deployment: from the operator's machine (bootstrap stage 4), or with --ci from the
# deploy workflow (stage 5 and every later merge to main). CI reaches Terraform only through this script, so both
# paths check the same inputs and, in the workers_dev mode, the account's workers.dev subdomain first.
#
# xtrace stays on: no secret value passes through this script. Locally the Terraform API token and the R2
# credentials are given to `op run` as op:// references, and op resolves them inside the Terraform process and masks
# them in its output. In CI the workflow step puts them into the environment under the names Terraform reads, and
# this script only checks that they are set, by name. The account ID is not a secret; it only stays out of the
# repository (docs/design/deployment.md).
set -euxo pipefail

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  printf '%s\n' \
    "Usage: scripts/terraform.sh [--ci] <deployment> <init|plan|apply>" \
    "" \
    "  init    terraform init with the state bucket of the deployment (R2 S3-compatible backend)" \
    "  plan    terraform plan with deployments/<deployment>.tfvars.json" \
    "  apply   terraform apply with deployments/<deployment>.tfvars.json; Terraform asks for approval" \
    "" \
    "Credentials come from the 1Password item onepassword_cloudflare_item at run time and are never written down." \
    "" \
    "      --ci   The deploy workflow: the account from CLOUDFLARE_ACCOUNT_ID, the Terraform token from" \
    "             CLOUDFLARE_API_TOKEN, and the R2 credentials from AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY," \
    "             all loaded from the deployment's 1Password Environment. No op session. apply does not ask for" \
    "             approval: the review of the merge to main is the approval (docs/design/deployment.md)." \
    "  -h, --help Show this help."
}

main() {
  local ci="false"
  case "${1-}" in
    -h | --help)
      usage
      return 0
      ;;
    --ci)
      ci="true"
      shift
      ;;
  esac
  [[ "$#" -eq 2 ]] || {
    usage >&2
    return 2
  }
  local deployment="${1}"
  local action="${2}"
  case "${action}" in
    init | plan | apply) ;;
    *)
      usage >&2
      return 2
      ;;
  esac

  local config
  local bucket
  local mode
  config="$(deployment_config_path "${deployment}")"
  bucket="$(config_string "${config}" state_bucket_name)"
  mode="$(hosting_mode "${config}")"

  local account_id
  local terraform_command
  if [[ "${ci}" == "true" ]]; then
    require_command curl jq terraform
    account_id="${CLOUDFLARE_ACCOUNT_ID:-}"
    [[ "${account_id}" =~ ^[0-9a-f]{32}$ ]] || fail "CLOUDFLARE_ACCOUNT_ID is not a Cloudflare account ID"
    local name
    for name in CLOUDFLARE_API_TOKEN AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY; do
      # Checked by name only: printenv's output is discarded, so xtrace never shows the value.
      printenv "${name}" >/dev/null || fail "${name} is not set; the workflow maps it from the deployment's 1Password Environment"
    done
    terraform_command=(terraform "-chdir=${IDP_REPO_ROOT}/infra")
  else
    require_command curl jq op terraform
    local vault
    local cloudflare_item
    vault="$(config_string "${config}" onepassword_vault)"
    cloudflare_item="$(config_string "${config}" onepassword_cloudflare_item)"
    require_op_session
    account_id="$(read_account_id "${vault}" "${cloudflare_item}")"
    local reference="op://${vault}/${cloudflare_item}"
    terraform_command=(
      env
      "CLOUDFLARE_API_TOKEN=${reference}/${OP_FIELD_TERRAFORM_API_TOKEN}"
      "AWS_ACCESS_KEY_ID=${reference}/${OP_FIELD_R2_ACCESS_KEY_ID}"
      "AWS_SECRET_ACCESS_KEY=${reference}/${OP_FIELD_R2_SECRET_ACCESS_KEY}"
      op run --
      terraform "-chdir=${IDP_REPO_ROOT}/infra"
    )
  fi
  # The S3 backend reads the endpoint from this variable, so the account ID never goes into a backend file.
  export AWS_ENDPOINT_URL_S3="https://${account_id}.r2.cloudflarestorage.com"
  export TF_VAR_account_id="${account_id}"

  # In the workers_dev mode the issuer is derived from the account's workers.dev subdomain, so a plan or apply against
  # an account whose subdomain differs stops before Terraform runs (docs/design/hosting-modes.md 1.4).
  if [[ "${mode}" == "workers_dev" && "${action}" != "init" ]]; then
    if [[ "${ci}" == "true" ]]; then
      verify_workers_dev_subdomain_from_env "${config}" "${account_id}"
    else
      verify_workers_dev_subdomain "${config}" "${vault}" "${cloudflare_item}" "${account_id}"
    fi
  fi

  case "${action}" in
    init)
      "${terraform_command[@]}" init -input=false -reconfigure "-backend-config=bucket=${bucket}"
      ;;
    plan)
      "${terraform_command[@]}" plan -input=false "-var-file=${config}"
      ;;
    apply)
      if [[ "${ci}" == "true" ]]; then
        # Merges to main apply with no manual approval (docs/design/deployment.md, デプロイのパイプライン).
        "${terraform_command[@]}" apply -input=false -auto-approve "-var-file=${config}"
      else
        # No -auto-approve: the operator reads the plan and approves it.
        "${terraform_command[@]}" apply "-var-file=${config}"
      fi
      ;;
  esac
}

main "$@"
