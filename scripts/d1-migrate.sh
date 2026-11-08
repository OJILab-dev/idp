#!/usr/bin/env bash
# Applies contract/migrations to the deployment's D1 database with cf (bootstrap stage 2).
set -euxo pipefail

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  printf '%s\n' \
    "Usage: scripts/d1-migrate.sh <deployment>" \
    "" \
    "Looks up the D1 database d1_database_name of deployments/<deployment>.tfvars.json by name and applies" \
    "the migrations in contract/migrations with cf d1 migrations apply. Already applied migrations are skipped." \
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
  local name
  config="$(deployment_config_path "${deployment}")"
  vault="$(config_string "${config}" onepassword_vault)"
  cloudflare_item="$(config_string "${config}" onepassword_cloudflare_item)"
  name="$(config_string "${config}" d1_database_name)"
  require_op_session

  IDP_ACCOUNT_ID="$(read_account_id "${vault}" "${cloudflare_item}")"
  verify_cf_account

  local id
  id="$(d1_database_id "${name}")"
  cf_cli d1 migrations apply "${id}" --dir "${IDP_REPO_ROOT}/contract/migrations"
  note "applied contract/migrations to D1 database ${name}"
}

main "$@"
