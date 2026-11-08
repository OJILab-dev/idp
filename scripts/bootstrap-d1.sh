#!/usr/bin/env bash
# Creates the D1 database in APAC and checks that it is on the production backend (bootstrap stage 1).
#
# D1 is not in Terraform so that the plan token needs no D1 permission at all (docs/design/deployment.md).
# The database ID is looked up from the name and never written down.
set -euxo pipefail

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  printf '%s\n' \
    "Usage: scripts/bootstrap-d1.sh <deployment>" \
    "" \
    "Creates the D1 database d1_database_name of deployments/<deployment>.tfvars.json with the APAC location hint." \
    "An existing database with that name is never replaced: creation is skipped and only the backend is checked." \
    "Fails unless the database is on the D1 production backend, which Time Travel needs." \
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

  local count
  count="$(d1_database_count "${name}")"
  case "${count}" in
    0)
      cf_cli d1 create --name "${name}" --primary-location-hint apac >/dev/null
      note "created D1 database ${name}"
      ;;
    1)
      note "D1 database ${name} already exists; not creating or replacing it"
      ;;
    *)
      fail "found ${count} D1 databases named ${name}"
      ;;
  esac

  # Time Travel, the only backup, needs the production backend ("Get D1 Database", version;
  # docs/design/open-questions.md).
  local id
  local version
  id="$(d1_database_id "${name}")"
  version="$(cf_cli d1 get "${id}" | jq -er '(.result // .) | .version')"
  [[ "${version}" == "production" ]] || fail "D1 database ${name} is on the ${version} backend, not production"
  note "D1 database ${name} is on the production backend"
}

main "$@"
