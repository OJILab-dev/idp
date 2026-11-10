#!/usr/bin/env bash
# Checks, from the operator's machine, that the account's workers.dev subdomain is the deployment's
# workers_dev_subdomain (docs/design/hosting-modes.md 1.1 and 1.4). The workers_dev issuer is derived from it, so the
# operator runs this before each deploy of a workers_dev deployment (docs/deployment/runbook.md). It reads only and
# changes nothing. It is never run by a test or by CI: the tests stub op and curl.
#
# xtrace stays on: no secret value passes through this script. The token is given to `op run` as an op:// reference
# and reaches curl only through its environment (scripts/lib.sh, read_workers_dev_subdomain).
set -euxo pipefail

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  printf '%s\n' \
    "Usage: scripts/check-workers-dev-subdomain.sh <deployment>" \
    "" \
    "Stops unless the account's workers.dev subdomain (Cloudflare API, Get a Workers Subdomain) equals" \
    "workers_dev_subdomain of deployments/<deployment>.tfvars.json. Only for hosting_mode workers_dev." \
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
  [[ "$#" -eq 1 ]] || {
    usage >&2
    return 2
  }
  local deployment="${1}"

  require_command curl jq op
  local config
  local vault
  local cloudflare_item
  config="$(deployment_config_path "${deployment}")"
  vault="$(config_string "${config}" onepassword_vault)"
  cloudflare_item="$(config_string "${config}" onepassword_cloudflare_item)"
  require_op_session

  local account_id
  account_id="$(read_account_id "${vault}" "${cloudflare_item}")"
  verify_workers_dev_subdomain "${config}" "${vault}" "${cloudflare_item}" "${account_id}"
  note "the account's workers.dev subdomain matches workers_dev_subdomain"
}

main "$@"
