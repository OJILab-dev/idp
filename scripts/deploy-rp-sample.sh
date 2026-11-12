#!/usr/bin/env bash
# Builds and deploys the sample relying party (examples/rp-sample) as the Worker rp-sample, in the same account as
# one workers_dev deployment of the IdP, then checks it from outside. Operator-run only; the deploy workflow never
# runs it, and it changes nothing of the IdP or admin Workers.
#
# This script handles no secret value: cf uses the operator's `cf auth login` session and the workers.dev check gets
# its token through op run (scripts/lib.sh). So it runs with xtrace like the other non-secret scripts. The Worker's
# two secrets are set by scripts/set-rp-sample-secrets.sh after the first deploy.
set -euxo pipefail

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# workers.dev's bot protection refuses library default User-Agents before the Worker sees them.
readonly PROBE_USER_AGENT="idp-deploy-check"

usage() {
  printf '%s\n' \
    "Usage: scripts/deploy-rp-sample.sh <deployment> <client_id>" \
    "" \
    "Deploys the sample relying party examples/rp-sample as the Worker ${RP_SAMPLE_WORKER_NAME} in the account of" \
    "deployments/<deployment>.tfvars.json, which must be in the workers_dev mode. The issuer is the deployment's," \
    "the client_id is the one registered with idpctl client_create, and the Worker serves" \
    "https://${RP_SAMPLE_WORKER_NAME}.<workers_dev_subdomain>.workers.dev only." \
    "" \
    "Runs from a clean checkout of the freshly fetched origin/main only. Reads the account ID from the 1Password" \
    "item onepassword_cloudflare_item, checks the account's workers.dev subdomain, builds with cf build, deploys" \
    "with cf deploy --prebuilt, and checks workers.dev on, preview URLs off, and the Worker's answer on its host." \
    "Until scripts/set-rp-sample-secrets.sh has set both secrets the Worker answers 500 (misconfigured)." \
    "" \
    "  -h, --help Show this help."
}

# Prints "<status> <content type>" of GET <url> and writes the body to a file. Retries while the host does not answer
# yet (000), the edge reports an origin error (52x), or workers.dev answers its plain-text 404 for a new Worker whose
# route is not live yet (is_route_not_live_yet, scripts/lib.sh). The sample never answers `/` with a plain-text 404
# itself (200 HTML, or the configuration 500), so that 404 is always workers.dev's.
probe_status() {
  local url="${1}"
  local body="${2}"
  local attempt
  local result=""
  for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
    result="$(curl --silent --proto '=https' --tlsv1.2 --max-time 20 --user-agent "${PROBE_USER_AGENT}" \
      --output "${body}" --write-out '%{http_code} %{content_type}' "${url}" || true)"
    case "${result}" in
      000* | 52[0-9]*) note "attempt ${attempt}: ${url} answered ${result%% *}; retrying" ;;
      *)
        is_route_not_live_yet "${result%% *}" "${result#* }" || break
        note "attempt ${attempt}: ${url} answered ${result}, as workers.dev does before a new Worker's route is live; retrying"
        ;;
    esac
    # No wait after the last attempt: its answer is judged at once.
    [[ "${attempt}" == "12" ]] || sleep 10
  done
  printf '%s\n' "${result}"
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
  [[ "$#" -eq 2 ]] || {
    usage >&2
    return 2
  }
  local deployment="${1}"
  local client_id="${2}"
  [[ "${client_id}" =~ ${CLIENT_ID_PATTERN} ]] || fail "not a client_id: ${client_id}"

  require_command curl git jq op pnpm
  # Every input is read and checked before anything changes.
  local config
  local issuer_host
  local host
  local vault
  local cloudflare_item
  config="$(deployment_config_path "${deployment}")"
  host="$(rp_sample_host "${config}")"
  issuer_host="$(deployment_issuer_host "${config}")"
  vault="$(config_string "${config}" onepassword_vault)"
  cloudflare_item="$(config_string "${config}" onepassword_cloudflare_item)"

  # The version is labelled with HEAD, so it must be what was reviewed (as for the IdP's local deploy).
  require_reviewed_checkout "${IDP_REPO_ROOT}"
  require_op_session
  IDP_ACCOUNT_ID="$(read_account_id "${vault}" "${cloudflare_item}")"
  verify_cf_account
  # The host is derived from the subdomain; a subdomain changed on the dashboard would serve another host than the
  # redirect URI registered with the IdP.
  verify_workers_dev_subdomain "${config}" "${vault}" "${cloudflare_item}" "${IDP_ACCOUNT_ID}"

  # Read by examples/rp-sample/cloudflare.config.ts when cf build evaluates it; it checks them again.
  export RP_SAMPLE_ISSUER="https://${issuer_host}"
  export RP_SAMPLE_CLIENT_ID="${client_id}"
  export RP_SAMPLE_ORIGIN="https://${host}"

  # Ignored by git, so the clean-checkout check cannot see it: an earlier build must not be what gets deployed.
  rm -rf "${IDP_REPO_ROOT:?}/${RP_SAMPLE_PROJECT}/.cloudflare"
  cf_cli_in "${RP_SAMPLE_PROJECT}" build
  cf_cli_in "${RP_SAMPLE_PROJECT}" deploy --prebuilt --message "deploy $(git -C "${IDP_REPO_ROOT}" rev-parse HEAD)"

  cf_cli workers get "${RP_SAMPLE_WORKER_NAME}" |
    jq -e "${CF_JQ_RESULT}"' cf_object | .subdomain.enabled == true and .subdomain.previews_enabled == false' >/dev/null ||
    fail "${RP_SAMPLE_WORKER_NAME} must have workers.dev on and preview URLs off"

  local workdir
  workdir="$(mktemp -d)"
  # shellcheck disable=SC2064 # Expand now: workdir is local and gone when the trap runs.
  trap "rm -rf '${workdir}'" EXIT
  local result
  result="$(probe_status "https://${host}/" "${workdir}/body")"
  case "${result%% *}" in
    200) note "the sample answers on https://${host}/" ;;
    500)
      grep -q "The relying party is misconfigured." "${workdir}/body" ||
        fail "https://${host}/ answered ${result}, but not the sample's configuration refusal"
      note "the sample answers on https://${host}/ and refuses every request until scripts/set-rp-sample-secrets.sh sets its secrets"
      ;;
    *) fail "https://${host}/ answered ${result}" ;;
  esac
  note "deployed ${RP_SAMPLE_WORKER_NAME} for ${deployment}: redirect URI https://${host}/callback, client_id ${client_id}"
}

main "$@"
