#!/usr/bin/env bash
# Builds and deploys the IdP Worker and the admin Worker of one deployment, then checks them from outside (bootstrap
# stage 5 and every later deploy; docs/design/deployment.md, デプロイのパイプライン). The deploy workflow
# (.github/workflows/deploy.yml) runs it with --ci after scripts/terraform.sh --ci apply; the operator can run it
# locally, from a clean checkout of the reviewed main only.
#
# This script handles no secret value itself: in CI the deploy token reaches cf and curl only through the
# environment (CLOUDFLARE_API_TOKEN, never expanded here), and locally cf uses the operator's `cf auth login` session
# and the workers.dev check gets its token through op run. So it runs with xtrace like the other non-secret scripts.
# Do not expand CLOUDFLARE_API_TOKEN anywhere in this file.
set -euxo pipefail

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# workers.dev's bot protection refuses library default User-Agents before the Worker sees them
# (docs/design/hosting-modes.md 5.2), so every probe names itself, in both modes.
readonly PROBE_USER_AGENT="idp-deploy-check"
# The plain-http probe's path and query: the redirect must keep both (docs/design/deployment.md, 直書きの禁止).
readonly PROBE_HTTP_PATH="/.well-known/openid-configuration?deploy-check=1"

usage() {
  printf '%s\n' \
    "Usage: scripts/deploy.sh [--ci] [--before-signing-key] <deployment>" \
    "" \
    "Reads deployments/<deployment>.tfvars.json, checks every input (and, in the workers_dev mode, the account's" \
    "workers.dev subdomain), looks up the D1 database by name, builds both Workers with cf build, applies" \
    "contract/migrations, deploys the IdP Worker and then the admin Worker with cf deploy --prebuilt, and checks" \
    "them from outside:" \
    "  - discovery and JWKS over https on the issuer host" \
    "  - plain http on the issuer host: the IdP Worker's 308 to https without credentials, and its 404 with an" \
    "    Authorization header or a __Host- cookie (in the workers_dev mode, workers.dev's own redirect is accepted)" \
    "  - the admin Worker's forbidden, with no reason, for an unsigned request" \
    "  - workers.dev enabled only in the workers_dev mode, and preview URLs disabled, on both Workers" \
    "" \
    "      --ci                  Take the account from CLOUDFLARE_ACCOUNT_ID and the deploy token from" \
    "                            CLOUDFLARE_API_TOKEN, both loaded from the deployment's 1Password Environment." \
    "                            Without it, the checkout must be clean and equal to the freshly fetched" \
    "                            origin/main, the account is read from the 1Password item, and cf uses the" \
    "                            operator's cf auth login session." \
    "      --before-signing-key  The first deploy (bootstrap stage 5): expect the IdP Worker to refuse every" \
    "                            request with 500 until the signing key is registered (stage 5b), and skip the" \
    "                            plain-http checks, which the deploy after stage 5b runs." \
    "  -h, --help                Show this help."
}

# Prints "<status> <detail>" of one request without following redirects, writing the body to a file. The detail is
# the curl write-out variable named by the third argument (content_type or redirect_url); the arguments after the
# fourth go to curl before the URL (headers). Only the URL's own scheme is allowed, so an http probe is never upgraded
# and an https probe never downgraded. Retries while the host does not answer yet (000) or the edge reports an origin
# error (52x): a new custom domain needs its DNS record and certificate before it answers. With the fourth argument
# "new_route" (and the content_type detail), it also retries workers.dev's plain-text 404 for a Worker whose route is
# not live yet (is_route_not_live_yet, scripts/lib.sh); "live_route" judges every 404 at once. Whatever the last
# attempt answered is printed, so a route that never goes live fails its check as any other wrong answer.
http_probe() {
  local url="${1}"
  local body="${2}"
  local detail="${3}"
  local route="${4}"
  shift 4
  case "${route}" in
    new_route) [[ "${detail}" == "content_type" ]] || fail "http_probe: new_route needs the content_type detail" ;;
    live_route) ;;
    *) fail "http_probe: unknown route state ${route}" ;;
  esac
  local scheme="${url%%://*}"
  local attempt
  local result=""
  for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
    result="$(curl --silent --proto "=${scheme}" --tlsv1.2 --max-time 20 --user-agent "${PROBE_USER_AGENT}" \
      --output "${body}" --write-out "%{http_code} %{${detail}}" "$@" "${url}" || true)"
    case "${result}" in
      000* | 52[0-9]*) note "attempt ${attempt}: ${url} answered ${result%% *}; retrying" ;;
      *)
        if [[ "${route}" == "new_route" ]] && is_route_not_live_yet "${result%% *}" "${result#* }"; then
          note "attempt ${attempt}: ${url} answered ${result}, as workers.dev does before a new Worker's route is live; retrying"
        else
          break
        fi
        ;;
    esac
    # No wait after the last attempt: its answer is judged at once.
    [[ "${attempt}" == "12" ]] || sleep 10
  done
  printf '%s\n' "${result}"
}

check_issuer() {
  local issuer="${1}"
  local before_signing_key="${2}"
  local workdir="${3}"
  local result
  # The first probe of the IdP Worker after cf deploy, so its workers.dev route may not be live yet; the later ones
  # (JWKS, plain http) run once discovery has answered.
  result="$(http_probe "${issuer}/.well-known/openid-configuration" "${workdir}/discovery.json" content_type new_route)"
  if [[ "${before_signing_key}" == "true" ]]; then
    # The Worker answers on its host over https and fails closed without a key (bootstrap stage 5).
    [[ "${result%% *}" == "500" ]] || fail "expected the IdP Worker to refuse with 500 before the signing key, got ${result}"
    grep -q "The identity provider is misconfigured." "${workdir}/discovery.json" ||
      fail "the 500 from ${issuer} is not the IdP Worker's configuration refusal"
    note "the IdP Worker answers on ${issuer} and refuses every request until the signing key is registered"
    return 0
  fi
  [[ "${result%% *}" == "200" ]] || fail "discovery at ${issuer} answered ${result}"
  jq -e --arg issuer "${issuer}" '.issuer == $issuer and .jwks_uri == ($issuer + "/jwks")' "${workdir}/discovery.json" >/dev/null ||
    fail "the discovery document does not name ${issuer} and its /jwks"
  result="$(http_probe "${issuer}/jwks" "${workdir}/jwks.json" content_type live_route)"
  [[ "${result%% *}" == "200" ]] || fail "JWKS at ${issuer}/jwks answered ${result}"
  jq -e '.keys | type == "array" and length > 0' "${workdir}/jwks.json" >/dev/null || fail "the JWKS has no key"
  note "discovery and JWKS answer on ${issuer}; kids: $(jq -c '[.keys[].kid]' "${workdir}/jwks.json")"
}

# One plain-http probe on the issuer host, judged by plain_http_verdict (scripts/lib.sh). The arguments after the
# fourth go to curl (the credential under test).
probe_plain_http() {
  local mode="${1}"
  local expectation="${2}"
  local issuer_host="${3}"
  local workdir="${4}"
  shift 4
  local expected="https://${issuer_host}${PROBE_HTTP_PATH}"
  local result
  local answered_by
  # live_route: the IdP Worker's own refusal is a plain-text 404, which must be judged, not retried.
  result="$(http_probe "http://${issuer_host}${PROBE_HTTP_PATH}" "${workdir}/http.body" redirect_url live_route "$@")"
  answered_by="$(plain_http_verdict "${mode}" "${expectation}" "${result%% *}" "${result#* }" "${expected}")" ||
    fail "plain http on ${issuer_host} (${expectation}) answered ${result}; the IdP Worker must answer 308 to ${expected} without credentials and 404 with them (a 301 in the custom_domain mode means a zone rule such as Always Use HTTPS answers first)"
  note "plain http on ${issuer_host} (${expectation}): ${result%% *}, answered by the ${answered_by}"
}

check_plain_http() {
  local mode="${1}"
  local issuer_host="${2}"
  local workdir="${3}"
  probe_plain_http "${mode}" redirect "${issuer_host}" "${workdir}"
  # Fake credentials, never real ones: the probe checks only that the Worker refuses to redirect them.
  probe_plain_http "${mode}" refuse "${issuer_host}" "${workdir}" --header "Authorization: Bearer deploy-check"
  probe_plain_http "${mode}" refuse "${issuer_host}" "${workdir}" --cookie "__Host-deploy-check=1"
}

check_admin_gate() {
  local admin_host="${1}"
  local workdir="${2}"
  local result
  # The only probe of the admin Worker, deployed seconds earlier: its workers.dev route may not be live yet.
  result="$(http_probe "https://${admin_host}/" "${workdir}/admin.body" content_type new_route)"
  is_admin_forbidden "${result%% *}" "${result#* }" "${workdir}/admin.body" ||
    fail "an unsigned request to ${admin_host} answered ${result}, not the admin Worker's forbidden with no reason"
  note "the admin Worker refuses an unsigned request on ${admin_host} with forbidden"
}

# The account's workers.dev subdomain is checked separately (workers_dev mode), so the setting is checked here
# rather than the URL: on in the workers_dev mode, off in the custom_domain mode, and preview URLs off in both
# (docs/design/hosting-modes.md 1.2).
check_workers_dev_setting() {
  local mode="${1}"
  local worker="${2}"
  local enabled="false"
  [[ "${mode}" == "workers_dev" ]] && enabled="true"
  cf_cli workers get "${worker}" |
    jq -e --argjson enabled "${enabled}" "${CF_JQ_RESULT}"' cf_object | .subdomain.enabled == $enabled and .subdomain.previews_enabled == false' >/dev/null ||
    fail "${worker} must have workers.dev $([[ "${enabled}" == "true" ]] && printf on || printf off) and preview URLs off"
  note "${worker}: workers.dev ${enabled}, preview URLs off"
}

main() {
  local ci="false"
  local before_signing_key="false"
  while [[ "$#" -gt 0 ]]; do
    case "${1}" in
      -h | --help)
        usage
        return 0
        ;;
      --ci) ci="true" ;;
      --before-signing-key) before_signing_key="true" ;;
      -*)
        usage >&2
        return 2
        ;;
      *) break ;;
    esac
    shift
  done
  [[ "$#" -eq 1 ]] || {
    usage >&2
    return 2
  }
  local deployment="${1}"

  require_command curl git jq pnpm
  # Every input is read and checked before anything changes, so a bad deployment file stops with nothing deployed.
  local config
  local mode
  local issuer_host
  local admin_host
  local d1_name
  local namespace
  local admin_namespace
  local signing_keys
  config="$(deployment_config_path "${deployment}")"
  mode="$(hosting_mode "${config}")"
  # The only way to the hosts: workers_dev derives them from workers_dev_subdomain (hosting-modes.md 1.3).
  issuer_host="$(deployment_issuer_host "${config}")"
  admin_host="$(deployment_admin_host "${config}")"
  d1_name="$(config_string "${config}" d1_database_name)"
  namespace="$(config_string "${config}" rate_limit_namespace_id)"
  admin_namespace="$(config_string "${config}" admin_rate_limit_namespace_id)"
  # The full row check (keyid = SHA-256 of a P-384 key); the admin config checks only the shape.
  check_admin_signing_keys "${config}"
  signing_keys="$(jq -c '.admin_signing_keys' "${config}")"

  if [[ "${ci}" == "true" ]]; then
    # The value is checked by name only: printenv's output is discarded, so xtrace never shows the token.
    printenv CLOUDFLARE_API_TOKEN >/dev/null || fail "CLOUDFLARE_API_TOKEN is not set; load the deployment's 1Password Environment"
    # A run whose commit is no longer the head of main (a late run or a re-run) stops before any change, so it never
    # deploys over a newer merge and its migrations. The workflow checks the same before Terraform.
    require_main_head "${IDP_REPO_ROOT}" "${GITHUB_SHA:-}"
    IDP_ACCOUNT_ID="${CLOUDFLARE_ACCOUNT_ID:-}"
    [[ "${IDP_ACCOUNT_ID}" =~ ^[0-9a-f]{32}$ ]] || fail "CLOUDFLARE_ACCOUNT_ID is not a Cloudflare account ID"
    # No verify_cf_account: the token is scoped to the Environment's one account, so no session can span accounts,
    # and the deploy token need not read account details.
    if [[ "${mode}" == "workers_dev" ]]; then
      verify_workers_dev_subdomain_from_env "${config}" "${IDP_ACCOUNT_ID}"
    fi
  else
    # In CI the workflow runs only on main and checks out that commit; locally nothing else guarantees it.
    require_reviewed_checkout "${IDP_REPO_ROOT}"
    require_command op
    local vault
    local cloudflare_item
    vault="$(config_string "${config}" onepassword_vault)"
    cloudflare_item="$(config_string "${config}" onepassword_cloudflare_item)"
    require_op_session
    IDP_ACCOUNT_ID="$(read_account_id "${vault}" "${cloudflare_item}")"
    verify_cf_account
    if [[ "${mode}" == "workers_dev" ]]; then
      verify_workers_dev_subdomain "${config}" "${vault}" "${cloudflare_item}" "${IDP_ACCOUNT_ID}"
    fi
  fi

  local d1_id
  d1_id="$(d1_database_id "${d1_name}")"
  # Read by both cloudflare.config.ts files when cf build evaluates them; each checks its own again.
  export IDP_HOSTING_MODE="${mode}"
  export IDP_ISSUER="https://${issuer_host}"
  export IDP_ADMIN_HOST="${admin_host}"
  export IDP_D1_DATABASE_ID="${d1_id}"
  export IDP_RATE_LIMIT_NAMESPACE_ID="${namespace}"
  export IDP_ADMIN_RATE_LIMIT_NAMESPACE_ID="${admin_namespace}"
  export IDP_ADMIN_SIGNING_KEYS="${signing_keys}"

  # Ignored, so the clean-checkout check cannot see it: an earlier build's output must not be what gets deployed.
  rm -rf "${IDP_REPO_ROOT}/apps/worker/.cloudflare" "${IDP_REPO_ROOT}/apps/admin-worker/.cloudflare"
  # Build both before changing anything, so a bad input or a build failure stops the run with nothing deployed.
  cf_cli_in apps/worker build
  cf_cli_in apps/admin-worker build

  # Expand/contract, so the Workers still running work with the new schema. 0004 needs the signature-only admin
  # Worker, which this same run deploys right after (docs/design/deployment.md, デプロイのパイプライン).
  cf_cli d1 migrations apply "${d1_id}" --dir "${IDP_REPO_ROOT}/contract/migrations"

  local message
  message="deploy $(git -C "${IDP_REPO_ROOT}" rev-parse HEAD)"
  # The IdP Worker first: the admin Worker's IDP Service Binding targets its IdpInternal entrypoint, which must exist
  # in the deployed version before a binding to it is created.
  cf_cli_in apps/worker deploy --prebuilt --message "${message}"
  cf_cli_in apps/admin-worker deploy --prebuilt --message "${message}"

  local workdir
  workdir="$(mktemp -d)"
  # shellcheck disable=SC2064 # Expand now: workdir is local and gone when the trap runs.
  trap "rm -rf '${workdir}'" EXIT
  check_issuer "${IDP_ISSUER}" "${before_signing_key}" "${workdir}"
  if [[ "${before_signing_key}" == "true" ]]; then
    note "plain-http checks skipped: the IdP Worker answers 500 to everything until the signing key is registered"
  else
    check_plain_http "${mode}" "${issuer_host}" "${workdir}"
  fi
  check_admin_gate "${admin_host}" "${workdir}"
  check_workers_dev_setting "${mode}" "${IDP_WORKER_NAME}"
  check_workers_dev_setting "${mode}" "${ADMIN_WORKER_NAME}"
  note "deployed ${IDP_WORKER_NAME} and ${ADMIN_WORKER_NAME} for ${deployment} (${mode})"
}

main "$@"
