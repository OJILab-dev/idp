#!/usr/bin/env bash
# Builds and deploys the IdP Worker and the admin Worker, then checks them from outside (bootstrap stage 5 and every
# later deploy). The deploy workflow (.github/workflows/deploy.yml) runs this script with --ci; the operator can run
# it locally for the first deploy, before the CI credentials exist.
#
# This script handles no secret value itself: in CI the deploy token reaches cf only through the environment
# (CLOUDFLARE_API_TOKEN, never expanded here), and locally cf uses the operator's `cf auth login` session. So it runs
# with xtrace like the other non-secret scripts. Do not expand CLOUDFLARE_API_TOKEN anywhere in this file.
set -euxo pipefail

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  printf '%s\n' \
    "Usage: scripts/deploy.sh [--ci] [--before-signing-key] <deployment>" \
    "" \
    "Reads deployments/<deployment>.tfvars.json, looks up the D1 database by name, builds both Workers with cf build," \
    "applies contract/migrations, deploys the IdP Worker and then the admin Worker with cf deploy --prebuilt, and" \
    "runs the post-deploy checks: discovery and JWKS over https on the issuer host, plain http on the issuer host" \
    "redirected to https at the edge, the admin host refusing a request without a client certificate at the edge," \
    "and workers.dev and preview URLs disabled on both Workers." \
    "" \
    "The two edge checks test the zone singletons (the redirect, mTLS, and WAF rules). When zone_singletons_owner is" \
    "external, the zone's owner applies them; a missing rule fails the run with that hand-off named." \
    "" \
    "      --ci                  Take the account from CLOUDFLARE_ACCOUNT_ID and the token from CLOUDFLARE_API_TOKEN," \
    "                            both loaded from the deployment's 1Password Environment. Without it, the account" \
    "                            is read from the 1Password item and cf uses the operator's cf auth login session." \
    "      --before-signing-key  Expect the IdP Worker to refuse every request (500), because the signing key is" \
    "                            registered only after the first deploy (bootstrap stage 5b)." \
    "  -h, --help                Show this help."
}

# Prints "<status> <detail>" of a GET without following redirects, writing the body to a file. The detail is the
# curl write-out variable named by the third argument (content_type or redirect_url). Only the URL's own scheme is
# allowed, so an http probe cannot be upgraded and an https probe cannot be downgraded. Retries while the host is
# not reachable yet (status 000) or the edge reports an origin error (52x): a new custom domain needs its DNS
# record and certificate before it answers.
http_probe() {
  local url="${1}"
  local body="${2}"
  local detail="${3:-content_type}"
  local scheme="${url%%://*}"
  local attempt
  local result=""
  for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
    result="$(curl --silent --proto "=${scheme}" --tlsv1.2 --max-time 20 --output "${body}" \
      --write-out "%{http_code} %{${detail}}" "${url}" || true)"
    case "${result}" in
      000* | 52[0-9]*) note "attempt ${attempt}: ${url} answered ${result%% *}; retrying" ;;
      *) break ;;
    esac
    sleep 10
  done
  printf '%s\n' "${result}"
}

check_issuer() {
  local issuer="${1}"
  local before_signing_key="${2}"
  local workdir="${3}"
  local result
  result="$(http_probe "${issuer}/.well-known/openid-configuration" "${workdir}/discovery.json")"
  if [[ "${before_signing_key}" == "true" ]]; then
    # The Worker answers on its custom domain over https and fails closed without a key (bootstrap stage 5).
    [[ "${result%% *}" == "500" ]] || fail "expected the IdP Worker to refuse with 500 before the signing key, got ${result}"
    grep -q "The identity provider is misconfigured." "${workdir}/discovery.json" ||
      fail "the 500 from ${issuer} is not the IdP Worker's configuration refusal"
    note "IdP Worker answers on ${issuer} and refuses every request until the signing key is registered"
    return 0
  fi
  [[ "${result%% *}" == "200" ]] || fail "discovery at ${issuer} answered ${result}"
  jq -e --arg issuer "${issuer}" '.issuer == $issuer and .jwks_uri == ($issuer + "/jwks")' "${workdir}/discovery.json" >/dev/null ||
    fail "the discovery document does not name ${issuer} and its /jwks"
  result="$(http_probe "${issuer}/jwks" "${workdir}/jwks.json")"
  [[ "${result%% *}" == "200" ]] || fail "JWKS at ${issuer}/jwks answered ${result}"
  jq -e '.keys | type == "array" and length > 0' "${workdir}/jwks.json" >/dev/null || fail "the JWKS has no key"
  note "discovery and JWKS answer on ${issuer}; kids: $(jq -c '[.keys[].kid]' "${workdir}/jwks.json")"
}

# Edge check of the issuer redirect rule (a zone singleton). Returns non-zero instead of failing, so every missing
# zone rule is reported in one run.
check_issuer_redirect() {
  local issuer_host="${1}"
  local workdir="${2}"
  # A query proves the rule keeps it: the wildcard captures the full URI, query included (infra/main.tf).
  local path="/.well-known/openid-configuration?smoke=1"
  local result
  result="$(http_probe "http://${issuer_host}${path}" "${workdir}/redirect.body" redirect_url)"
  if is_https_redirect "${result%% *}" "${result#* }" "https://${issuer_host}${path}"; then
    note "the edge redirects http on ${issuer_host} to https"
    return 0
  fi
  note "MISSING ZONE RULE: http on ${issuer_host} answered ${result}, not a 301 to https; the issuer redirect rule (http_request_dynamic_redirect) is not applied"
  return 1
}

# Edge check of the admin host's mTLS association and WAF rule (zone singletons). Returns non-zero like the above.
check_admin_host() {
  local admin_host="${1}"
  local workdir="${2}"
  local result
  result="$(http_probe "https://${admin_host}/" "${workdir}/admin.body")"
  if is_waf_block "${result%% *}" "${result#* }"; then
    note "the edge blocks ${admin_host} without a client certificate"
    return 0
  fi
  note "MISSING ZONE RULE: ${admin_host} without a client certificate answered ${result}, not the edge's 403; the mTLS hostname association or the WAF rule (http_request_firewall_custom) is not applied"
  return 1
}

# Stops the run after the edge checks found a missing zone rule, naming who applies the rules. The Workers are
# already deployed and refuse such requests themselves (fail-closed); what is lost until the rules exist is the
# stop before the Worker, which protects the account's daily request limit (docs/design/domain-placement.md, 2).
fail_missing_zone_rules() {
  local owner="${1}"
  local deployment="${2}"
  if [[ "${owner}" == "external" ]]; then
    fail "zone_singletons_owner is external and the zone's owner has not applied the IdP's zone rules above; hand them the zone_singletons output of scripts/terraform.sh ${deployment} output (runbook stage 4b'), then run the deploy again"
  fi
  fail "zone_singletons_owner is idp and the IdP's zone rules above are missing; run scripts/terraform.sh ${deployment} plan and apply (runbook stage 4b), then run the deploy again"
}

check_no_workers_dev() {
  local worker="${1}"
  # The account's workers.dev subdomain is not an input, so the setting is checked instead of the URL.
  cf_cli workers get "${worker}" | jq -e '(.result // .) | .subdomain.enabled == false and .subdomain.previews_enabled == false' >/dev/null ||
    fail "workers.dev or preview URLs are enabled on ${worker}"
  note "workers.dev and preview URLs are off for ${worker}"
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
  local config
  local issuer_host
  local admin_host
  local d1_name
  local namespace
  local owner
  local allowlist
  config="$(deployment_config_path "${deployment}")"
  issuer_host="$(config_string "${config}" issuer_host)"
  admin_host="$(config_string "${config}" admin_host)"
  d1_name="$(config_string "${config}" d1_database_name)"
  # The IdP Worker's cloudflare.config.ts checks its form; it has no default (domain-placement.md, 4).
  namespace="$(config_string "${config}" rate_limit_namespace_id)"
  # Read before anything changes, so a deployment without it stops here rather than after the deploy.
  owner="$(config_zone_singletons_owner "${config}")"
  # Passed as compact JSON; the admin Worker's cloudflare.config.ts refuses an empty or malformed list.
  allowlist="$(jq -ce '.admin_allowlist | select(type == "array")' "${config}")" ||
    fail "deployment file lacks the array \"admin_allowlist\": ${config}"

  if [[ "${ci}" == "true" ]]; then
    # The value is checked by name only: printenv's output is discarded, so xtrace never shows the token.
    printenv CLOUDFLARE_API_TOKEN >/dev/null || fail "CLOUDFLARE_API_TOKEN is not set; load the deployment's 1Password Environment"
    IDP_ACCOUNT_ID="${CLOUDFLARE_ACCOUNT_ID:-}"
    [[ "${IDP_ACCOUNT_ID}" =~ ^[0-9a-f]{32}$ ]] || fail "CLOUDFLARE_ACCOUNT_ID is not a Cloudflare account ID"
    # No verify_cf_account: the token is scoped to the one account of the Environment, so there is no session
    # that could span accounts, and the deploy token need not read account details.
  else
    require_command op
    local vault
    local cloudflare_item
    vault="$(config_string "${config}" onepassword_vault)"
    cloudflare_item="$(config_string "${config}" onepassword_cloudflare_item)"
    require_op_session
    IDP_ACCOUNT_ID="$(read_account_id "${vault}" "${cloudflare_item}")"
    verify_cf_account
  fi

  local d1_id
  d1_id="$(d1_database_id "${d1_name}")"
  # Read by both cloudflare.config.ts files when cf build evaluates them.
  export IDP_ISSUER="https://${issuer_host}"
  export IDP_ADMIN_HOST="${admin_host}"
  export IDP_ADMIN_ALLOWLIST="${allowlist}"
  export IDP_D1_DATABASE_ID="${d1_id}"
  export IDP_RATE_LIMIT_NAMESPACE_ID="${namespace}"

  # Build both before changing anything, so a bad input or a build failure stops the run with nothing deployed.
  cf_cli_in apps/worker build
  cf_cli_in apps/admin-worker build

  # Migrations are expand/contract, so the Workers still running work with the new schema (deployment.md).
  cf_cli d1 migrations apply "${d1_id}" --dir "${IDP_REPO_ROOT}/contract/migrations"

  local message
  message="deploy $(git -C "${IDP_REPO_ROOT}" rev-parse HEAD)"
  # The IdP Worker first: the admin Worker's IDP Service Binding targets its IdpInternal entrypoint, which must
  # exist in the deployed version before a binding to it is created.
  cf_cli_in apps/worker deploy --prebuilt --message "${message}"
  cf_cli_in apps/admin-worker deploy --prebuilt --message "${message}"

  local workdir
  workdir="$(mktemp -d)"
  # shellcheck disable=SC2064 # Expand now: workdir is local and gone when the trap runs.
  trap "rm -rf '${workdir}'" EXIT
  check_issuer "${IDP_ISSUER}" "${before_signing_key}" "${workdir}"
  check_no_workers_dev "${IDP_WORKER_NAME}"
  check_no_workers_dev "${ADMIN_WORKER_NAME}"
  # Both edge checks run before failing, so one run lists every missing zone rule.
  local missing=0
  check_issuer_redirect "${issuer_host}" "${workdir}" || missing=$((missing + 1))
  check_admin_host "${admin_host}" "${workdir}" || missing=$((missing + 1))
  [[ "${missing}" -eq 0 ]] || fail_missing_zone_rules "${owner}" "${deployment}"
  note "deployed ${IDP_WORKER_NAME} and ${ADMIN_WORKER_NAME} for ${deployment}; zone rules present (owner: ${owner})"
}

main "$@"
