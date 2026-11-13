#!/usr/bin/env bash
# Offline tests for scripts/deploy.sh and scripts/terraform.sh --ci. The stubs of scripts/test/deploy-stubs stand in
# for pnpm (cf), curl, git, and terraform, and scripts/test/stubs/op for op, so nothing here reaches Cloudflare,
# 1Password, R2, or the network. The tokens are fake strings, and the only key material is the published P-384 public
# key of contract/testdata/vectors.json, so xtrace stays on.
#
# The scripts are copied into a temporary tree, because lib.sh finds deployments/ next to its own directory.
set -euxo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TEST_DIR
REPO_ROOT="$(cd "${TEST_DIR}/../.." && pwd)"
readonly REPO_ROOT
readonly ACCOUNT_ID="0123456789abcdef0123456789abcdef"
readonly D1_ID="0f6b6c3e-5d0a-4a7e-9a35-6f1f4f6c2b11"
readonly HEAD_SHA="1111111111111111111111111111111111111111"

P384_SPKI="$(jq -er '.admin_signature.keyid.valid[0].spki' "${REPO_ROOT}/contract/testdata/vectors.json")"
readonly P384_SPKI
P384_KEYID="$(jq -er '.admin_signature.keyid.valid[0].keyid' "${REPO_ROOT}/contract/testdata/vectors.json")"
readonly P384_KEYID

failures=0

pass() {
  printf 'ok   %s\n' "${1}"
}

failure() {
  printf 'FAIL %s\n' "$*" >&2
  failures=$((failures + 1))
}

assert_equal() {
  local name="${1}"
  local expected="${2}"
  local actual="${3}"
  if [[ "${actual}" == "${expected}" ]]; then
    pass "${name}"
  else
    failure "${name}: expected ${expected}, got ${actual}"
  fi
}

# Builds a fresh tree for one mode: scripts/, deployments/test.tfvars.json, bin/ with the stubs, and stub/ with the
# stubs' answers for a healthy deployment. Prints its path.
make_tree() {
  local mode="${1}"
  local tree
  tree="$(mktemp -d)"
  mkdir -p "${tree}/scripts" "${tree}/deployments" "${tree}/bin" "${tree}/stub/op/fields"
  cp "${REPO_ROOT}/scripts/lib.sh" "${REPO_ROOT}/scripts/deploy.sh" "${REPO_ROOT}/scripts/terraform.sh" "${tree}/scripts/"
  cp "${TEST_DIR}/deploy-stubs/pnpm" "${TEST_DIR}/deploy-stubs/curl" "${TEST_DIR}/deploy-stubs/git" \
    "${TEST_DIR}/deploy-stubs/terraform" "${TEST_DIR}/deploy-stubs/sleep" "${TEST_DIR}/stubs/op" "${tree}/bin/"
  local hosting
  local issuer_host
  local admin_host
  if [[ "${mode}" == "custom_domain" ]]; then
    hosting='{hosting_mode: "custom_domain", zone: "example.com", issuer_host: "id.example.com", admin_host: "admin.id.example.com"}'
    issuer_host="id.example.com"
    admin_host="admin.id.example.com"
  else
    hosting='{hosting_mode: "workers_dev", workers_dev_subdomain: "team-1"}'
    issuer_host="idp.team-1.workers.dev"
    admin_host="idp-admin.team-1.workers.dev"
  fi
  jq -n --arg keyid "${P384_KEYID}" --arg spki "${P384_SPKI}" "${hosting}"' + {
    admin_signing_keys: [{keyid: $keyid, name: "alice", public_key: $spki}],
    d1_database_name: "idp-test",
    rate_limit_namespace_id: "1001",
    admin_rate_limit_namespace_id: "1002",
    state_bucket_name: "idp-test-tfstate",
    onepassword_vault: "idp-test",
    onepassword_cloudflare_item: "cloudflare",
    github_deploy_environment: "test"
  }' >"${tree}/deployments/test.tfvars.json"

  local stub="${tree}/stub"
  : >"${stub}/calls"
  : >"${stub}/probes"
  : >"${stub}/sleeps"
  : >"${stub}/git_status"
  : >"${stub}/op/calls"
  printf '%s\n' "${HEAD_SHA}" >"${stub}/git_head"
  printf '%s\n' "${HEAD_SHA}" >"${stub}/git_main"
  printf '%s\n' "${ACCOUNT_ID}" >"${stub}/account_id"
  printf '%s\n' "${ACCOUNT_ID}" >"${stub}/op/fields/account_id"
  # A bare array, the shape the pinned cf prints for `d1 list` (the wrapped API shape is covered in lib.test.sh).
  jq -nc --arg id "${D1_ID}" '[{name: "idp-test", uuid: $id}, {name: "idp-test-2", uuid: "other"}]' >"${stub}/d1_list"
  local enabled="false"
  [[ "${mode}" == "workers_dev" ]] && enabled="true"
  jq -nc --argjson enabled "${enabled}" '{subdomain: {enabled: $enabled, previews_enabled: false}}' >"${stub}/workers_idp.json"
  cp "${stub}/workers_idp.json" "${stub}/workers_idp-admin.json"
  printf '%s' '{"success":true,"errors":[],"result":{"subdomain":"team-1"}}' >"${stub}/subdomain_response"
  printf '%s\n' "${issuer_host}" >"${stub}/issuer_host"
  printf '%s\n' "${admin_host}" >"${stub}/admin_host"
  printf 'ok\n' >"${stub}/idp_state"
  printf 'worker\n' >"${stub}/http_state"
  printf 'forbidden\n' >"${stub}/admin_state"
  printf '%s\n' "${tree}"
}

# Runs scripts/<script> in the tree the way the deploy workflow does: the account ID and the token in the
# environment, as the 1Password Environment loads them. Its stderr goes to err and the exit code to status.
run_ci() {
  local tree="${1}"
  local script="${2}"
  shift 2
  local status=0
  : >"${tree}/stub/expect_token"
  printf 'stub-api-token\n' >"${tree}/stub/api_token"
  PATH="${tree}/bin:${PATH}" STUB_DIR="${tree}/stub" OP_STUB_DIR="${tree}/stub/op" GITHUB_SHA="${HEAD_SHA}" \
    CLOUDFLARE_ACCOUNT_ID="${ACCOUNT_ID}" CLOUDFLARE_API_TOKEN="stub-api-token" \
    "${tree}/scripts/${script}" "$@" >"${tree}/out" 2>"${tree}/err" || status="$?"
  printf '%s\n' "${status}" >"${tree}/status"
}

# Runs scripts/<script> in the tree as the operator does: no token in the environment, op signed in, cf logged in.
run_local() {
  local tree="${1}"
  local script="${2}"
  shift 2
  local status=0
  rm -f "${tree}/stub/expect_token"
  PATH="${tree}/bin:${PATH}" STUB_DIR="${tree}/stub" OP_STUB_DIR="${tree}/stub/op" \
    env -u CLOUDFLARE_API_TOKEN -u CLOUDFLARE_ACCOUNT_ID "${tree}/scripts/${script}" "$@" >"${tree}/out" 2>"${tree}/err" ||
    status="$?"
  printf '%s\n' "${status}" >"${tree}/status"
}

status_of() {
  cat "${1}/status"
}

# The stubs' calls that change or build something, in order, one per line joined with ";".
changes_of() {
  grep -E '^cf [^ ]+ (build|deploy|d1 migrations)|^terraform [^ ]+ (init|plan|apply) |^curl subdomain' "${1}/stub/calls" |
    tr '\n' ';' || true
}

readonly CI_CHANGES="cf worker build;cf admin-worker build;cf deploy-v3 d1 migrations apply ${D1_ID} --dir REPO/contract/migrations;cf worker deploy --prebuilt --message deploy ${HEAD_SHA};cf admin-worker deploy --prebuilt --message deploy ${HEAD_SHA};"

# The expected changes with the tree's root in place of REPO (cf d1 runs in the repository root).
expected_changes() {
  local tree="${1}"
  local prefix="${2-}"
  local root
  root="$(basename "${tree}")"
  printf '%s%s' "${prefix}" "${CI_CHANGES}" | sed -e "s|cf deploy-v3 |cf ${root} |" -e "s|REPO|${tree}|"
}

test_custom_domain_ci_deploy() {
  local tree
  tree="$(make_tree custom_domain)"
  run_ci "${tree}" deploy.sh --ci test
  assert_equal "custom_domain CI: exit code" "0" "$(status_of "${tree}")"
  # Both builds before any change; migrations, then the IdP Worker, then the admin Worker (deployment.md).
  assert_equal "custom_domain CI: builds, migrations, IdP Worker, admin Worker" "$(expected_changes "${tree}")" "$(changes_of "${tree}")"
  assert_equal "custom_domain CI: the IdP Worker's build environment" \
    "IDP_ADMIN_HOST=admin.id.example.com|IDP_ADMIN_RATE_LIMIT_NAMESPACE_ID=1002|IDP_ADMIN_SIGNING_KEYS=[{\"keyid\":\"${P384_KEYID}\",\"name\":\"alice\",\"public_key\":\"${P384_SPKI}\"}]|IDP_D1_DATABASE_ID=${D1_ID}|IDP_HOSTING_MODE=custom_domain|IDP_ISSUER=https://id.example.com|IDP_RATE_LIMIT_NAMESPACE_ID=1001" \
    "$(tr '\n' '|' <"${tree}/stub/build_env_worker" | sed 's/|$//')"
  assert_equal "custom_domain CI: both builds get the same environment" "$(cat "${tree}/stub/build_env_worker")" \
    "$(cat "${tree}/stub/build_env_admin-worker")"
  # The probes: discovery and JWKS, plain http without and with credentials, and the unsigned admin request.
  assert_equal "custom_domain CI: probes" \
    "https://id.example.com/.well-known/openid-configuration credentials=false;https://id.example.com/jwks credentials=false;http://id.example.com/.well-known/openid-configuration?deploy-check=1 credentials=false;http://id.example.com/.well-known/openid-configuration?deploy-check=1 credentials=true;http://id.example.com/.well-known/openid-configuration?deploy-check=1 credentials=true;https://admin.id.example.com/ credentials=false;" \
    "$(sed 's/ user_agent=[^ ]*//' "${tree}/stub/probes" | tr '\n' ';')"
  # workers.dev's bot protection refuses library default User-Agents before the Worker (hosting-modes.md 5.2).
  assert_equal "custom_domain CI: every probe names itself" "0" "$(grep -c 'user_agent= ' "${tree}/stub/probes" || true)"
  assert_equal "custom_domain CI: op is never called" "" "$(cat "${tree}/stub/op/calls")"
  rm -rf "${tree}"
}

test_workers_dev_ci_deploy() {
  local tree
  tree="$(make_tree workers_dev)"
  run_ci "${tree}" deploy.sh --ci test
  assert_equal "workers_dev CI: exit code" "0" "$(status_of "${tree}")"
  # The subdomain the issuer is derived from is checked before anything is built or changed.
  assert_equal "workers_dev CI: subdomain check first" "$(expected_changes "${tree}" "curl subdomain;")" "$(changes_of "${tree}")"
  assert_equal "workers_dev CI: the derived issuer" "IDP_ISSUER=https://idp.team-1.workers.dev" \
    "$(grep '^IDP_ISSUER=' "${tree}/stub/build_env_worker")"
  rm -rf "${tree}"

  tree="$(make_tree workers_dev)"
  printf '%s' '{"success":true,"errors":[],"result":{"subdomain":"other"}}' >"${tree}/stub/subdomain_response"
  run_ci "${tree}" deploy.sh --ci test
  assert_equal "workers_dev CI: another subdomain stops the deploy" "1" "$(status_of "${tree}")"
  assert_equal "workers_dev CI: nothing is built or changed" "curl subdomain;" "$(changes_of "${tree}")"
  rm -rf "${tree}"
}

# workers.dev may redirect plain http itself before the Worker (hosting-modes.md 7.2, unverified); a zone may not.
test_plain_http_checks() {
  local tree
  tree="$(make_tree workers_dev)"
  printf 'edge301\n' >"${tree}/stub/http_state"
  run_ci "${tree}" deploy.sh --ci test
  assert_equal "workers_dev: workers.dev's own redirect is accepted" "0" "$(status_of "${tree}")"
  rm -rf "${tree}"

  tree="$(make_tree custom_domain)"
  printf 'edge301\n' >"${tree}/stub/http_state"
  run_ci "${tree}" deploy.sh --ci test
  assert_equal "custom_domain: a zone redirect instead of the Worker's fails" "1" "$(status_of "${tree}")"
  rm -rf "${tree}"
}

test_admin_gate_check() {
  local tree
  tree="$(make_tree custom_domain)"
  printf 'leaky\n' >"${tree}/stub/admin_state"
  run_ci "${tree}" deploy.sh --ci test
  assert_equal "a forbidden that tells the reason fails" "1" "$(status_of "${tree}")"
  rm -rf "${tree}"
}

test_workers_dev_setting_check() {
  local tree
  tree="$(make_tree custom_domain)"
  jq -nc '{subdomain: {enabled: true, previews_enabled: false}}' >"${tree}/stub/workers_idp-admin.json"
  run_ci "${tree}" deploy.sh --ci test
  assert_equal "custom_domain: workers.dev on the admin Worker fails" "1" "$(status_of "${tree}")"
  rm -rf "${tree}"

  tree="$(make_tree workers_dev)"
  jq -nc '{subdomain: {enabled: true, previews_enabled: true}}' >"${tree}/stub/workers_idp.json"
  run_ci "${tree}" deploy.sh --ci test
  assert_equal "workers_dev: preview URLs on the IdP Worker fail" "1" "$(status_of "${tree}")"
  rm -rf "${tree}"
}

# The number of probes of one URL, and of the waits between all the probes.
probes_of() {
  grep -c "^${2} " "${1}/stub/probes" || true
}

waits_of() {
  grep -c '^sleep 10$' "${1}/stub/sleeps" || true
}

# Right after the first cf deploy, workers.dev answered a new Worker's host with its own plain-text 404 for a short
# while (easyidp, 2026-11-12). The discovery and admin probes keep retrying it within the bounded attempts, and fail
# as before once those run out.
test_new_routes_are_waited_for() {
  local tree
  local discovery="https://idp.team-1.workers.dev/.well-known/openid-configuration"
  local admin="https://idp-admin.team-1.workers.dev/"

  tree="$(make_tree workers_dev)"
  printf '3\n' >"${tree}/stub/issuer_pending"
  printf '2\n' >"${tree}/stub/admin_pending"
  run_ci "${tree}" deploy.sh --ci test
  assert_equal "new routes: the deploy passes once both answer" "0" "$(status_of "${tree}")"
  assert_equal "new routes: discovery is probed until it answers" "4" "$(probes_of "${tree}" "${discovery}")"
  assert_equal "new routes: the admin gate is probed until it answers" "3" "$(probes_of "${tree}" "${admin}")"
  assert_equal "new routes: one wait per retry" "5" "$(waits_of "${tree}")"
  rm -rf "${tree}"

  # The first deploy, before the signing key: the configuration 500 is still recognised after the wait.
  tree="$(make_tree workers_dev)"
  printf '2\n' >"${tree}/stub/issuer_pending"
  printf 'before_key\n' >"${tree}/stub/idp_state"
  run_ci "${tree}" deploy.sh --ci --before-signing-key test
  assert_equal "new routes before the key: the deploy passes" "0" "$(status_of "${tree}")"
  assert_equal "new routes before the key: discovery is probed until it answers" "3" "$(probes_of "${tree}" "${discovery}")"
  rm -rf "${tree}"

  tree="$(make_tree workers_dev)"
  printf 'forever\n' >"${tree}/stub/issuer_pending"
  run_ci "${tree}" deploy.sh --ci test
  assert_equal "issuer never live: the deploy fails" "1" "$(status_of "${tree}")"
  assert_equal "issuer never live: discovery gets the bounded attempts" "12" "$(probes_of "${tree}" "${discovery}")"
  assert_equal "issuer never live: no wait after the last attempt" "11" "$(waits_of "${tree}")"
  assert_equal "issuer never live: the check stops there" "0" "$(probes_of "${tree}" "${admin}")"
  rm -rf "${tree}"

  tree="$(make_tree workers_dev)"
  printf 'forever\n' >"${tree}/stub/admin_pending"
  run_ci "${tree}" deploy.sh --ci test
  assert_equal "admin never live: the deploy fails" "1" "$(status_of "${tree}")"
  assert_equal "admin never live: the gate gets the bounded attempts" "12" "$(probes_of "${tree}" "${admin}")"
  rm -rf "${tree}"
}

# The first deploy runs before the signing key exists, so the IdP Worker refuses every request with 500, plain http
# included; the http checks wait for the deploy after stage 5b.
test_before_signing_key() {
  local tree
  tree="$(make_tree custom_domain)"
  printf 'before_key\n' >"${tree}/stub/idp_state"
  run_ci "${tree}" deploy.sh --ci --before-signing-key test
  assert_equal "before the key: the configuration 500 is expected" "0" "$(status_of "${tree}")"
  assert_equal "before the key: no plain http probe" "0" "$(grep -c '^http://' "${tree}/stub/probes" || true)"
  run_ci "${tree}" deploy.sh --ci test
  assert_equal "after the key is due: the 500 fails" "1" "$(status_of "${tree}")"
  rm -rf "${tree}"
}

# Everything that can be checked before a change is checked before the builds.
test_stops_before_any_change() {
  local tree
  tree="$(make_tree custom_domain)"
  jq '.admin_signing_keys = []' "${tree}/deployments/test.tfvars.json" >"${tree}/config"
  mv "${tree}/config" "${tree}/deployments/test.tfvars.json"
  run_ci "${tree}" deploy.sh --ci test
  assert_equal "an empty admin_signing_keys stops" "1" "$(status_of "${tree}")"
  assert_equal "an empty admin_signing_keys changes nothing" "" "$(changes_of "${tree}")"
  rm -rf "${tree}"

  tree="$(make_tree custom_domain)"
  jq 'del(.admin_rate_limit_namespace_id)' "${tree}/deployments/test.tfvars.json" >"${tree}/config"
  mv "${tree}/config" "${tree}/deployments/test.tfvars.json"
  run_ci "${tree}" deploy.sh --ci test
  assert_equal "a missing admin namespace stops" "1" "$(status_of "${tree}")"
  assert_equal "a missing admin namespace changes nothing" "" "$(changes_of "${tree}")"
  rm -rf "${tree}"

  tree="$(make_tree custom_domain)"
  : >"${tree}/stub/expect_token"
  PATH="${tree}/bin:${PATH}" STUB_DIR="${tree}/stub" OP_STUB_DIR="${tree}/stub/op" CLOUDFLARE_ACCOUNT_ID="${ACCOUNT_ID}" \
    env -u CLOUDFLARE_API_TOKEN "${tree}/scripts/deploy.sh" --ci test >/dev/null 2>&1 && failure "CI without a token must stop"
  assert_equal "CI without a token changes nothing" "" "$(changes_of "${tree}")"
  PATH="${tree}/bin:${PATH}" STUB_DIR="${tree}/stub" OP_STUB_DIR="${tree}/stub/op" CLOUDFLARE_ACCOUNT_ID="not-an-id" \
    CLOUDFLARE_API_TOKEN="stub-api-token" "${tree}/scripts/deploy.sh" --ci test >/dev/null 2>&1 &&
    failure "CI with a malformed account ID must stop"
  assert_equal "CI with a malformed account ID changes nothing" "" "$(changes_of "${tree}")"
  rm -rf "${tree}"

  tree="$(make_tree custom_domain)"
  printf '[]' >"${tree}/stub/d1_list"
  run_ci "${tree}" deploy.sh --ci test
  assert_equal "a missing D1 database stops before any change" "" "$(changes_of "${tree}")"
  rm -rf "${tree}"

  tree="$(make_tree custom_domain)"
  : >"${tree}/stub/fail_build"
  run_ci "${tree}" deploy.sh --ci test
  assert_equal "a failed build stops before the migrations" "cf worker build;" "$(changes_of "${tree}")"
  rm -rf "${tree}"
}

# A late or re-run CI job for a commit that is no longer the head of main stops before any change, so it never
# rolls back a newer deploy.
test_ci_refuses_an_older_commit() {
  local tree
  tree="$(make_tree custom_domain)"
  printf '2222222222222222222222222222222222222222\n' >"${tree}/stub/git_main"
  run_ci "${tree}" deploy.sh --ci test
  assert_equal "CI: a commit behind main stops" "1" "$(status_of "${tree}")"
  assert_equal "CI: a commit behind main changes nothing" "" "$(changes_of "${tree}")"
  rm -rf "${tree}"

  tree="$(make_tree custom_domain)"
  : >"${tree}/stub/expect_token"
  PATH="${tree}/bin:${PATH}" STUB_DIR="${tree}/stub" CLOUDFLARE_ACCOUNT_ID="${ACCOUNT_ID}" CLOUDFLARE_API_TOKEN="stub-api-token" \
    env -u GITHUB_SHA "${tree}/scripts/deploy.sh" --ci test >/dev/null 2>&1 && failure "CI without GITHUB_SHA must stop"
  assert_equal "CI without GITHUB_SHA changes nothing" "" "$(changes_of "${tree}")"
  rm -rf "${tree}"
}

# Ignored build output survives the clean-checkout check, so the deploy removes it before building: what is deployed
# is always what this run built.
test_removes_earlier_build_output() {
  local tree
  tree="$(make_tree custom_domain)"
  mkdir -p "${tree}/apps/worker/.cloudflare/output" "${tree}/apps/admin-worker/.cloudflare/output"
  printf 'stale\n' >"${tree}/apps/worker/.cloudflare/output/stale"
  run_ci "${tree}" deploy.sh --ci test
  assert_equal "earlier build output: the deploy succeeds" "0" "$(status_of "${tree}")"
  assert_equal "earlier build output: both builds ran on a clean project" "$(expected_changes "${tree}")" "$(changes_of "${tree}")"
  rm -rf "${tree}"
}

test_failed_idp_deploy_stops_the_admin_deploy() {
  local tree
  tree="$(make_tree custom_domain)"
  : >"${tree}/stub/fail_deploy"
  run_ci "${tree}" deploy.sh --ci test
  assert_equal "a failed IdP deploy: exit code" "1" "$(status_of "${tree}")"
  assert_equal "a failed IdP deploy stops before the admin Worker" "0" "$(grep -c '^cf admin-worker deploy' "${tree}/stub/calls" || true)"
  rm -rf "${tree}"
}

# Outside CI, only a clean checkout of the freshly fetched origin/main deploys; the account comes from 1Password and
# cf must act on it.
test_local_deploy() {
  local tree
  tree="$(make_tree workers_dev)"
  printf 'stub-api-token\n' >"${tree}/stub/api_token"
  run_local "${tree}" deploy.sh test
  assert_equal "local: a reviewed checkout deploys" "0" "$(status_of "${tree}")"
  assert_equal "local: the subdomain is read with the Terraform token through op" "op://idp-test/cloudflare/terraform_api_token" \
    "$(cat "${tree}/stub/op/token_reference")"
  assert_equal "local: subdomain check first" "$(expected_changes "${tree}" "curl subdomain;")" "$(changes_of "${tree}")"
  rm -rf "${tree}"

  tree="$(make_tree custom_domain)"
  printf '?? stray\n' >"${tree}/stub/git_status"
  run_local "${tree}" deploy.sh test
  assert_equal "local: a dirty checkout stops" "1" "$(status_of "${tree}")"
  assert_equal "local: a dirty checkout changes nothing" "" "$(changes_of "${tree}")"
  rm -rf "${tree}"

  tree="$(make_tree custom_domain)"
  printf '2222222222222222222222222222222222222222\n' >"${tree}/stub/git_main"
  run_local "${tree}" deploy.sh test
  assert_equal "local: HEAD other than origin/main stops" "1" "$(status_of "${tree}")"
  assert_equal "local: HEAD other than origin/main changes nothing" "" "$(changes_of "${tree}")"
  rm -rf "${tree}"

  tree="$(make_tree custom_domain)"
  printf 'ffffffffffffffffffffffffffffffff\n' >"${tree}/stub/account_id"
  run_local "${tree}" deploy.sh test
  assert_equal "local: cf on another account stops" "1" "$(status_of "${tree}")"
  assert_equal "local: cf on another account changes nothing" "" "$(changes_of "${tree}")"
  rm -rf "${tree}"
}

# Runs terraform.sh --ci as the deploy workflow does: the Terraform token and the R2 credentials in the environment
# under the names Terraform reads, mapped there by the workflow step.
run_terraform_ci() {
  local tree="${1}"
  shift
  local status=0
  printf 'stub-terraform-token\n' >"${tree}/stub/api_token"
  PATH="${tree}/bin:${PATH}" STUB_DIR="${tree}/stub" OP_STUB_DIR="${tree}/stub/op" CLOUDFLARE_ACCOUNT_ID="${ACCOUNT_ID}" \
    CLOUDFLARE_API_TOKEN="stub-terraform-token" AWS_ACCESS_KEY_ID="stub-r2-key-id" AWS_SECRET_ACCESS_KEY="stub-r2-secret" \
    "${tree}/scripts/terraform.sh" --ci "$@" >"${tree}/out" 2>"${tree}/err" || status="$?"
  printf '%s\n' "${status}" >"${tree}/status"
}

test_terraform_ci() {
  local tree
  tree="$(make_tree custom_domain)"
  run_terraform_ci "${tree}" test init
  run_terraform_ci "${tree}" test apply
  assert_equal "terraform CI apply: exit code" "0" "$(status_of "${tree}")"
  # Non-interactive in CI: the main ruleset's review is the approval (deployment.md, デプロイのパイプライン).
  assert_equal "terraform CI: init then apply without a prompt" \
    "terraform -chdir=${tree}/infra init -input=false -reconfigure -backend-config=bucket=idp-test-tfstate;terraform -chdir=${tree}/infra apply -input=false -auto-approve -var-file=${tree}/deployments/test.tfvars.json;" \
    "$(changes_of "${tree}")"
  assert_equal "terraform CI: op is never called" "" "$(cat "${tree}/stub/op/calls")"
  rm -rf "${tree}"

  tree="$(make_tree workers_dev)"
  run_terraform_ci "${tree}" test apply
  assert_equal "terraform CI workers_dev: the subdomain is checked before apply" "curl subdomain;terraform -chdir=${tree}/infra apply -input=false -auto-approve -var-file=${tree}/deployments/test.tfvars.json;" \
    "$(changes_of "${tree}")"
  printf '%s' '{"success":true,"errors":[],"result":{"subdomain":"other"}}' >"${tree}/stub/subdomain_response"
  : >"${tree}/stub/calls"
  run_terraform_ci "${tree}" test apply
  assert_equal "terraform CI workers_dev: another subdomain stops" "1" "$(status_of "${tree}")"
  assert_equal "terraform CI workers_dev: nothing is applied" "curl subdomain;" "$(changes_of "${tree}")"
  rm -rf "${tree}"

  tree="$(make_tree custom_domain)"
  PATH="${tree}/bin:${PATH}" STUB_DIR="${tree}/stub" CLOUDFLARE_ACCOUNT_ID="${ACCOUNT_ID}" CLOUDFLARE_API_TOKEN="stub-terraform-token" \
    env -u AWS_SECRET_ACCESS_KEY AWS_ACCESS_KEY_ID="stub-r2-key-id" "${tree}/scripts/terraform.sh" --ci test apply >/dev/null 2>&1 &&
    failure "terraform CI without the R2 secret must stop"
  assert_equal "terraform CI without the R2 secret runs nothing" "" "$(changes_of "${tree}")"
  rm -rf "${tree}"
}

# Sourcing the file (to debug one case by hand) defines the helpers without running the tests.
[[ "${BASH_SOURCE[0]}" == "${0}" ]] || return 0

test_custom_domain_ci_deploy
test_workers_dev_ci_deploy
test_plain_http_checks
test_admin_gate_check
test_workers_dev_setting_check
test_new_routes_are_waited_for
test_before_signing_key
test_stops_before_any_change
test_ci_refuses_an_older_commit
test_removes_earlier_build_output
test_failed_idp_deploy_stops_the_admin_deploy
test_local_deploy
test_terraform_ci

if [[ "${failures}" -ne 0 ]]; then
  printf '%s test(s) failed\n' "${failures}" >&2
  exit 1
fi
printf 'all tests passed\n'
