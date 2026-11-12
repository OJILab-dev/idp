#!/usr/bin/env bash
# Offline tests for scripts/deploy-rp-sample.sh and scripts/set-rp-sample-secrets.sh. The stubs of
# scripts/test/rp-sample-stubs stand in for pnpm (cf), curl, and openssl, scripts/test/deploy-stubs/git for git, and
# scripts/test/stubs/op for op, so nothing here reaches Cloudflare, 1Password, or the network. The client secret
# and the session key are fake, public test values, so xtrace stays on here.
#
# The scripts are copied into a temporary tree, because lib.sh finds deployments/ and examples/ next to its own
# directory.
set -euxo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TEST_DIR
REPO_ROOT="$(cd "${TEST_DIR}/../.." && pwd)"
readonly REPO_ROOT
readonly ACCOUNT_ID="0123456789abcdef0123456789abcdef"
readonly HEAD_SHA="1111111111111111111111111111111111111111"
# Fake values in the formats the script accepts; never real secrets.
readonly FAKE_CLIENT_SECRET="test-client-secret-not-real-0123456789abcde"
readonly FAKE_SESSION_KEY="c3R1Yi1zZXNzaW9uLWtleS0zMi1ieXRlcy1sb25nISE="

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

# Builds a fresh tree: scripts/, deployments/test.tfvars.json, examples/rp-sample/, bin/ with the stubs, and stub/
# with the stubs' answers for a healthy account. Prints its path.
make_tree() {
  local mode="${1}"
  local tree
  tree="$(mktemp -d)"
  mkdir -p "${tree}/scripts" "${tree}/deployments" "${tree}/examples/rp-sample" "${tree}/bin" "${tree}/stub/op/fields"
  cp "${REPO_ROOT}/scripts/lib.sh" "${REPO_ROOT}/scripts/deploy-rp-sample.sh" "${REPO_ROOT}/scripts/set-rp-sample-secrets.sh" "${tree}/scripts/"
  cp "${TEST_DIR}/rp-sample-stubs/pnpm" "${TEST_DIR}/rp-sample-stubs/curl" "${TEST_DIR}/rp-sample-stubs/openssl" \
    "${TEST_DIR}/deploy-stubs/git" "${TEST_DIR}/deploy-stubs/sleep" "${TEST_DIR}/stubs/op" "${tree}/bin/"
  local hosting
  if [[ "${mode}" == "custom_domain" ]]; then
    hosting='{hosting_mode: "custom_domain", zone: "example.com", issuer_host: "id.example.com", admin_host: "admin.id.example.com"}'
  else
    hosting='{hosting_mode: "workers_dev", workers_dev_subdomain: "team-1"}'
  fi
  jq -n "${hosting}"' + {
    d1_database_name: "idp-test",
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
  printf '%s' '{"success":true,"errors":[],"result":{"subdomain":"team-1"}}' >"${stub}/subdomain_response"
  printf '%s' '{"subdomain":{"enabled":true,"previews_enabled":false}}' >"${stub}/workers_rp-sample.json"
  printf 'unconfigured\n' >"${stub}/rp_state"
  # The file idpctl client_create --secret-out writes: the value and a newline, mode 0600.
  printf '%s\n' "${FAKE_CLIENT_SECRET}" >"${tree}/client-secret"
  chmod 600 "${tree}/client-secret"
  printf '%s\n' "${tree}"
}

# Runs scripts/<script> in the tree as the operator does: no token in the environment, op signed in, cf logged in.
# stdin comes from the file named by STDIN_FILE (default /dev/null). Its stdout goes to out, stderr to err, and the
# exit code to status.
run() {
  local tree="${1}"
  local script="${2}"
  shift 2
  local status=0
  PATH="${tree}/bin:${PATH}" STUB_DIR="${tree}/stub" OP_STUB_DIR="${tree}/stub/op" \
    env -u CLOUDFLARE_API_TOKEN -u CLOUDFLARE_ACCOUNT_ID "${tree}/scripts/${script}" "$@" \
    <"${STDIN_FILE:-/dev/null}" >"${tree}/out" 2>"${tree}/err" || status="$?"
  printf '%s\n' "${status}" >"${tree}/status"
}

status_of() {
  cat "${1}/status"
}

# The cf calls that build, deploy, or set a secret, in order, joined with ";".
changes_of() {
  grep -E '^cf [^ ]+ (build|deploy|workers secrets)' "${1}/stub/calls" | sed -E 's/^cf [^ ]+ /cf /' | tr '\n' ';' || true
}

test_deploy() {
  local tree
  tree="$(make_tree workers_dev)"
  run "${tree}" deploy-rp-sample.sh test rp-sample
  assert_equal "deploy: exit code" "0" "$(status_of "${tree}")"
  assert_equal "deploy: build, then deploy labelled with HEAD" "cf build;cf deploy --prebuilt --message deploy ${HEAD_SHA};" "$(changes_of "${tree}")"
  assert_equal "deploy: both run in the sample's project" "2" "$(grep -c '^cf rp-sample \(build\|deploy\)' "${tree}/stub/calls")"
  assert_equal "deploy: the build environment" \
    "RP_SAMPLE_CLIENT_ID=rp-sample|RP_SAMPLE_ISSUER=https://idp.team-1.workers.dev|RP_SAMPLE_ORIGIN=https://rp-sample.team-1.workers.dev" \
    "$(tr '\n' '|' <"${tree}/stub/build_env" | sed 's/|$//')"
  assert_equal "deploy: the workers.dev subdomain is checked before the build" "curl subdomain" \
    "$(grep -E '^curl subdomain|^cf [^ ]+ build' "${tree}/stub/calls" | head -n 1)"
  assert_equal "deploy: the token reaches curl through op run" "op://idp-test/cloudflare/terraform_api_token" \
    "$(cat "${tree}/stub/op/token_reference")"
  # workers.dev's bot protection refuses library default User-Agents.
  assert_equal "deploy: probes its own host with a named User-Agent" "https://rp-sample.team-1.workers.dev/ user_agent=idp-deploy-check" \
    "$(cat "${tree}/stub/probes")"
  assert_equal "deploy: never touches the IdP or admin Workers" "0" \
    "$(grep -cE 'cf [^ ]+ .*(--worker idp|workers get idp|d1 )|^cf (worker|admin-worker) ' "${tree}/stub/calls" || true)"
  assert_equal "deploy: tells the operator to set the secrets" "1" "$(grep -c '^the sample answers .*set-rp-sample-secrets.sh' "${tree}/err")"
  rm -rf "${tree}"

  tree="$(make_tree workers_dev)"
  printf 'ok\n' >"${tree}/stub/rp_state"
  run "${tree}" deploy-rp-sample.sh test rp-sample
  assert_equal "deploy: a configured sample answers 200" "0" "$(status_of "${tree}")"
  rm -rf "${tree}"

  tree="$(make_tree workers_dev)"
  printf 'broken\n' >"${tree}/stub/rp_state"
  run "${tree}" deploy-rp-sample.sh test rp-sample
  assert_equal "deploy: another 500 fails" "1" "$(status_of "${tree}")"
  rm -rf "${tree}"

  tree="$(make_tree workers_dev)"
  printf '%s' '{"subdomain":{"enabled":true,"previews_enabled":true}}' >"${tree}/stub/workers_rp-sample.json"
  run "${tree}" deploy-rp-sample.sh test rp-sample
  assert_equal "deploy: preview URLs on fails" "1" "$(status_of "${tree}")"
  rm -rf "${tree}"

  # Right after the first deploy, workers.dev answers a plain-text 404 until the new Worker's route is live.
  tree="$(make_tree workers_dev)"
  printf '3\n' >"${tree}/stub/not_live_count"
  run "${tree}" deploy-rp-sample.sh test rp-sample
  assert_equal "deploy: waits for a new route to go live" "0" "$(status_of "${tree}")"
  assert_equal "deploy: probes until the route is live" "4" "$(wc -l <"${tree}/stub/probes" | tr -d ' ')"
  assert_equal "deploy: waits between the probes" "3" "$(wc -l <"${tree}/stub/sleeps" | tr -d ' ')"
  rm -rf "${tree}"

  tree="$(make_tree workers_dev)"
  printf 'never_live\n' >"${tree}/stub/rp_state"
  run "${tree}" deploy-rp-sample.sh test rp-sample
  assert_equal "deploy: a route that never goes live fails" "1" "$(status_of "${tree}")"
  assert_equal "deploy: gives up after 12 probes" "12" "$(wc -l <"${tree}/stub/probes" | tr -d ' ')"
  assert_equal "deploy: no wait after the last probe" "11" "$(wc -l <"${tree}/stub/sleeps" | tr -d ' ')"
  rm -rf "${tree}"

  tree="$(make_tree workers_dev)"
  mkdir -p "${tree}/examples/rp-sample/.cloudflare"
  run "${tree}" deploy-rp-sample.sh test rp-sample
  assert_equal "deploy: an earlier build's output is removed first" "0" "$(status_of "${tree}")"
  rm -rf "${tree}"
}

# Each case must stop before any build or deploy.
test_deploy_stops_before_any_change() {
  local name
  local tree
  for name in custom_domain bad_client_id dirty older_head subdomain_mismatch other_account; do
    tree="$(make_tree workers_dev)"
    local client_id="rp-sample"
    case "${name}" in
      custom_domain) rm -rf "${tree}" && tree="$(make_tree custom_domain)" ;;
      bad_client_id) client_id="RP_Sample" ;;
      dirty) printf ' M README.md\n' >"${tree}/stub/git_status" ;;
      older_head) printf '2222222222222222222222222222222222222222\n' >"${tree}/stub/git_head" ;;
      subdomain_mismatch) printf '%s' '{"success":true,"errors":[],"result":{"subdomain":"team-2"}}' >"${tree}/stub/subdomain_response" ;;
      other_account) printf 'ffffffffffffffffffffffffffffffff\n' >"${tree}/stub/account_id" ;;
    esac
    run "${tree}" deploy-rp-sample.sh test "${client_id}"
    assert_equal "deploy ${name}: exit code" "1" "$(status_of "${tree}")"
    assert_equal "deploy ${name}: nothing built or deployed" "" "$(changes_of "${tree}")"
    rm -rf "${tree}"
  done
}

test_set_secrets() {
  local tree
  tree="$(make_tree workers_dev)"
  run "${tree}" set-rp-sample-secrets.sh test "${tree}/client-secret"
  assert_equal "secrets: exit code" "0" "$(status_of "${tree}")"
  assert_equal "secrets: the client secret, then the session key, on the sample's Worker" \
    "cf workers secrets update CLIENT_SECRET --worker rp-sample --type secret_text --body @/dev/stdin;cf workers secrets update SESSION_KEY --worker rp-sample --type secret_text --body @/dev/stdin;" \
    "$(changes_of "${tree}")"
  # The trailing newline of the --secret-out file is not part of the secret.
  assert_equal "secrets: the client secret body" "{\"name\":\"CLIENT_SECRET\",\"type\":\"secret_text\",\"text\":\"${FAKE_CLIENT_SECRET}\"}" \
    "$(cat "${tree}/stub/secret_CLIENT_SECRET.json")"
  assert_equal "secrets: the session key comes from openssl rand, without a newline" \
    "{\"name\":\"SESSION_KEY\",\"type\":\"secret_text\",\"text\":\"${FAKE_SESSION_KEY}\"}" "$(cat "${tree}/stub/secret_SESSION_KEY.json")"
  assert_equal "secrets: stdout is empty" "" "$(cat "${tree}/out")"
  assert_equal "secrets: stderr never shows the client secret" "0" "$(grep -c "${FAKE_CLIENT_SECRET}" "${tree}/err" || true)"
  assert_equal "secrets: stderr never shows the session key" "0" "$(grep -c "${FAKE_SESSION_KEY}" "${tree}/err" || true)"
  rm -rf "${tree}"

  tree="$(make_tree workers_dev)"
  STDIN_FILE="${tree}/client-secret" run "${tree}" set-rp-sample-secrets.sh test -
  assert_equal "secrets from stdin: exit code" "0" "$(status_of "${tree}")"
  assert_equal "secrets from stdin: the client secret body" "{\"name\":\"CLIENT_SECRET\",\"type\":\"secret_text\",\"text\":\"${FAKE_CLIENT_SECRET}\"}" \
    "$(cat "${tree}/stub/secret_CLIENT_SECRET.json")"
  rm -rf "${tree}"
}

# Each case must stop before any secret is set, and without showing the value it read.
test_set_secrets_refusals() {
  local name
  local tree
  for name in readable_by_others symlink missing short custom_domain other_account; do
    tree="$(make_tree workers_dev)"
    local source="${tree}/client-secret"
    case "${name}" in
      readable_by_others) chmod 644 "${source}" ;;
      symlink) ln -s "${source}" "${tree}/link" && source="${tree}/link" ;;
      missing) source="${tree}/absent" ;;
      short) printf 'short-not-a-secret-value\n' >"${source}" ;;
      custom_domain) rm -rf "${tree}" && tree="$(make_tree custom_domain)" && source="${tree}/client-secret" ;;
      other_account) printf 'ffffffffffffffffffffffffffffffff\n' >"${tree}/stub/account_id" ;;
    esac
    run "${tree}" set-rp-sample-secrets.sh test "${source}"
    assert_equal "secrets ${name}: exit code" "1" "$(status_of "${tree}")"
    assert_equal "secrets ${name}: nothing set" "" "$(changes_of "${tree}")"
    assert_equal "secrets ${name}: the value is not shown" "0" \
      "$(grep -cE "${FAKE_CLIENT_SECRET}|short-not-a-secret-value" "${tree}/err" "${tree}/out" | awk -F: '{ sum += $NF } END { print sum }')"
    rm -rf "${tree}"
  done
}

test_secret_script_has_no_xtrace() {
  # xtrace would print the secret after expansion (scripts/upload-signing-key.sh has the same rule).
  assert_equal "secrets: no set -x anywhere" "0" "$(grep -cE '^[[:space:]]*set -[a-z]*x' "${REPO_ROOT}/scripts/set-rp-sample-secrets.sh" || true)"
  assert_equal "secrets: set -euo pipefail" "1" "$(grep -c '^set -euo pipefail$' "${REPO_ROOT}/scripts/set-rp-sample-secrets.sh")"
}

test_usage() {
  local tree
  tree="$(make_tree workers_dev)"
  run "${tree}" deploy-rp-sample.sh --help
  assert_equal "deploy --help: exit code" "0" "$(status_of "${tree}")"
  run "${tree}" deploy-rp-sample.sh test
  assert_equal "deploy without client_id: exit code" "2" "$(status_of "${tree}")"
  run "${tree}" set-rp-sample-secrets.sh --help
  assert_equal "secrets --help: exit code" "0" "$(status_of "${tree}")"
  run "${tree}" set-rp-sample-secrets.sh test
  assert_equal "secrets without a source: exit code" "2" "$(status_of "${tree}")"
  # A secret as an argument would show in the process list; only a path or - is taken, and a value is not a file.
  run "${tree}" set-rp-sample-secrets.sh test "${FAKE_CLIENT_SECRET}"
  assert_equal "secrets with a value instead of a path: exit code" "1" "$(status_of "${tree}")"
  assert_equal "secrets with a value instead of a path: nothing set" "" "$(changes_of "${tree}")"
  rm -rf "${tree}"
}

test_deploy
test_deploy_stops_before_any_change
test_set_secrets
test_set_secrets_refusals
test_secret_script_has_no_xtrace
test_usage

if [[ "${failures}" -ne 0 ]]; then
  printf '%s test(s) failed\n' "${failures}" >&2
  exit 1
fi
printf 'all tests passed\n'
