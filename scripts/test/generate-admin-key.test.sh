#!/usr/bin/env bash
# Offline tests for scripts/generate-admin-key.sh. A stub op answers from files and logs every call, and a stub
# openssl refuses genpkey, so nothing here reaches 1Password or generates a key. The only key material is the
# published P-384 public keys of contract/testdata/vectors.json and RFC 6979 Appendix A.2.6, so xtrace stays on.
#
# The scripts are copied into a temporary tree, because lib.sh finds deployments/ next to its own directory.
set -euxo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TEST_DIR
REPO_ROOT="$(cd "${TEST_DIR}/../.." && pwd)"
readonly REPO_ROOT
# Exported, not readonly: the stub openssl runs it, and a readonly variable cannot prefix a command.
REAL_OPENSSL="$(command -v openssl)"
export REAL_OPENSSL

P384_SPKI="$(jq -er '.admin_signature.keyid.valid[0].spki' "${REPO_ROOT}/contract/testdata/vectors.json")"
readonly P384_SPKI
P384_KEYID="$(jq -er '.admin_signature.keyid.valid[0].keyid' "${REPO_ROOT}/contract/testdata/vectors.json")"
readonly P384_KEYID
ED25519_SPKI="$(jq -er '.admin_signature.keyid.valid[1].spki' "${REPO_ROOT}/contract/testdata/vectors.json")"
readonly ED25519_SPKI
readonly RFC6979_P384_SPKI="MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE7DpOQVtOGaRWhhgCn0J/pdqai8SukuAuBqrlKGswDGTe+PDqkFWGYGSiVFFUgLwTgBXZty19VyROqO+awMYhiWcIpZNn+d+59UyoSz8cnbEoiyMcOuDU/nNE/SUzJkcg"

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

# Builds a fresh tree: scripts/, deployments/test.tfvars.json, and bin/ with the stubs. Prints its path.
make_tree() {
  local tree
  tree="$(mktemp -d)"
  mkdir -p "${tree}/scripts" "${tree}/deployments" "${tree}/bin" "${tree}/op/fields"
  cp "${REPO_ROOT}/scripts/lib.sh" "${REPO_ROOT}/scripts/generate-admin-key.sh" "${tree}/scripts/"
  : >"${tree}/op/calls"
  jq -n '{
    hosting_mode: "custom_domain",
    zone: "example.com",
    issuer_host: "id.example.com",
    admin_host: "admin.id.example.com",
    onepassword_vault: "idp-test",
    onepassword_admin_key_item_prefix: "admin-key-",
    admin_signing_keys: []
  }' >"${tree}/deployments/test.tfvars.json"
  cp "${TEST_DIR}/stubs/op" "${TEST_DIR}/stubs/openssl" "${tree}/bin/"
  printf '%s\n' "${tree}"
}

# Stores a public key in the stub item as PEM, the way the generation script stores it.
set_item_public_key() {
  local tree="${1}"
  local spki="${2}"
  local sha256="${3}"
  printf '%s' "${spki}" | "${REAL_OPENSSL}" base64 -d -A | "${REAL_OPENSSL}" pkey -pubin -inform DER >"${tree}/op/fields/public_key"
  printf '%s\n' "${sha256}" >"${tree}/op/fields/public_key_sha256"
}

# Runs the script in the tree. Its stdout goes to out, its stderr to err, and the exit code to status.
run_script() {
  local tree="${1}"
  shift
  local status=0
  PATH="${tree}/bin:${PATH}" OP_STUB_DIR="${tree}/op" \
    "${tree}/scripts/generate-admin-key.sh" "$@" >"${tree}/out" 2>"${tree}/err" || status="$?"
  printf '%s\n' "${status}" >"${tree}/status"
}

status_of() {
  cat "${1}/status"
}

keys_of() {
  jq -c '.admin_signing_keys' "${1}/deployments/test.tfvars.json"
}

# The existing-item mode must never touch the private key: no read of the private_key field, and no
# `op item get`, whose JSON would carry the concealed fields into the script.
assert_only_public_fields_read() {
  local name="${1}"
  local tree="${2}"
  if grep -q 'private_key\|^item \|genpkey' "${tree}/op/calls"; then
    failure "${name}: op/openssl calls went beyond the public fields: $(tr '\n' ';' <"${tree}/op/calls")"
  else
    pass "${name}"
  fi
}

test_existing_item_writes_the_row() {
  local tree
  tree="$(make_tree)"
  set_item_public_key "${tree}" "${P384_SPKI}" "${P384_KEYID}"
  local expected
  expected="$(jq -nc --arg k "${P384_KEYID}" --arg p "${P384_SPKI}" '[{keyid: $k, name: "alice", public_key: $p}]')"

  run_script "${tree}" --from-existing test alice
  assert_equal "existing item: exit code" "0" "$(status_of "${tree}")"
  assert_equal "existing item: the row is written" "${expected}" "$(keys_of "${tree}")"
  assert_equal "existing item: stdout is the row" "$(printf '%s' "${expected}" | jq -c '.[0]')" "$(jq -c . "${tree}/out")"
  assert_equal "existing item: the other inputs are untouched" "example.com" \
    "$(jq -r '.zone' "${tree}/deployments/test.tfvars.json")"
  assert_equal "existing item: no CSR input is written" "false" \
    "$(jq 'has("admin_client_certificates")' "${tree}/deployments/test.tfvars.json")"
  assert_only_public_fields_read "existing item: reads only the public fields" "${tree}"

  run_script "${tree}" --from-existing test alice
  assert_equal "existing item: a second run keeps one row" "${expected}" "$(keys_of "${tree}")"
  rm -rf "${tree}"
}

test_existing_item_appends_to_other_admins() {
  local tree
  tree="$(make_tree)"
  local bob
  bob="$(jq -nc --arg p "${RFC6979_P384_SPKI}" --arg k "$(printf '%s' "${RFC6979_P384_SPKI}" | "${REAL_OPENSSL}" base64 -d -A | "${REAL_OPENSSL}" dgst -sha256 -r | cut -d ' ' -f 1)" \
    '{keyid: $k, name: "bob", public_key: $p}')"
  jq --argjson bob "${bob}" '.admin_signing_keys = [$bob]' "${tree}/deployments/test.tfvars.json" >"${tree}/config"
  mv "${tree}/config" "${tree}/deployments/test.tfvars.json"
  set_item_public_key "${tree}" "${P384_SPKI}" "${P384_KEYID}"

  run_script "${tree}" --from-existing test alice
  assert_equal "existing item: appends after other admins" "bob,alice" \
    "$(jq -r '.admin_signing_keys | map(.name) | join(",")' "${tree}/deployments/test.tfvars.json")"
  rm -rf "${tree}"
}

# Runs the script expecting a refusal whose stderr contains reason, and checks that the deployment file did not
# change. The reason proves that the refusal comes from the intended check, not from an unrelated failure.
assert_refused() {
  local name="${1}"
  local tree="${2}"
  local reason="${3}"
  shift 3
  local before
  before="$(cat "${tree}/deployments/test.tfvars.json")"
  run_script "${tree}" "$@"
  if [[ "$(status_of "${tree}")" == "0" ]]; then
    failure "${name}: expected a refusal"
  elif [[ "$(cat "${tree}/deployments/test.tfvars.json")" != "${before}" ]]; then
    failure "${name}: the deployment file changed"
  elif [[ -s "${tree}/out" ]]; then
    failure "${name}: printed a result on stdout"
  elif ! grep -qF -- "${reason}" "${tree}/err"; then
    failure "${name}: stderr lacks \"${reason}\": $(tail -n 3 "${tree}/err" | tr '\n' ';')"
  else
    pass "${name}"
  fi
}

test_existing_item_refusals() {
  local tree
  tree="$(make_tree)"
  set_item_public_key "${tree}" "${P384_SPKI}" "$(printf '0%.0s' {1..64})"
  assert_refused "existing item: public_key_sha256 that does not match public_key" "${tree}" \
    "does not match its public_key_sha256" --from-existing test alice

  set_item_public_key "${tree}" "${ED25519_SPKI}" "$(printf '%s' "${ED25519_SPKI}" | "${REAL_OPENSSL}" base64 -d -A | "${REAL_OPENSSL}" dgst -sha256 -r | cut -d ' ' -f 1)"
  assert_refused "existing item: a key that is not P-384" "${tree}" "is not an ECDSA P-384 key" --from-existing test alice

  printf 'not a key\n' >"${tree}/op/fields/public_key"
  assert_refused "existing item: a public_key that is not PEM" "${tree}" "is not a PEM public key" --from-existing test alice

  rm -f "${tree}/op/fields/public_key" "${tree}/op/fields/public_key_sha256"
  assert_refused "existing item: an item without public_key" "${tree}" "cannot read public_key" --from-existing test alice

  set_item_public_key "${tree}" "${P384_SPKI}" "${P384_KEYID}"
  assert_refused "existing item: an invalid admin name" "${tree}" "invalid admin name" --from-existing test Alice
  assert_refused "existing item: --replace together with --from-existing" "${tree}" "Usage:" --replace --from-existing test alice
  assert_only_public_fields_read "existing item: refusals read only the public fields" "${tree}"

  jq -c --arg k "${P384_KEYID}" --arg p "${P384_SPKI}" '.admin_signing_keys = [{keyid: $k, name: "bob", public_key: $p}]' \
    "${tree}/deployments/test.tfvars.json" >"${tree}/config"
  mv "${tree}/config" "${tree}/deployments/test.tfvars.json"
  assert_refused "existing item: a keyid that already belongs to another admin" "${tree}" \
    "already belongs to another admin" --from-existing test alice
  rm -rf "${tree}"
}

test_invalid_deployment_file_stops_before_op() {
  local tree
  tree="$(make_tree)"
  set_item_public_key "${tree}" "${P384_SPKI}" "${P384_KEYID}"
  jq 'del(.admin_signing_keys)' "${tree}/deployments/test.tfvars.json" >"${tree}/config"
  mv "${tree}/config" "${tree}/deployments/test.tfvars.json"
  assert_refused "a deployment file without admin_signing_keys (existing item)" "${tree}" \
    "lacks the list \"admin_signing_keys\"" --from-existing test alice
  assert_refused "a deployment file without admin_signing_keys (generation)" "${tree}" \
    "lacks the list \"admin_signing_keys\"" test alice

  jq -c --arg p "${P384_SPKI}" '.admin_signing_keys = [{keyid: ("0" * 64), name: "bob", public_key: $p}]' \
    "${tree}/deployments/test.tfvars.json" >"${tree}/config"
  mv "${tree}/config" "${tree}/deployments/test.tfvars.json"
  assert_refused "a deployment file with a wrong keyid (generation)" "${tree}" \
    "is not the SHA-256 of its public_key" test alice
  assert_equal "an invalid deployment file stops before op and openssl genpkey" "" "$(cat "${tree}/op/calls")"
  rm -rf "${tree}"
}

# A deployment file that still holds an input removed with mTLS stops the script before 1Password is touched
# (docs/design/hosting-modes.md 1.1 and plan step 7).
test_removed_inputs_stop_before_op() {
  local tree
  local input
  for input in admin_allowlist admin_client_certificates; do
    tree="$(make_tree)"
    set_item_public_key "${tree}" "${P384_SPKI}" "${P384_KEYID}"
    jq --arg input "${input}" '.[$input] = {}' "${tree}/deployments/test.tfvars.json" >"${tree}/config"
    mv "${tree}/config" "${tree}/deployments/test.tfvars.json"
    assert_refused "${input} stops the script (existing item)" "${tree}" "removed with mTLS" --from-existing test alice
    assert_refused "${input} stops the script (generation)" "${tree}" "removed with mTLS" test alice
    assert_equal "${input} stops before op and openssl genpkey" "" "$(cat "${tree}/op/calls")"
    rm -rf "${tree}"
  done
}

# The script no longer makes a CSR: neither its help nor its code may mention one (hosting-modes.md 3.10).
test_no_csr() {
  if grep -qi 'csr\|certificate request\|openssl req' "${REPO_ROOT}/scripts/generate-admin-key.sh"; then
    failure "generate-admin-key.sh still mentions a CSR"
  else
    pass "generate-admin-key.sh makes no CSR"
  fi
}

test_generation_refuses_an_existing_item_before_generating() {
  local tree
  tree="$(make_tree)"
  : >"${tree}/op/item_exists"
  assert_refused "generation: an existing item without --replace" "${tree}" "already exists" test alice
  if grep -q 'genpkey\|^item create' "${tree}/op/calls"; then
    failure "generation: generated or stored a key despite the existing item"
  else
    pass "generation: stops before generating a key"
  fi
  rm -rf "${tree}"
}

test_usage() {
  local tree
  tree="$(make_tree)"
  run_script "${tree}" --help
  assert_equal "--help exits 0" "0" "$(status_of "${tree}")"
  if grep -q -- '--from-existing' "${tree}/out"; then pass "--help documents --from-existing"; else failure "--help lacks --from-existing"; fi
  run_script "${tree}" --from-existing test
  assert_equal "a missing admin name exits 2" "2" "$(status_of "${tree}")"
  run_script "${tree}" --replace --from-existing test alice
  assert_equal "--replace with --from-existing exits 2" "2" "$(status_of "${tree}")"
  rm -rf "${tree}"
}

test_existing_item_writes_the_row
test_existing_item_appends_to_other_admins
test_existing_item_refusals
test_invalid_deployment_file_stops_before_op
test_removed_inputs_stop_before_op
test_no_csr
test_generation_refuses_an_existing_item_before_generating
test_usage

if [[ "${failures}" -ne 0 ]]; then
  printf '%s test(s) failed\n' "${failures}" >&2
  exit 1
fi
printf 'all tests passed\n'
