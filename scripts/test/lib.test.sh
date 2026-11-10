#!/usr/bin/env bash
# Offline tests for scripts/lib.sh. They use only published test vectors (RFC 8037 Appendix A, the public keys of
# contract/testdata/vectors.json and RFC 6979 Appendix A.2.6), which are not secrets, so xtrace stays on. Nothing here calls op, cf, or the network, and nothing generates a key.
set -euxo pipefail

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

failures=0

assert_equal() {
  local name="${1}"
  local expected="${2}"
  local actual="${3}"
  if [[ "${actual}" == "${expected}" ]]; then
    printf 'ok   %s\n' "${name}"
  else
    printf 'FAIL %s: expected %s, got %s\n' "${name}" "${expected}" "${actual}" >&2
    failures=$((failures + 1))
  fi
}

assert_fails() {
  local name="${1}"
  shift
  if ("$@") >/dev/null 2>&1; then
    printf 'FAIL %s: expected a failure\n' "${name}" >&2
    failures=$((failures + 1))
  else
    printf 'ok   %s\n' "${name}"
  fi
}

# RFC 8037 A.1: the private key d, and the public key x derived from it.
readonly RFC8037_D="nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
readonly RFC8037_X="11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
# RFC 8037 A.3: the JWK thumbprint of that public key.
readonly RFC8037_KID="kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
# The RFC 8037 A.1 key as PKCS#8 DER (the RFC 8410 §7 header followed by d), base64.
readonly RFC8037_PKCS8="MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g"

test_kid_matches_rfc8037() {
  assert_equal "ed25519_kid matches RFC 8037 A.3" "${RFC8037_KID}" "$(ed25519_kid "${RFC8037_X}")"
}

test_private_jwk_from_pkcs8() {
  local jwk
  jwk="$(printf '%s' "${RFC8037_PKCS8}" | ed25519_private_jwk_from_pkcs8)"
  assert_equal "jwk d" "${RFC8037_D}" "$(printf '%s' "${jwk}" | jq -r .d)"
  assert_equal "jwk x" "${RFC8037_X}" "$(printf '%s' "${jwk}" | jq -r .x)"
  assert_equal "jwk kid" "${RFC8037_KID}" "$(printf '%s' "${jwk}" | jq -r .kid)"
  assert_equal "jwk alg and use" "Ed25519 sig OKP Ed25519" "$(printf '%s' "${jwk}" | jq -r '"\(.alg) \(.use) \(.kty) \(.crv)"')"
}

test_public_jwk_has_no_private_member() {
  local public
  public="$(printf '%s' "${RFC8037_PKCS8}" | ed25519_private_jwk_from_pkcs8 | public_jwk)"
  assert_equal "public jwk members" "alg,crv,kid,kty,use,x" "$(printf '%s' "${public}" | jq -r 'keys | join(",")')"
}

reject_truncated_pkcs8() {
  printf '%s' "MC4CAQAwBQYDK2VwBCIEIJ1h" | ed25519_private_jwk_from_pkcs8
}

reject_non_ed25519_header() {
  # The RFC 8037 key with the OID byte for X25519 (0x6e) instead of Ed25519 (0x70).
  printf '%s' "MC4CAQAwBQYDK2VuBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g" | ed25519_private_jwk_from_pkcs8
}

test_rejects_malformed_pkcs8() {
  assert_fails "rejects a truncated PKCS#8 key" reject_truncated_pkcs8
  assert_fails "rejects a non-Ed25519 PKCS#8 key" reject_non_ed25519_header
}

test_base64url_has_no_padding_or_unsafe_characters() {
  assert_equal "base64url of 0xfb 0xff" "-_8" "$(printf '\373\377' | base64url)"
}

test_deployment_config_path_rejects_unsafe_names() {
  assert_fails "rejects a path traversal" deployment_config_path "../etc"
  assert_fails "rejects an uppercase name" deployment_config_path "Prod"
  assert_fails "rejects a missing file" deployment_config_path "no-such-deployment"
}

test_config_string_fails_closed() {
  local config
  config="$(mktemp)"
  printf '%s' '{"zone":"example.com","empty":"","number":1}' >"${config}"
  assert_equal "reads a string input" "example.com" "$(config_string "${config}" zone)"
  assert_fails "rejects an empty input" config_string "${config}" empty
  assert_fails "rejects a non-string input" config_string "${config}" number
  assert_fails "rejects a missing input" config_string "${config}" absent
  rm -f "${config}"
}

# The P-384 keyid vector of contract/testdata/vectors.json: only a public key, so it is not a secret.
VECTORS="${IDP_REPO_ROOT}/contract/testdata/vectors.json"
readonly VECTORS
P384_SPKI="$(jq -er '.admin_signature.keyid.valid[0].spki' "${VECTORS}")"
readonly P384_SPKI
P384_KEYID="$(jq -er '.admin_signature.keyid.valid[0].keyid' "${VECTORS}")"
readonly P384_KEYID
# The Ed25519 key of RFC 9421 Appendix B.1.4 from the same vectors: a valid SPKI that is not P-384.
ED25519_SPKI="$(jq -er '.admin_signature.keyid.valid[1].spki' "${VECTORS}")"
readonly ED25519_SPKI
# The public key of RFC 6979 Appendix A.2.6 (P-384) as an SPKI: a second P-384 key with a published value.
readonly RFC6979_P384_SPKI="MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE7DpOQVtOGaRWhhgCn0J/pdqai8SukuAuBqrlKGswDGTe+PDqkFWGYGSiVFFUgLwTgBXZty19VyROqO+awMYhiWcIpZNn+d+59UyoSz8cnbEoiyMcOuDU/nNE/SUzJkcg"

test_p384_keyid_matches_the_contract_vector() {
  assert_equal "p384_spki_keyid matches the contract vector" "${P384_KEYID}" "$(p384_spki_keyid "${P384_SPKI}")"
}

test_p384_keyid_rejects_other_keys_and_encodings() {
  assert_fails "rejects an Ed25519 SPKI" p384_spki_keyid "${ED25519_SPKI}"
  # The last base64 character changed: the point is no longer on the curve.
  assert_fails "rejects a point off the curve" p384_spki_keyid "${P384_SPKI%?}U"
  assert_fails "rejects base64 without padding" p384_spki_keyid "${ED25519_SPKI%=}"
  assert_fails "rejects base64url" p384_spki_keyid "$(printf '%s' "${P384_SPKI}" | tr '+/' '-_')"
  assert_fails "rejects base64 split over lines" p384_spki_keyid "${P384_SPKI:0:64}"$'\n'"${P384_SPKI:64}"
  assert_fails "rejects an empty value" p384_spki_keyid ""
}

test_spki_base64_from_public_pem() {
  local pem
  pem="$(printf '%s' "${P384_SPKI}" | openssl base64 -d -A | openssl pkey -pubin -inform DER)"
  assert_equal "PEM to SPKI base64" "${P384_SPKI}" "$(printf '%s\n' "${pem}" | spki_base64_from_public_pem)"
}

test_admin_signing_key_row() {
  local row
  row="$(admin_signing_key_row alice "${P384_SPKI}")"
  assert_equal "row members" "keyid,name,public_key" "$(printf '%s' "${row}" | jq -r 'keys | join(",")')"
  assert_equal "row keyid" "${P384_KEYID}" "$(printf '%s' "${row}" | jq -r .keyid)"
  assert_equal "row public_key" "${P384_SPKI}" "$(printf '%s' "${row}" | jq -r .public_key)"
  assert_equal "row name" "alice" "$(printf '%s' "${row}" | jq -r .name)"
  assert_fails "rejects an invalid admin name" admin_signing_key_row "Alice" "${P384_SPKI}"
  assert_fails "rejects a non-P-384 key" admin_signing_key_row alice "${ED25519_SPKI}"
}

# Writes a deployment file whose admin_signing_keys is the given JSON and prints its path.
config_with_keys() {
  local keys="${1}"
  local config
  config="$(mktemp)"
  jq -n --argjson keys "${keys}" '{zone: "example.com", admin_signing_keys: $keys}' >"${config}"
  printf '%s\n' "${config}"
}

check_keys() {
  local keys="${1}"
  local config
  config="$(config_with_keys "${keys}")"
  check_admin_signing_keys "${config}"
  rm -f "${config}"
}

test_check_admin_signing_keys() {
  local alice
  local bob
  alice="$(jq -nc --arg k "${P384_KEYID}" --arg p "${P384_SPKI}" '{keyid: $k, name: "alice", public_key: $p}')"
  bob="$(admin_signing_key_row bob "${RFC6979_P384_SPKI}")"
  assert_equal "accepts an empty list" "ok" "$(check_keys '[]' && printf ok)"
  assert_equal "accepts valid rows" "ok" "$(check_keys "[${alice},${bob}]" && printf ok)"
  assert_equal "accepts two keys of one admin" "ok" \
    "$(check_keys "[${alice},$(printf '%s' "${bob}" | jq -c '.name = "alice"')]" && printf ok)"
  assert_fails "rejects a missing list" check_admin_signing_keys "$(mktemp)"
  assert_fails "rejects an object instead of a list" check_keys "{\"alice\":${alice}}"
  assert_fails "rejects a repeated keyid" check_keys "[${alice},$(printf '%s' "${alice}" | jq -c '.name = "carol"')]"
  assert_fails "rejects another member" check_keys "[$(printf '%s' "${alice}" | jq -c '.alg = "ecdsa-p384-sha384"')]"
  assert_fails "rejects a missing member" check_keys "[$(printf '%s' "${alice}" | jq -c 'del(.name)')]"
  assert_fails "rejects a non-string member" check_keys "[$(printf '%s' "${alice}" | jq -c '.name = 1')]"
  assert_fails "rejects an uppercase keyid" check_keys "[$(printf '%s' "${alice}" | jq -c '.keyid |= ascii_upcase')]"
  assert_fails "rejects a keyid of another key" check_keys "[$(printf '%s' "${bob}" | jq -c --arg k "${P384_KEYID}" '.keyid = $k')]"
  assert_fails "rejects an invalid name" check_keys "[$(printf '%s' "${alice}" | jq -c '.name = "-alice"')]"
  # $(...) strips trailing newlines, so these pass unless the forms are checked on the raw JSON strings.
  assert_fails "rejects a keyid with a trailing newline" check_keys "[$(printf '%s' "${alice}" | jq -c '.keyid += "\n"')]"
  assert_fails "rejects a name with a trailing newline" check_keys "[$(printf '%s' "${alice}" | jq -c '.name += "\n"')]"
  assert_fails "rejects a public_key with a trailing newline" check_keys "[$(printf '%s' "${alice}" | jq -c '.public_key += "\n"')]"
  assert_fails "rejects keyids that differ only by a trailing newline" \
    check_keys "[${alice},$(printf '%s' "${alice}" | jq -c '.keyid += "\n" | .name = "carol"')]"
  assert_fails "rejects a non-P-384 key" check_keys "[$(admin_signing_key_row_unchecked carol "${ED25519_SPKI}")]"
}

# A row for a key that admin_signing_key_row would refuse, to prove that the check refuses it too.
admin_signing_key_row_unchecked() {
  local name="${1}"
  local spki="${2}"
  local keyid
  keyid="$(printf '%s' "${spki}" | openssl base64 -d -A | openssl dgst -sha256 -r | cut -d ' ' -f 1)"
  jq -nc --arg k "${keyid}" --arg n "${name}" --arg p "${spki}" '{keyid: $k, name: $n, public_key: $p}'
}

test_write_admin_signing_key_row() {
  local alice
  local alice_new
  local bob
  alice="$(admin_signing_key_row alice "${P384_SPKI}")"
  alice_new="$(admin_signing_key_row alice "${RFC6979_P384_SPKI}")"
  bob="$(admin_signing_key_row bob "${RFC6979_P384_SPKI}")"
  local config
  config="$(config_with_keys '[]')"

  write_admin_signing_key_row "${config}" "${alice}" false
  assert_equal "appends a row" "${P384_KEYID}" "$(jq -r '.admin_signing_keys | map(.keyid) | join(",")' "${config}")"
  write_admin_signing_key_row "${config}" "${alice}" false
  assert_equal "writing the same row twice keeps one" "1" "$(jq -r '.admin_signing_keys | length' "${config}")"
  assert_equal "keeps the other inputs" "example.com" "$(jq -r .zone "${config}")"
  assert_fails "rejects a keyid that belongs to another admin" write_admin_signing_key_row "${config}" \
    "$(printf '%s' "${alice}" | jq -c '.name = "carol"')" false
  assert_fails "rejects a row that fails the check" write_admin_signing_key_row "${config}" \
    "$(printf '%s' "${bob}" | jq -c --arg k "${P384_KEYID}" '.keyid = $k')" false
  assert_equal "a refused row leaves the file unchanged" "alice" "$(jq -r '.admin_signing_keys | map(.name) | join(",")' "${config}")"

  write_admin_signing_key_row "${config}" "${alice_new}" false
  assert_equal "without replace an admin keeps the old key" "2" "$(jq -r '.admin_signing_keys | length' "${config}")"
  write_admin_signing_key_row "${config}" "${alice}" true
  assert_equal "replace drops the admin's other keys" "${P384_KEYID}" "$(jq -r '.admin_signing_keys | map(.keyid) | join(",")' "${config}")"
  rm -f "${config}"
}

test_kid_matches_rfc8037
test_private_jwk_from_pkcs8
test_public_jwk_has_no_private_member
test_rejects_malformed_pkcs8
test_base64url_has_no_padding_or_unsafe_characters
test_deployment_config_path_rejects_unsafe_names
test_config_string_fails_closed
test_p384_keyid_matches_the_contract_vector
test_p384_keyid_rejects_other_keys_and_encodings
test_spki_base64_from_public_pem
test_admin_signing_key_row
test_check_admin_signing_keys
test_write_admin_signing_key_row

if [[ "${failures}" -ne 0 ]]; then
  printf '%s test(s) failed\n' "${failures}" >&2
  exit 1
fi
printf 'all tests passed\n'
