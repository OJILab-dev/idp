#!/usr/bin/env bash
# Offline tests for scripts/lib.sh. They use only the published test vectors of RFC 8037 Appendix A, which are
# not secrets, so xtrace stays on. Nothing here calls op, cf, or the network, and nothing generates a key.
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

assert_succeeds() {
  local name="${1}"
  shift
  if ("$@") >/dev/null 2>&1; then
    printf 'ok   %s\n' "${name}"
  else
    printf 'FAIL %s: expected success\n' "${name}" >&2
    failures=$((failures + 1))
  fi
}

test_is_waf_block_tells_the_edge_from_the_worker() {
  assert_succeeds "a 403 HTML page is the WAF block" is_waf_block 403 "text/html; charset=UTF-8"
  assert_fails "the admin Worker's own 403 problem reached the Worker" is_waf_block 403 "application/problem+json"
  assert_fails "a 200 is not a block" is_waf_block 200 "text/html"
  assert_fails "an unreachable host is not a block" is_waf_block 000 ""
}

test_kid_matches_rfc8037
test_private_jwk_from_pkcs8
test_public_jwk_has_no_private_member
test_rejects_malformed_pkcs8
test_base64url_has_no_padding_or_unsafe_characters
test_deployment_config_path_rejects_unsafe_names
test_config_string_fails_closed
test_is_waf_block_tells_the_edge_from_the_worker

if [[ "${failures}" -ne 0 ]]; then
  printf '%s test(s) failed\n' "${failures}" >&2
  exit 1
fi
printf 'all tests passed\n'
