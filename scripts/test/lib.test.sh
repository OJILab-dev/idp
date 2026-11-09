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

test_is_https_redirect_requires_the_rule_shape() {
  local expected="https://id.example.com/.well-known/openid-configuration?smoke=1"
  assert_succeeds "a 301 to the same URL over https is the rule" is_https_redirect 301 "${expected}" "${expected}"
  assert_fails "the IdP Worker's 404 for http means the rule is missing" is_https_redirect 404 "" "${expected}"
  assert_fails "a 302 is not the rule's permanent redirect" is_https_redirect 302 "${expected}" "${expected}"
  assert_fails "a redirect that drops the query is not the rule" is_https_redirect 301 \
    "https://id.example.com/.well-known/openid-configuration" "${expected}"
  assert_fails "a redirect to another host is not the rule" is_https_redirect 301 \
    "https://www.example.com/.well-known/openid-configuration?smoke=1" "${expected}"
}

test_zone_singletons_owner_is_idp_or_external() {
  local config
  config="$(mktemp)"
  printf '%s' '{"zone_singletons_owner":"external"}' >"${config}"
  assert_equal "reads external" "external" "$(config_zone_singletons_owner "${config}")"
  printf '%s' '{"zone_singletons_owner":"idp"}' >"${config}"
  assert_equal "reads idp" "idp" "$(config_zone_singletons_owner "${config}")"
  printf '%s' '{"zone_singletons_owner":"service"}' >"${config}"
  assert_fails "rejects an unknown owner" config_zone_singletons_owner "${config}"
  printf '%s' '{}' >"${config}"
  assert_fails "rejects a missing owner" config_zone_singletons_owner "${config}"
  rm -f "${config}"
}

# A throwaway origin (bare) and a clone of its main, so require_reviewed_checkout runs against real git offline.
make_reviewed_clone() {
  local root="${1}"
  git init --quiet --bare --initial-branch=main "${root}/origin.git"
  git clone --quiet "${root}/origin.git" "${root}/work" 2>/dev/null
  git -C "${root}/work" checkout --quiet -b main
  printf 'reviewed\n' >"${root}/work/file"
  git -C "${root}/work" add file
  git -C "${root}/work" -c user.name=test -c user.email=test@example.invalid commit --quiet -m reviewed
  git -C "${root}/work" push --quiet origin main
}

local_commit() {
  local repo="${1}"
  printf 'local\n' >>"${repo}/file"
  git -C "${repo}" -c user.name=test -c user.email=test@example.invalid commit --quiet -am local
}

remote_moves_ahead() {
  local root="${1}"
  git clone --quiet "${root}/origin.git" "${root}/other" 2>/dev/null
  printf 'merged\n' >>"${root}/other/file"
  git -C "${root}/other" -c user.name=test -c user.email=test@example.invalid commit --quiet -am merged
  git -C "${root}/other" push --quiet origin main
}

test_require_reviewed_checkout() {
  local root
  root="$(mktemp -d)"
  make_reviewed_clone "${root}"
  assert_succeeds "a clean checkout of origin/main is reviewed" require_reviewed_checkout "${root}/work"
  printf 'x\n' >"${root}/work/untracked"
  assert_fails "an untracked file is refused" require_reviewed_checkout "${root}/work"
  rm -f "${root}/work/untracked"
  printf 'edit\n' >>"${root}/work/file"
  assert_fails "an uncommitted change is refused" require_reviewed_checkout "${root}/work"
  git -C "${root}/work" checkout --quiet -- file
  local_commit "${root}/work"
  assert_fails "a local commit not on origin/main is refused" require_reviewed_checkout "${root}/work"
  git -C "${root}/work" reset --quiet --hard origin/main
  remote_moves_ahead "${root}"
  # The stale remote-tracking ref still equals HEAD; only the fetch inside the check reveals the newer main.
  assert_fails "a checkout behind the freshly fetched main is refused" require_reviewed_checkout "${root}/work"
  rm -rf "${root}"
}

test_kid_matches_rfc8037
test_private_jwk_from_pkcs8
test_public_jwk_has_no_private_member
test_rejects_malformed_pkcs8
test_base64url_has_no_padding_or_unsafe_characters
test_deployment_config_path_rejects_unsafe_names
test_config_string_fails_closed
test_is_waf_block_tells_the_edge_from_the_worker
test_is_https_redirect_requires_the_rule_shape
test_zone_singletons_owner_is_idp_or_external
test_require_reviewed_checkout

if [[ "${failures}" -ne 0 ]]; then
  printf '%s test(s) failed\n' "${failures}" >&2
  exit 1
fi
printf 'all tests passed\n'
