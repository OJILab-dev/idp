#!/usr/bin/env bash
# Registers the Ed25519 signing key from 1Password as the IdP Worker's Secret (bootstrap stage 5b).
#
# This script handles a secret, so it runs with `set -euo pipefail` and WITHOUT -x: xtrace prints every command
# after expansion, which would put the private key into the terminal, CI logs, and any AI context
# (docs/design/deployment.md "シェルスクリプトの規則"). Do not add -x, and do not make it print the key.
#
# The private JWK flows from `op read` to cf through shell variables and pipes only: cf reads the request body
# from /dev/stdin, so the key is never on disk or in a process argument list. Only the kid is printed.
set -euo pipefail

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  printf '%s\n' \
    "Usage: scripts/upload-signing-key.sh <deployment>" \
    "" \
    "Reads the private JWK from the 1Password item onepassword_signing_key_item and sets it as the Worker Secret" \
    "${SIGNING_KEY_SECRET_NAME} of the Worker ${IDP_WORKER_NAME}, which creates a new version of that Worker." \
    "Run it after the first CI deploy, because a Secret belongs to an existing Worker. Prints the kid." \
    "" \
    "  -h, --help Show this help."
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
  [[ "$#" -eq 1 ]] || {
    usage >&2
    return 2
  }
  local deployment="${1}"

  require_command jq op openssl pnpm
  local config
  local vault
  local item
  local cloudflare_item
  config="$(deployment_config_path "${deployment}")"
  vault="$(config_string "${config}" onepassword_vault)"
  item="$(config_string "${config}" onepassword_signing_key_item)"
  cloudflare_item="$(config_string "${config}" onepassword_cloudflare_item)"
  require_op_session

  IDP_ACCOUNT_ID="$(read_account_id "${vault}" "${cloudflare_item}")"
  verify_cf_account

  local jwk
  jwk="$(op read "op://${vault}/${item}/jwk")" || fail "cannot read jwk from the 1Password item ${item}"

  # Check the shape before upload so that a wrong item fails here, not as a Worker that refuses every request.
  # jq prints nothing (-e only sets the exit status), and its error output is dropped because it can quote input.
  printf '%s' "${jwk}" | jq -e '
    type == "object"
    and .kty == "OKP" and .crv == "Ed25519" and .alg == "Ed25519" and .use == "sig"
    and (.x | type == "string") and (.d | type == "string") and (.kid | type == "string")' >/dev/null 2>&1 ||
    fail "1Password item ${item} does not hold an Ed25519 private JWK"
  local x
  local kid
  x="$(printf '%s' "${jwk}" | jq -r .x)"
  kid="$(printf '%s' "${jwk}" | jq -r .kid)"
  [[ "$(ed25519_kid "${x}")" == "${kid}" ]] || fail "the kid in ${item} is not the RFC 7638 thumbprint of its key"

  # cf prints the API result, which names the Secret but not its value; it is dropped anyway so that a future
  # cf that echoes the request cannot leak the key.
  printf '%s' "${jwk}" | jq -Rsc --arg name "${SIGNING_KEY_SECRET_NAME}" '{name: $name, type: "secret_text", text: .}' |
    cf_cli workers secrets update "${SIGNING_KEY_SECRET_NAME}" --worker "${IDP_WORKER_NAME}" --type secret_text --body @/dev/stdin >/dev/null
  jwk=""

  note "set ${SIGNING_KEY_SECRET_NAME} on ${IDP_WORKER_NAME}; JWKS should now list this kid"
  printf '%s\n' "${kid}"
}

main "$@"
