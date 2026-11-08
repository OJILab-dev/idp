#!/usr/bin/env bash
# Generates the Ed25519 token signing key and stores it only in 1Password (bootstrap stage 3).
#
# This script handles a secret, so it runs with `set -euo pipefail` and WITHOUT -x: xtrace prints every command
# after expansion, which would put the private key into the terminal, CI logs, and any AI context
# (docs/design/deployment.md "シェルスクリプトの規則"). Do not add -x, and do not make it print the key.
#
# The private JWK exists only in shell variables and pipes; it is never written to disk or passed as a process
# argument. Only the kid and the public JWK are printed.
set -euo pipefail

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  printf '%s\n' \
    "Usage: scripts/generate-signing-key.sh [--replace] <deployment>" \
    "" \
    "Generates an Ed25519 signing key (docs/design/cross-language-contract.md) and stores the private JWK in the" \
    "1Password item onepassword_signing_key_item of deployments/<deployment>.tfvars.json. Prints the public JWK" \
    "on stdout. It does not touch the Worker Secret; scripts/upload-signing-key.sh does that after the first deploy." \
    "" \
    "  --replace  Archive an existing item first. Without it, an existing item stops the script." \
    "  -h, --help Show this help."
}

main() {
  local replace="false"
  local deployment=""
  while [[ "$#" -gt 0 ]]; do
    case "${1}" in
      -h | --help)
        usage
        return 0
        ;;
      --replace)
        replace="true"
        ;;
      -*)
        usage >&2
        return 2
        ;;
      *)
        [[ -z "${deployment}" ]] || {
          usage >&2
          return 2
        }
        deployment="${1}"
        ;;
    esac
    shift
  done
  [[ -n "${deployment}" ]] || {
    usage >&2
    return 2
  }

  require_command jq op openssl
  local config
  local vault
  local item
  config="$(deployment_config_path "${deployment}")"
  vault="$(config_string "${config}" onepassword_vault)"
  item="$(config_string "${config}" onepassword_signing_key_item)"
  require_op_session

  if op_item_exists "${vault}" "${item}"; then
    [[ "${replace}" == "true" ]] || fail "1Password item ${item} already exists; pass --replace to archive it and generate a new key"
    note "archiving the existing 1Password item ${item}"
    op_archive_item "${vault}" "${item}"
  fi

  local jwk
  local kid
  local public
  jwk="$(openssl genpkey -algorithm ed25519 -outform DER | openssl base64 -A | ed25519_private_jwk_from_pkcs8)"
  kid="$(printf '%s' "${jwk}" | jq -er .kid)"
  public="$(printf '%s' "${jwk}" | public_jwk)"

  # The template is built from stdin so the JWK stays out of jq's arguments.
  printf '%s' "${jwk}" | jq -Rsc --arg title "${item}" --arg kid "${kid}" --arg public "${public}" '{
    title: $title,
    category: "SECURE_NOTE",
    fields: [
      {id: "jwk", label: "jwk", type: "CONCEALED", value: .},
      {id: "kid", label: "kid", type: "STRING", value: $kid},
      {id: "public_jwk", label: "public_jwk", type: "STRING", value: $public}
    ]
  }' | op_create_item_from_stdin "${vault}"
  jwk=""

  op_verify_field "${vault}" "${item}" kid "${kid}"
  note "stored the signing key in the 1Password item ${item} (kid ${kid})"
  printf '%s\n' "${public}"
}

main "$@"
