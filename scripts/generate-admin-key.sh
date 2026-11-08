#!/usr/bin/env bash
# Generates an admin's mTLS private key (ECDSA P-384) and CSR (bootstrap stage 4).
#
# This script handles a secret, so it runs with `set -euo pipefail` and WITHOUT -x: xtrace prints every command
# after expansion, which would put the private key into the terminal, CI logs, and any AI context
# (docs/design/deployment.md "シェルスクリプトの規則"). Do not add -x, and do not make it print the key.
#
# The private key exists only in a shell variable and pipes and goes straight into 1Password. The CSR and the
# public key are not secrets: the CSR is written into the deployment file, where Terraform issues the client
# certificate from it, and both are printed.
set -euo pipefail

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  printf '%s\n' \
    "Usage: scripts/generate-admin-key.sh [--replace] <deployment> <admin-name>" \
    "" \
    "Generates an ECDSA P-384 private key (docs/design/idpctl.md) and stores it in the 1Password item" \
    "<onepassword_admin_key_item_prefix><admin-name>. Writes the CSR to admin_client_certificates in" \
    "deployments/<deployment>.tfvars.json and prints the CSR and the public key on stdout." \
    "The admin name follows the ADMIN_ALLOWLIST rule: lowercase letters, digits, and hyphens, 1 to 64 characters." \
    "" \
    "  --replace  Archive an existing item first. Without it, an existing item stops the script." \
    "  -h, --help Show this help."
}

# Replaces admin_client_certificates[<name>] in the deployment file. The file is rewritten through a temporary
# file in the same directory so that a failure never leaves it half written.
write_csr_to_config() {
  local config="${1}"
  local name="${2}"
  local csr="${3}"
  local temporary
  temporary="$(mktemp "${config}.XXXXXX")"
  if jq --indent 2 --arg name "${name}" --arg csr "${csr}" \
    '.admin_client_certificates = ((.admin_client_certificates // {}) + {($name): $csr})' \
    "${config}" >"${temporary}"; then
    mv "${temporary}" "${config}"
  else
    rm -f "${temporary}"
    fail "cannot update admin_client_certificates in ${config}"
  fi
}

main() {
  local replace="false"
  local positional=()
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
        positional+=("${1}")
        ;;
    esac
    shift
  done
  [[ "${#positional[@]}" -eq 2 ]] || {
    usage >&2
    return 2
  }
  local deployment="${positional[0]}"
  local admin="${positional[1]}"
  [[ "${admin}" =~ ${ADMIN_NAME_PATTERN} ]] || fail "invalid admin name: ${admin}"

  require_command jq op openssl
  local config
  local vault
  local prefix
  config="$(deployment_config_path "${deployment}")"
  vault="$(config_string "${config}" onepassword_vault)"
  prefix="$(config_string "${config}" onepassword_admin_key_item_prefix)"
  local item="${prefix}${admin}"
  require_op_session

  if op_item_exists "${vault}" "${item}"; then
    [[ "${replace}" == "true" ]] || fail "1Password item ${item} already exists; pass --replace to archive it and generate a new key"
    note "archiving the existing 1Password item ${item}"
    op_archive_item "${vault}" "${item}"
  fi

  local key_pem
  local csr
  local public_pem
  key_pem="$(openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -pkeyopt ec_param_enc:named_curve)"
  # openssl reads the key from /dev/stdin, so it is never a file on disk or a process argument.
  # The subject is informational only: the admin Worker authorises by fingerprint, never by subject
  # (docs/design/idpctl.md "証明書の主体名で認可しない").
  csr="$(printf '%s\n' "${key_pem}" | openssl req -new -key /dev/stdin -subj "/CN=${admin}" -sha384)"
  public_pem="$(printf '%s\n' "${key_pem}" | openssl pkey -pubout)"
  # A single-line identifier of the key pair, used to confirm that op stored this template.
  local public_key_sha256
  public_key_sha256="$(printf '%s\n' "${public_pem}" | openssl pkey -pubin -outform DER | openssl dgst -sha256 -r | cut -d ' ' -f 1)"

  printf '%s\n' "${key_pem}" | jq -Rsc --arg title "${item}" --arg csr "${csr}" --arg public "${public_pem}" \
    --arg public_sha256 "${public_key_sha256}" '{
    title: $title,
    category: "SECURE_NOTE",
    fields: [
      {id: "private_key", label: "private_key", type: "CONCEALED", value: .},
      {id: "csr", label: "csr", type: "STRING", value: $csr},
      {id: "public_key", label: "public_key", type: "STRING", value: $public},
      {id: "public_key_sha256", label: "public_key_sha256", type: "STRING", value: $public_sha256}
    ]
  }' | op_create_item_from_stdin "${vault}"
  key_pem=""

  op_verify_field "${vault}" "${item}" public_key_sha256 "${public_key_sha256}"
  write_csr_to_config "${config}" "${admin}" "${csr}"$'\n'
  note "stored the private key in the 1Password item ${item} and the CSR in ${config}"
  note "next: open a PR with the deployment file, then apply Terraform to issue the client certificate"
  printf '%s\n%s\n' "${csr}" "${public_pem}"
}

main "$@"
