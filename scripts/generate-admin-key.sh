#!/usr/bin/env bash
# Generates an admin's private key (ECDSA P-384) and writes its admin_signing_keys row (bootstrap stage 4), or
# writes the row for a key that a 1Password item already holds.
#
# This script handles a secret, so it runs with `set -euo pipefail` and WITHOUT -x: xtrace prints every command
# after expansion, which would put the private key into the terminal, CI logs, and any AI context
# (docs/design/deployment.md "シェルスクリプトの規則"). Do not add -x, and do not make it print the key.
#
# The private key exists only in a shell variable and pipes and goes straight into 1Password. The row (keyid,
# name, public_key) is not a secret: it is written into the deployment file, which the admin Worker reads as
# ADMIN_SIGNING_KEYS (docs/design/hosting-modes.md 3.7 and 3.10). Until mTLS is removed (step 7 of the
# implementation order there), the admin Worker still checks client certificates, so a generated key also gets a
# CSR in admin_client_certificates; without it, a new admin could not use the API before the switch to signatures.
#
# --from-existing reads only the non-secret fields public_key and public_key_sha256 of an existing item, with
# `op read` of each field. It never reads the private_key field and never runs `op item get`, whose JSON would
# carry the concealed private key into this process.
set -euo pipefail

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  printf '%s\n' \
    "Usage: scripts/generate-admin-key.sh [--replace | --from-existing] <deployment> <admin-name>" \
    "" \
    "Generates an ECDSA P-384 private key (docs/design/idpctl.md) and stores it in the 1Password item" \
    "<onepassword_admin_key_item_prefix><admin-name>. Adds the row {keyid, name, public_key} to admin_signing_keys" \
    "and the CSR to admin_client_certificates in deployments/<deployment>.tfvars.json, and prints the CSR and the" \
    "row on stdout. keyid is the SHA-256 of the public key's SPKI DER, the item's public_key_sha256." \
    "The admin name follows the ADMIN_ALLOWLIST rule: lowercase letters, digits, and hyphens, 1 to 64 characters." \
    "" \
    "  --replace        Archive an existing item first and remove the admin's other admin_signing_keys rows." \
    "                   Without it, an existing item stops the script." \
    "  --from-existing  Generate nothing: read only public_key and public_key_sha256 of the existing item," \
    "                   add its admin_signing_keys row, and print the row. The private key is never read." \
    "  -h, --help       Show this help."
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

# Writes the row of the key already in the item. The keyid computed from public_key must equal the item's
# public_key_sha256, the value the generation stored and verified, so a field edited by hand stops the script.
write_row_from_existing_item() {
  local config="${1}"
  local vault="${2}"
  local item="${3}"
  local admin="${4}"
  local public_pem
  local recorded_sha256
  public_pem="$(op read "op://${vault}/${item}/public_key")" || fail "cannot read public_key from the 1Password item ${item}"
  recorded_sha256="$(op read "op://${vault}/${item}/public_key_sha256")" ||
    fail "cannot read public_key_sha256 from the 1Password item ${item}"
  local spki
  spki="$(printf '%s\n' "${public_pem}" | spki_base64_from_public_pem 2>/dev/null)" ||
    fail "public_key of the 1Password item ${item} is not a PEM public key"
  local row
  row="$(admin_signing_key_row "${admin}" "${spki}")"
  [[ "$(printf '%s' "${row}" | jq -r .keyid)" == "${recorded_sha256}" ]] ||
    fail "public_key of the 1Password item ${item} does not match its public_key_sha256"
  write_admin_signing_key_row "${config}" "${row}" false
  note "added the admin_signing_keys row of the existing 1Password item ${item} to ${config}"
  note "next: open a PR with the deployment file; check that keyid equals public_key_sha256 of ${item}"
  printf '%s\n' "${row}"
}

generate_key() {
  local config="${1}"
  local vault="${2}"
  local item="${3}"
  local admin="${4}"
  local replace="${5}"
  if op_item_exists "${vault}" "${item}"; then
    [[ "${replace}" == "true" ]] || fail "1Password item ${item} already exists; pass --replace to archive it and generate a new key, or --from-existing to use its key"
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
  # The row is built before the item is created, so a key the admin Worker would refuse never reaches 1Password.
  local row
  local public_key_sha256
  row="$(admin_signing_key_row "${admin}" "$(printf '%s\n' "${public_pem}" | spki_base64_from_public_pem)")"
  # The keyid, a single-line identifier of the key pair, also confirms that op stored this template.
  public_key_sha256="$(printf '%s' "${row}" | jq -r .keyid)"

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
  write_admin_signing_key_row "${config}" "${row}" "${replace}"
  write_csr_to_config "${config}" "${admin}" "${csr}"$'\n'
  note "stored the private key in the 1Password item ${item}, and the admin_signing_keys row and the CSR in ${config}"
  note "next: open a PR with the deployment file, then apply Terraform to issue the client certificate"
  printf '%s\n%s\n' "${csr}" "${row}"
}

main() {
  local replace="false"
  local from_existing="false"
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
      --from-existing)
        from_existing="true"
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
  # --replace archives the item that --from-existing reads, so the two together have no meaning.
  [[ "${#positional[@]}" -eq 2 && ! ("${replace}" == "true" && "${from_existing}" == "true") ]] || {
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
  # Checked before 1Password is touched: an invalid list must not leave a new item without its row.
  check_admin_signing_keys "${config}"
  require_op_session

  if [[ "${from_existing}" == "true" ]]; then
    write_row_from_existing_item "${config}" "${vault}" "${item}" "${admin}"
  else
    generate_key "${config}" "${vault}" "${item}" "${admin}" "${replace}"
  fi
}

main "$@"
