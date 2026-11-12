#!/usr/bin/env bash
# Sets the two Worker Secrets of the sample relying party (examples/rp-sample): CLIENT_SECRET, the confidential
# client's secret that `idpctl client_create --secret-out <file>` wrote, and SESSION_KEY, a fresh 32-byte key for its
# cookies. Operator-run, after the first scripts/deploy-rp-sample.sh, because a Secret belongs to an existing Worker.
#
# This script handles secrets, so it runs with `set -euo pipefail` and WITHOUT -x: xtrace prints every command after
# expansion, which would put the client secret into the terminal, logs, and any AI context (as
# scripts/upload-signing-key.sh). Do not add -x, and do not make it print a secret.
#
# The client secret is read from a 0600 file or from stdin, never from an argument (a process list shows arguments),
# and flows to cf through a shell variable and a pipe only: cf reads the request body from /dev/stdin. The session key
# is generated inside the pipe with openssl rand and is never held in a variable or written anywhere else.
set -euo pipefail

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  printf '%s\n' \
    "Usage: scripts/set-rp-sample-secrets.sh <deployment> <client-secret-file | ->" \
    "" \
    "Sets ${RP_SAMPLE_CLIENT_SECRET_NAME} and ${RP_SAMPLE_SESSION_KEY_NAME} on the Worker ${RP_SAMPLE_WORKER_NAME} in the" \
    "account of deployments/<deployment>.tfvars.json (workers_dev mode only), which creates a new version of it." \
    "" \
    "<client-secret-file> is the file idpctl client_create --secret-out wrote: a regular file, not a symbolic link," \
    "owned by you, with mode 0600 or 0400. With -, the client secret is read from stdin instead." \
    "${RP_SAMPLE_SESSION_KEY_NAME} is always a fresh random key, so running this again signs everyone out of the sample." \
    "Prints nothing secret." \
    "" \
    "  -h, --help Show this help."
}

# Prints the permission bits of a file in octal, with the GNU or the BSD (macOS) stat. GNU first: BSD stat refuses
# -c, while GNU stat accepts -f (file system status) and would print something else.
file_mode() {
  local path="${1}"
  stat -c '%a' "${path}" 2>/dev/null || stat -f '%Lp' "${path}"
}

# Stops unless the client secret file is safe to read: a regular file, not a link, owned by the operator, and not
# readable or writable by anyone else (idpctl creates it 0600).
check_secret_file() {
  local path="${1}"
  [[ -f "${path}" && ! -L "${path}" ]] || fail "not a regular file: ${path}"
  [[ -O "${path}" ]] || fail "the client secret file is not yours: ${path}"
  local mode
  mode="$(file_mode "${path}")" || fail "cannot read the mode of ${path}"
  [[ "${mode}" == "600" || "${mode}" == "400" ]] || fail "the client secret file must have mode 0600 or 0400, not ${mode}: ${path}"
}

# Reads a secret_text value on stdin and sets it as the named Secret of the sample's Worker. cf prints the API
# result, which names the Secret but not its value; it is dropped anyway so that a future cf that echoes the request
# cannot leak it.
put_secret() {
  local name="${1}"
  jq -Rsc --arg name "${name}" '{name: $name, type: "secret_text", text: .}' |
    cf_cli workers secrets update "${name}" --worker "${RP_SAMPLE_WORKER_NAME}" --type secret_text --body @/dev/stdin >/dev/null
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
  [[ "$#" -eq 2 ]] || {
    usage >&2
    return 2
  }
  local deployment="${1}"
  local source="${2}"

  require_command jq op openssl pnpm
  local config
  local vault
  local cloudflare_item
  config="$(deployment_config_path "${deployment}")"
  # Stops unless the deployment is in the workers_dev mode, the only one the sample runs in.
  rp_sample_host "${config}" >/dev/null
  vault="$(config_string "${config}" onepassword_vault)"
  cloudflare_item="$(config_string "${config}" onepassword_cloudflare_item)"
  [[ "${source}" == "-" ]] || check_secret_file "${source}"

  # Read before any change, so a bad secret stops the script with nothing set. $(...) drops the newline idpctl
  # writes after the value.
  local secret
  if [[ "${source}" == "-" ]]; then
    secret="$(cat)"
  else
    secret="$(cat -- "${source}")"
  fi
  # The IdP's client secrets are 32 random bytes as unpadded base64url (packages/core/src/shared/identifiers.ts). The
  # value is never echoed, not even in this error.
  [[ "${secret}" =~ ^[A-Za-z0-9_-]{43}$ ]] || fail "the client secret is not 43 base64url characters (an idpctl --secret-out file)"

  require_op_session
  IDP_ACCOUNT_ID="$(read_account_id "${vault}" "${cloudflare_item}")"
  verify_cf_account

  printf '%s' "${secret}" | put_secret "${RP_SAMPLE_CLIENT_SECRET_NAME}"
  secret=""
  # 32 bytes as standard base64, the form examples/rp-sample/src/sealed.ts imports.
  openssl rand -base64 32 | tr -d '\n' | put_secret "${RP_SAMPLE_SESSION_KEY_NAME}"

  note "set ${RP_SAMPLE_CLIENT_SECRET_NAME} and ${RP_SAMPLE_SESSION_KEY_NAME} on ${RP_SAMPLE_WORKER_NAME}"
}

main "$@"
