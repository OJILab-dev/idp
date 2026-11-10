# shellcheck shell=bash
# The constants below are used by the scripts that source this file, which shellcheck cannot see from here.
# shellcheck disable=SC2034
#
# Shared helpers for the deployment scripts (docs/deployment/runbook.md). Sourced, never executed: each script
# sets its own shell options, because the scripts that handle secrets must run without xtrace.
#
# Kept compatible with bash 3.2, the bash that macOS ships, since the operator runs these scripts locally.

# The Worker name and the Secret name are code, not deployment inputs: they are the same in every deployment
# (docs/design/deployment.md "デプロイごとの入力"). Keep them in sync with the IdP Worker's cloudflare.config.ts
# and its Secret binding.
readonly IDP_WORKER_NAME="idp"
# The admin Worker's name; in the workers_dev mode it is the admin host's first label, so it is code too. Keep it in
# sync with ADMIN_WORKER_NAME of packages/core/src/shared/hosting.ts (docs/design/hosting-modes.md 1.2 and 1.3).
readonly ADMIN_WORKER_NAME="idp-admin"
readonly SIGNING_KEY_SECRET_NAME="SIGNING_KEY_ED25519_CURRENT"

# Field labels of the Vault item named by onepassword_cloudflare_item. The operator creates this item by hand,
# because it holds credentials (docs/deployment/bootstrap.md, 前提).
readonly OP_FIELD_ACCOUNT_ID="account_id"
readonly OP_FIELD_TERRAFORM_API_TOKEN="terraform_api_token"
readonly OP_FIELD_R2_ACCESS_KEY_ID="r2_access_key_id"
readonly OP_FIELD_R2_SECRET_ACCESS_KEY="r2_secret_access_key"

IDP_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly IDP_REPO_ROOT

# Same rule as the admin names of ADMIN_SIGNING_KEYS (docs/design/idpctl.md).
readonly ADMIN_NAME_PATTERN='^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$'

# The DER of every P-384 SubjectPublicKeyInfo with an uncompressed point starts with these 24 bytes (the
# id-ecPublicKey and secp384r1 OIDs of RFC 5480 §2.1.1, the BIT STRING header, and the 0x04 point prefix of
# SEC 1 §2.3.3) and is 120 bytes long. The admin Worker reads public_key as exactly this form
# (docs/design/hosting-modes.md 3.7).
readonly P384_SPKI_DER_PREFIX_HEX="3076301006072a8648ce3d020106052b8104002203620004"
readonly P384_SPKI_DER_LENGTH=120

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

# Notes go to stderr so that stdout carries only the script's non-secret result.
note() {
  printf '%s\n' "$*" >&2
}

require_command() {
  local name
  for name in "$@"; do
    command -v "${name}" >/dev/null 2>&1 || fail "required command not found: ${name}"
  done
}

# Prints the path of deployments/<deployment>.tfvars.json, the single source of the deployment inputs.
deployment_config_path() {
  local deployment="${1}"
  [[ "${deployment}" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || fail "invalid deployment name: ${deployment}"
  local path="${IDP_REPO_ROOT}/deployments/${deployment}.tfvars.json"
  [[ -f "${path}" ]] || fail "deployment file not found: ${path}"
  reject_removed_inputs "${path}" || exit 1
  check_hosting_inputs "${path}" || exit 1
  printf '%s\n' "${path}"
}

# Stops if the deployment file still holds an input that was removed: admin_allowlist and admin_client_certificates
# went with mTLS (docs/design/hosting-modes.md 1.1 and plan step 7), and zone_singletons_owner went with ③. A stale
# key stops every script, whatever its value, so that no one reads a deployment as still using what it named
# (fail-closed against stale configs). Terraform's variables refuse the same keys. Every script reaches this through
# deployment_config_path.
reject_removed_inputs() {
  local path="${1}"
  local removed
  removed="$(jq -er '[keys[] | select(. == "admin_allowlist" or . == "admin_client_certificates" or . == "zone_singletons_owner")]
    | join(" ")' "${path}")" || fail "deployment file is not a JSON object: ${path}"
  [[ -z "${removed}" ]] ||
    fail "deployment file holds removed inputs (${removed}); delete them (admin_signing_keys replaces those removed with mTLS): ${path}"
}

# Prints the inputs among the given keys that the deployment file holds, whatever their value (null included).
present_inputs() {
  local path="${1}"
  shift
  # With --args every argument after the filter is a key, so the file comes in on stdin.
  jq -er --args '[keys[] as $key | select($ARGS.positional | index($key))] | join(" ")' "$@" <"${path}"
}

# Prints the hosting mode, the one input every other hosting input follows (docs/design/hosting-modes.md 1.1). It
# has no default, and only the exact strings are accepted.
hosting_mode() {
  local path="${1}"
  jq -er '.hosting_mode | select(. == "custom_domain" or . == "workers_dev")' "${path}" ||
    fail "deployment file lacks \"hosting_mode\" (custom_domain or workers_dev; there is no default): ${path}"
}

# Stops unless the hosting inputs follow the table of docs/design/hosting-modes.md 1.1 exactly: custom_domain requires
# zone, issuer_host, and admin_host and forbids workers_dev_subdomain; workers_dev is the reverse. A forbidden key
# stops the script even when its value is empty or null, because a value left over from the other mode would make a
# reviewer misread which mode the deployment runs in. Terraform's variables and both cloudflare.config.ts files check
# the same rules (hosting-modes.md 1.4). Every script reaches this through deployment_config_path.
#
# Each $(...) ends in `|| exit 1`: fail inside a command substitution exits only that subshell, and errexit does not
# apply where a caller tests the result (an if or a ||), so the failure must be passed on explicitly.
check_hosting_inputs() {
  local path="${1}"
  local mode
  local forbidden
  mode="$(hosting_mode "${path}")" || exit 1
  case "${mode}" in
    custom_domain)
      forbidden="$(present_inputs "${path}" workers_dev_subdomain)" || exit 1
      [[ -z "${forbidden}" ]] || fail "the custom_domain mode forbids ${forbidden}: ${path}"
      local key
      for key in zone issuer_host admin_host; do
        config_string "${path}" "${key}" >/dev/null || exit 1
      done
      # A custom domain under workers.dev would be the workers_dev mode's host under the other mode's name.
      jq -e '[.zone, .issuer_host, .admin_host] | all(. != "workers.dev" and (endswith(".workers.dev") | not))' "${path}" >/dev/null ||
        fail "the custom_domain mode forbids hosts under workers.dev: ${path}"
      ;;
    workers_dev)
      forbidden="$(present_inputs "${path}" zone issuer_host admin_host)" || exit 1
      [[ -z "${forbidden}" ]] ||
        fail "the workers_dev mode forbids ${forbidden}; the hosts are derived from workers_dev_subdomain: ${path}"
      # One DNS label, matched on the raw JSON string inside jq (see check_admin_signing_keys for why \A and \z).
      jq -e '.workers_dev_subdomain | type == "string" and test("\\A[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\z")' "${path}" >/dev/null ||
        fail "the workers_dev mode requires \"workers_dev_subdomain\", one DNS label of <subdomain>.workers.dev: ${path}"
      ;;
  esac
}

# Prints the issuer host: issuer_host in custom_domain, idp.<workers_dev_subdomain>.workers.dev in workers_dev. The
# workers_dev hosts are derived, never separate inputs (docs/design/hosting-modes.md 1.3).
deployment_issuer_host() {
  deployment_host "${1}" issuer_host "${IDP_WORKER_NAME}"
}

# Prints the admin host: admin_host in custom_domain, idp-admin.<workers_dev_subdomain>.workers.dev in workers_dev.
deployment_admin_host() {
  deployment_host "${1}" admin_host "${ADMIN_WORKER_NAME}"
}

# Prints the custom_domain input named by key, or <worker name>.<workers_dev_subdomain>.workers.dev.
deployment_host() {
  local path="${1}"
  local key="${2}"
  local worker="${3}"
  local mode
  local subdomain
  check_hosting_inputs "${path}" || exit 1
  mode="$(hosting_mode "${path}")" || exit 1
  if [[ "${mode}" == "custom_domain" ]]; then
    config_string "${path}" "${key}" || exit 1
  else
    subdomain="$(config_string "${path}" workers_dev_subdomain)" || exit 1
    printf '%s.%s.workers.dev\n' "${worker}" "${subdomain}"
  fi
}

# Prints the account's workers.dev subdomain label from the Cloudflare API ("Get a Workers Subdomain",
# GET /accounts/{account_id}/workers/subdomain); the pinned cf has no command for it. The token is the Terraform
# token of the Vault item, which needs account-level Workers Scripts Read in the workers_dev mode
# (docs/design/deployment.md, API トークン). op run resolves the op:// reference into curl's environment only, and curl
# reads it from there (--variable, curl 8.3 or later), so the token never appears in an argument, in xtrace, or in
# the output (op run also masks it). Talks to the network: only the operator's scripts call it, never a test or CI.
read_workers_dev_subdomain() {
  local vault="${1}"
  local item="${2}"
  local account_id="${3}"
  [[ "${account_id}" =~ ^[0-9a-f]{32}$ ]] || fail "not a Cloudflare account ID: ${account_id}"
  local response
  response="$(env "CLOUDFLARE_API_TOKEN=op://${vault}/${item}/${OP_FIELD_TERRAFORM_API_TOKEN}" op run -- \
    curl --fail --silent --show-error --proto '=https' --max-time 30 \
    --variable '%CLOUDFLARE_API_TOKEN' --expand-header 'Authorization: Bearer {{CLOUDFLARE_API_TOKEN}}' \
    "https://api.cloudflare.com/client/v4/accounts/${account_id}/workers/subdomain")" || return 1
  # Checked on the raw JSON string, so a value with a trailing newline cannot pass after $(...) strips it.
  printf '%s' "${response}" | jq -er 'select(.success == true) | .result.subdomain
    | select(type == "string" and test("\\A[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\z"))'
}

# Stops unless the account's workers.dev subdomain is the deployment's workers_dev_subdomain, before anything is
# changed (docs/design/hosting-modes.md 1.1 and 1.4). The issuer is derived from it, so a subdomain changed on the
# dashboard would otherwise deploy the IdP under another issuer unnoticed. It also stops an account that has no
# subdomain yet: the deploy must never create one on its own (the operator creates it on the dashboard).
verify_workers_dev_subdomain() {
  local config="${1}"
  local vault="${2}"
  local item="${3}"
  local account_id="${4}"
  local mode
  local expected
  local actual
  mode="$(hosting_mode "${config}")" || exit 1
  [[ "${mode}" == "workers_dev" ]] || fail "the workers.dev subdomain is checked only in the workers_dev mode"
  expected="$(config_string "${config}" workers_dev_subdomain)" || exit 1
  actual="$(read_workers_dev_subdomain "${vault}" "${item}" "${account_id}")" ||
    fail "cannot read the account's workers.dev subdomain; the account needs one, and the Terraform token needs Workers Scripts Read"
  [[ "${actual}" == "${expected}" ]] ||
    fail "the account's workers.dev subdomain is ${actual}, not workers_dev_subdomain ${expected}; nothing was changed"
}

# Prints a required string input. A missing or empty value stops the script: no input has a default
# (docs/design/deployment.md, fail-closed).
config_string() {
  local path="${1}"
  local key="${2}"
  local value
  value="$(jq -er --arg key "${key}" '.[$key] | select(type == "string" and length > 0)' "${path}")" ||
    fail "deployment file lacks a non-empty string \"${key}\": ${path}"
  printf '%s\n' "${value}"
}

require_op_session() {
  op whoami >/dev/null 2>&1 || fail "op is not signed in; the operator signs in to 1Password first"
}

# Prints the account ID from 1Password. It is not a secret, but it stays out of the repository because the
# repository is public (docs/design/deployment.md).
read_account_id() {
  local vault="${1}"
  local item="${2}"
  local account_id
  account_id="$(op read "op://${vault}/${item}/${OP_FIELD_ACCOUNT_ID}")" ||
    fail "cannot read ${OP_FIELD_ACCOUNT_ID} from the 1Password item ${item}"
  [[ "${account_id}" =~ ^[0-9a-f]{32}$ ]] || fail "${OP_FIELD_ACCOUNT_ID} of ${item} is not a Cloudflare account ID"
  printf '%s\n' "${account_id}"
}

# Runs the repository-pinned cf (never a global one, AGENT.md) against IDP_ACCOUNT_ID. The operator's
# `cf auth login` session can span several accounts, so every call names the account explicitly.
cf_cli() {
  CLOUDFLARE_ACCOUNT_ID="${IDP_ACCOUNT_ID:?IDP_ACCOUNT_ID is not set}" pnpm --dir "${IDP_REPO_ROOT}" exec cf "$@"
}

# Stops unless cf acts on the deployment's account. Called before any change.
verify_cf_account() {
  local actual
  actual="$(cf_cli accounts get | jq -er '(.result // .) | .id')" ||
    fail "cannot read the account through cf; the operator runs cf auth login first"
  [[ "${actual}" == "${IDP_ACCOUNT_ID}" ]] || fail "cf is not acting on the deployment's account"
}

# Prints how many D1 databases have exactly this name. `d1 list --name` is a search, so the match is exact here.
d1_database_count() {
  local name="${1}"
  cf_cli d1 list --name "${name}" | jq -er --arg name "${name}" '[(.result // .)[] | select(.name == $name)] | length'
}

# Prints the ID of the D1 database with this name. The ID is looked up every time and never written down
# (docs/design/deployment.md, 直書きの禁止).
d1_database_id() {
  local name="${1}"
  cf_cli d1 list --name "${name}" | jq -er --arg name "${name}" '
    [(.result // .)[] | select(.name == $name)]
    | if length == 1 then .[0].uuid else error("expected exactly one D1 database named \($name)") end'
}

# base64url without padding (RFC 4648 §5), reading bytes on stdin.
base64url() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

# Prints the RFC 7638 JWK thumbprint of an Ed25519 public key: SHA-256 over the required members crv, kty, x
# (RFC 8037 §2) in lexicographic order with no whitespace, then base64url (docs/design/cross-language-contract.md).
ed25519_kid() {
  local x="${1}"
  printf '{"crv":"Ed25519","kty":"OKP","x":"%s"}' "${x}" | openssl dgst -sha256 -binary | base64url
}

# Reads an Ed25519 private key as base64 PKCS#8 DER on stdin and prints the private JWK on stdout.
# The output is SECRET: the caller must pipe or capture it and never print it.
#
# The key is held as base64 text in shell variables and moved with printf, a builtin, so it never appears in a
# process argument list or on disk.
ed25519_private_jwk_from_pkcs8() {
  local der_b64
  der_b64="$(cat)"

  # RFC 8410 §7: an Ed25519 PKCS#8 key is this fixed 16-byte header followed by the 32-byte seed.
  local header
  header="$(printf '%s' "${der_b64}" | openssl base64 -d -A | head -c 16 | od -An -tx1 | tr -d ' \n')"
  [[ "${header}" == "302e020100300506032b657004220420" ]] || fail "unexpected Ed25519 PKCS#8 encoding"
  local length
  length="$(printf '%s' "${der_b64}" | openssl base64 -d -A | wc -c | tr -d ' ')"
  [[ "${length}" == "48" ]] || fail "unexpected Ed25519 PKCS#8 length"

  # RFC 8410 §4: the SubjectPublicKeyInfo is this fixed 12-byte header followed by the 32-byte public key.
  local public_header
  public_header="$(printf '%s' "${der_b64}" | openssl base64 -d -A | openssl pkey -inform DER -pubout -outform DER |
    head -c 12 | od -An -tx1 | tr -d ' \n')"
  [[ "${public_header}" == "302a300506032b6570032100" ]] || fail "unexpected Ed25519 public key encoding"

  local d
  local x
  local kid
  d="$(printf '%s' "${der_b64}" | openssl base64 -d -A | tail -c 32 | base64url)"
  x="$(printf '%s' "${der_b64}" | openssl base64 -d -A | openssl pkey -inform DER -pubout -outform DER | tail -c 32 | base64url)"
  kid="$(ed25519_kid "${x}")"
  # Every value is base64url, so no JSON escaping is needed; printf keeps d out of any argument list.
  printf '{"kty":"OKP","crv":"Ed25519","x":"%s","d":"%s","kid":"%s","alg":"Ed25519","use":"sig"}' "${x}" "${d}" "${kid}"
}

# Prints the public members of a private JWK read on stdin, exactly the members the JWKS carries.
public_jwk() {
  jq -c '{kty, crv, x, kid, alg, use}'
}

# Reads a PEM public key on stdin and prints its SPKI DER as padded base64 on one line, the public_key form of
# admin_signing_keys. Only a public key is accepted: -pubin makes openssl refuse a private key.
spki_base64_from_public_pem() {
  openssl pkey -pubin -outform DER | openssl base64 -A
}

# Prints the keyid of a P-384 public key given as padded one-line base64 SPKI DER: the SHA-256 of the DER in
# lowercase hex (docs/design/hosting-modes.md 3.7). Returns non-zero unless the value is exactly the form the
# admin Worker accepts: canonical base64, the P-384 SPKI prefix and length, and a point openssl can load (on the
# curve). The base64 and the DER must round-trip unchanged, so the keyid covers exactly what is written.
p384_spki_keyid() {
  local spki="${1}"
  [[ "${spki}" =~ ^[A-Za-z0-9+/]+={0,2}$ && $((${#spki} % 4)) -eq 0 ]] || return 1
  local der_hex
  der_hex="$(printf '%s' "${spki}" | openssl base64 -d -A | od -An -tx1 | tr -d ' \n')" || return 1
  [[ "${#der_hex}" -eq $((P384_SPKI_DER_LENGTH * 2)) && "${der_hex}" == "${P384_SPKI_DER_PREFIX_HEX}"* ]] || return 1
  local reencoded
  reencoded="$(printf '%s' "${spki}" | openssl base64 -d -A | openssl pkey -pubin -inform DER -outform DER 2>/dev/null |
    openssl base64 -A)" || return 1
  [[ "${reencoded}" == "${spki}" ]] || return 1
  printf '%s' "${spki}" | openssl base64 -d -A | openssl dgst -sha256 -r | cut -d ' ' -f 1
}

# Prints one admin_signing_keys row, {keyid, name, public_key}, for a P-384 public key given as base64 SPKI DER.
admin_signing_key_row() {
  local name="${1}"
  local spki="${2}"
  [[ "${name}" =~ ${ADMIN_NAME_PATTERN} ]] || fail "invalid admin name: ${name}"
  local keyid
  keyid="$(p384_spki_keyid "${spki}")" || fail "the public key of ${name} is not an ECDSA P-384 key"
  jq -nc --arg keyid "${keyid}" --arg name "${name}" --arg public_key "${spki}" \
    '{keyid: $keyid, name: $name, public_key: $public_key}'
}

# Stops unless admin_signing_keys of the deployment file is a list the admin Worker accepts row by row: exactly the
# members keyid, name, and public_key, all strings; a lowercase 64-hex keyid equal to the SHA-256 of a P-384
# public_key; a valid admin name; and no repeated keyid (docs/design/hosting-modes.md 3.7). An empty list stops it
# too, because the admin Worker reads the list and refuses every request while it is empty (hosting-modes.md 1.1 and
# 1.4). Only the generation script passes "allow-empty", to add the first row to a new deployment's list
# (docs/deployment/runbook.md, stage 0 and 4a); what it writes is then checked again without it.
check_admin_signing_keys() {
  local config="${1}"
  local empty="${2-}"
  [[ -z "${empty}" || "${empty}" == "allow-empty" ]] || fail "unknown admin_signing_keys check mode: ${empty}"
  jq -e '.admin_signing_keys | type == "array"' "${config}" >/dev/null 2>&1 ||
    fail "deployment file lacks the list \"admin_signing_keys\": ${config}"
  if [[ "${empty}" != "allow-empty" ]]; then
    jq -e '.admin_signing_keys | length > 0' "${config}" >/dev/null ||
      fail "admin_signing_keys is empty; add a row with scripts/generate-admin-key.sh before deploying: ${config}"
  fi
  jq -e '.admin_signing_keys | all(type == "object" and keys == ["keyid", "name", "public_key"] and all(.[]; type == "string"))' \
    "${config}" >/dev/null || fail "every admin_signing_keys row must have exactly the strings keyid, name, and public_key: ${config}"
  # The forms are checked on the raw JSON strings inside jq, not after $(...): command substitution strips trailing
  # newlines, so "<keyid>\n" would otherwise pass the shell checks while the admin Worker reads a different value.
  # After these checks no value can hold a newline, so reading them through $(...) below is exact. The patterns
  # are anchored with \A and \z: in jq's regex library (Oniguruma), $ also matches before a final newline.
  jq -e --arg name_pattern "${ADMIN_NAME_PATTERN}" '
    def whole($p): "\\A" + ($p | ltrimstr("^") | rtrimstr("$")) + "\\z";
    .admin_signing_keys | all(
      (.keyid | test(whole("^[0-9a-f]{64}$")))
      and (.name | test(whole($name_pattern)))
      and (.public_key | test(whole("^[A-Za-z0-9+/]+={0,2}$"))))' "${config}" >/dev/null ||
    fail "every admin_signing_keys row must have a 64 lowercase hex keyid, an admin name, and a one-line base64 public_key: ${config}"
  jq -e '.admin_signing_keys | (map(.keyid) | unique | length) == length' "${config}" >/dev/null ||
    fail "admin_signing_keys repeats a keyid: ${config}"
  local rows
  local count
  local index=0
  rows="$(jq -c '.admin_signing_keys' "${config}")"
  count="$(printf '%s' "${rows}" | jq 'length')"
  while [[ "${index}" -lt "${count}" ]]; do
    local keyid
    local name
    local public_key
    keyid="$(printf '%s' "${rows}" | jq -r --argjson i "${index}" '.[$i].keyid')"
    name="$(printf '%s' "${rows}" | jq -r --argjson i "${index}" '.[$i].name')"
    public_key="$(printf '%s' "${rows}" | jq -r --argjson i "${index}" '.[$i].public_key')"
    [[ "${name}" =~ ${ADMIN_NAME_PATTERN} ]] || fail "admin_signing_keys row ${index} has an invalid name: ${config}"
    [[ "${keyid}" =~ ^[0-9a-f]{64}$ ]] || fail "admin_signing_keys row ${index} has a keyid that is not 64 lowercase hex: ${config}"
    local actual
    actual="$(p384_spki_keyid "${public_key}")" ||
      fail "admin_signing_keys row ${index} has a public_key that is not a base64 P-384 SPKI: ${config}"
    [[ "${actual}" == "${keyid}" ]] || fail "admin_signing_keys row ${index} has a keyid that is not the SHA-256 of its public_key: ${config}"
    index=$((index + 1))
  done
}

# Adds a row to admin_signing_keys of the deployment file. A row with the same keyid and name is kept as it is, so
# a second run changes nothing; the same keyid under another name stops the script. With replace=true, the admin's
# other rows are removed, so a replaced key stops working after the next deploy. Other admins' rows and the other
# inputs are kept. The result is checked before it replaces the file, through a temporary file in the same
# directory, so that a failure never leaves the file half written or invalid.
write_admin_signing_key_row() {
  local config="${1}"
  local row="${2}"
  local replace="${3}"
  local temporary
  temporary="$(mktemp "${config}.XXXXXX")"
  if jq --indent 2 --argjson row "${row}" --arg replace "${replace}" '
    if any(.admin_signing_keys[]; .keyid == $row.keyid and .name != $row.name)
    then error("the keyid already belongs to another admin") else . end
    | .admin_signing_keys |= (
        map(select($replace != "true" or .name != $row.name or .keyid == $row.keyid))
        | if any(.[]; .keyid == $row.keyid) then . else . + [$row] end)' \
    "${config}" >"${temporary}" && (check_admin_signing_keys "${temporary}"); then
    mv "${temporary}" "${config}"
  else
    rm -f "${temporary}"
    fail "cannot update admin_signing_keys in ${config}"
  fi
}

op_item_exists() {
  local vault="${1}"
  local title="${2}"
  # The item JSON can include concealed values, so it is discarded.
  op item get "${title}" --vault "${vault}" --format json >/dev/null 2>&1
}

# Archives (not deletes) an existing item so that a replaced key can still be recovered from 1Password.
op_archive_item() {
  local vault="${1}"
  local title="${2}"
  op item delete "${title}" --vault "${vault}" --archive >/dev/null
}

# Reads a 1Password item template (JSON) on stdin and creates the item. The template goes through stdin, not
# arguments, because it carries the secret; op echoes the created item, concealed fields included, so its
# output is discarded.
op_create_item_from_stdin() {
  local vault="${1}"
  op item create --vault "${vault}" --format json >/dev/null
}

# Stops unless a non-secret field of the item has the expected value. Confirms that op stored the template.
op_verify_field() {
  local vault="${1}"
  local title="${2}"
  local field="${3}"
  local expected="${4}"
  local actual
  actual="$(op read "op://${vault}/${title}/${field}")" || fail "cannot read ${field} back from ${title}"
  [[ "${actual}" == "${expected}" ]] || fail "1Password item ${title} does not hold the expected ${field}"
}
