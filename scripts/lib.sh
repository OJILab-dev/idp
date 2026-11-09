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
readonly SIGNING_KEY_SECRET_NAME="SIGNING_KEY_ED25519_CURRENT"
# Keep in sync with the admin Worker's cloudflare.config.ts.
readonly ADMIN_WORKER_NAME="idp-admin"

# Field labels of the Vault item named by onepassword_cloudflare_item. The operator creates this item by hand,
# because it holds credentials (docs/deployment/bootstrap.md, 前提).
readonly OP_FIELD_ACCOUNT_ID="account_id"
readonly OP_FIELD_TERRAFORM_API_TOKEN="terraform_api_token"
readonly OP_FIELD_R2_ACCESS_KEY_ID="r2_access_key_id"
readonly OP_FIELD_R2_SECRET_ACCESS_KEY="r2_secret_access_key"

IDP_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly IDP_REPO_ROOT

# Same rule as the admin names of ADMIN_ALLOWLIST (docs/design/idpctl.md).
readonly ADMIN_NAME_PATTERN='^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$'

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
  printf '%s\n' "${path}"
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

# Like cf_cli, but runs cf in a Worker's project directory (apps/<name>), where cf build and cf deploy look for
# cloudflare.config.ts, vite.config.ts, and the Build Output.
cf_cli_in() {
  local project="${1}"
  shift
  CLOUDFLARE_ACCOUNT_ID="${IDP_ACCOUNT_ID:?IDP_ACCOUNT_ID is not set}" pnpm --dir "${IDP_REPO_ROOT}/${project}" exec cf "$@"
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

# Succeeds when a response to the admin host was blocked at the edge rather than by the admin Worker. Both answer
# 403, but the Worker's refusals are all application/problem+json (docs/design/idpctl.md), and the WAF block page is
# not. A request the Worker refused has already used the account's daily request limit, so it is a failure here.
is_waf_block() {
  local status="${1}"
  local content_type="${2}"
  [[ "${status}" == "403" ]] && [[ "${content_type}" != application/problem+json* ]]
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
