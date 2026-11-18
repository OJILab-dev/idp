#!/bin/sh

set -eu

mode=apply
github_org=${IDP_GITHUB_ORG:-OJILab-dev}
op_account=${OP_ACCOUNT:-ojilab.1password.com}
integration_key_ref=${OP_INTEGRATION_KEY_REF:-op://github-organization/OP_INTEGRATION_KEY/password}

usage() {
  printf '%s\n' "Usage: OP_WORKLOAD_ID=<id> OP_ENVIRONMENT_ID=<id> ./setup-1password-integration.sh [--check]" \
    "" \
    "環境変数（未設定または空の場合は既定値を使います）:" \
    "  IDP_GITHUB_ORG          対象の GitHub Organization（既定値: OJILab-dev）" \
    "  OP_ACCOUNT              Integration Key を読む 1Password アカウント（既定値: ojilab.1password.com）" \
    "  OP_INTEGRATION_KEY_REF  Integration Key の secret reference（既定値: op://github-organization/OP_INTEGRATION_KEY/password）" \
    "--check は 1Password を読まず、GitHub 側の設定だけを確認します。"
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

note() {
  printf '%s\n' "$*"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

case "${1-}" in
  "")
    ;;
  --check)
    mode=check
    ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

require_command gh
require_command jq

script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd)
cd "$script_dir"

gh auth status -h github.com >/dev/null 2>&1 || fail "gh is not authenticated to github.com"

repository=$(gh repo view --json nameWithOwner --jq .nameWithOwner)
case "$repository" in
  OJILab-dev/template-cf-stack)
    fail "run this script in a repository generated from the template"
    ;;
  "$github_org"/*)
    ;;
  *)
    fail "repository must belong to $github_org: $repository"
    ;;
esac

read_variable() {
  variable_name=$1
  gh variable list --repo "$repository" --json name,value \
    --jq ".[] | select(.name == \"$variable_name\") | .value"
}

has_secret() {
  secret_name=$1
  gh secret list --repo "$repository" --json name \
    --jq ".[] | select(.name == \"$secret_name\") | .name" | grep -qx "$secret_name"
}

verify_configuration() {
  actual_workload_id=$(read_variable OP_WORKLOAD_ID)
  actual_environment_id=$(read_variable OP_ENVIRONMENT_ID)

  [ -n "$actual_workload_id" ] || fail "missing repository variable: OP_WORKLOAD_ID"
  [ -n "$actual_environment_id" ] || fail "missing repository variable: OP_ENVIRONMENT_ID"
  has_secret OP_INTEGRATION_KEY || fail "missing repository secret: OP_INTEGRATION_KEY"

  if [ -n "${OP_WORKLOAD_ID-}" ]; then
    [ "$actual_workload_id" = "$OP_WORKLOAD_ID" ] || fail "OP_WORKLOAD_ID differs"
  fi
  if [ -n "${OP_ENVIRONMENT_ID-}" ]; then
    [ "$actual_environment_id" = "$OP_ENVIRONMENT_ID" ] || fail "OP_ENVIRONMENT_ID differs"
  fi
}

if [ "$mode" = apply ]; then
  require_command op
  [ -n "${OP_WORKLOAD_ID-}" ] || fail "OP_WORKLOAD_ID is required"
  [ -n "${OP_ENVIRONMENT_ID-}" ] || fail "OP_ENVIRONMENT_ID is required"

  note "Configuring 1Password integration for $repository"
  gh variable set OP_WORKLOAD_ID --repo "$repository" --body "$OP_WORKLOAD_ID"
  gh variable set OP_ENVIRONMENT_ID --repo "$repository" --body "$OP_ENVIRONMENT_ID"
  integration_key=$(op read "$integration_key_ref" \
    --account "$op_account")
  [ -n "$integration_key" ] || fail "1Password returned an empty Integration Key"
  printf '%s' "$integration_key" | gh secret set OP_INTEGRATION_KEY --repo "$repository"
  unset integration_key
fi

verify_configuration
note "1Password integration verified: $repository"
