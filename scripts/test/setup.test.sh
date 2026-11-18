#!/usr/bin/env bash
# Offline: gh, op, and mise are copies of this test acting as stubs; no GitHub or 1Password access.
# Keep xtrace off to check that scripts do not print even the fake Integration Key.
set -euo pipefail

case "$(basename "$0")" in
  gh)
    printf 'gh %s\n' "$*" >> "$SETUP_LOG"
    case "$1 $2" in
      'auth status') ;;
      'auth token') printf 'fake-token\n' ;;
      'repo view') printf '%s\n' "$TEST_REPOSITORY" ;;
      'variable set') ;;
      'variable list')
        case "$*" in
          *OP_WORKLOAD_ID*) printf 'test-workload\n' ;;
          *OP_ENVIRONMENT_ID*) printf 'test-environment\n' ;;
        esac
        ;;
      'secret set')
        [[ "$(</dev/stdin)" == fake-integration-key ]]
        ;;
      'secret list') printf 'OP_INTEGRATION_KEY\n' ;;
      'api --method') ;;
      api*) jq '. + {visibility: "private", default_branch: "main"}' .github/repository-settings.json ;;
      *) exit 1 ;;
    esac
    exit 0
    ;;
  op)
    [[ $# == 4 && $1 == read && $3 == --account ]]
    [[ $2 == "${OP_INTEGRATION_KEY_REF:-op://github-organization/OP_INTEGRATION_KEY/password}" ]]
    [[ $4 == "${OP_ACCOUNT:-ojilab.1password.com}" ]]
    printf 'op %s\n' "$*" >> "$SETUP_LOG"
    printf 'fake-integration-key\n'
    exit 0
    ;;
  mise)
    printf 'mise %s\n' "$*" >> "$SETUP_LOG"
    exit 0
    ;;
esac

root=$(cd "$(dirname "$0")/../.." && pwd)
tree=$(mktemp -d "$root/.setup-test.XXXXXX")
trap 'rm -rf "$tree"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$tree/bin" "$tree/.github/rulesets"
cp "$root"/setup-*.sh "$tree/"
cp "$root/.github/repository-settings.json" "$tree/.github/"
cp "$root/.github/rulesets/public-default-branch.json" "$tree/.github/rulesets/"
for command in gh op mise; do
  cp "$0" "$tree/bin/$command"
  chmod +x "$tree/bin/$command"
done
export PATH="$tree/bin:$PATH"
export SETUP_LOG="$tree/commands.log"
export OP_WORKLOAD_ID=test-workload OP_ENVIRONMENT_ID=test-environment
unset IDP_GITHUB_ORG OP_ACCOUNT OP_INTEGRATION_KEY_REF

run_setup() {
  : > "$SETUP_LOG"
  sh "$tree/$1" "${@:2}" > "$tree/output" 2>&1
}

assert_logged() {
  grep -Fxq -- "$1" "$SETUP_LOG" || {
    printf 'FAIL: missing command: %s\n' "$1" >&2
    exit 1
  }
}

assert_refused() {
  if run_setup "$1" --check; then
    printf 'FAIL: accepted %s\n' "$TEST_REPOSITORY" >&2
    exit 1
  fi
  grep -Fq -- "$2" "$tree/output" || {
    printf 'FAIL: missing refusal message: %s\n' "$2" >&2
    exit 1
  }
  if grep -Eq '^gh (api|variable|secret)|^op ' "$SETUP_LOG"; then
    printf 'FAIL: accessed configuration after owner refusal\n' >&2
    exit 1
  fi
}

for script in setup-repository.sh setup-1password-integration.sh; do
  export TEST_REPOSITORY=OJILab-dev/idp
  run_setup "$script" --check
  if grep -Eq '^op |^gh (variable|secret) set|^gh api --method' "$SETUP_LOG"; then
    printf 'FAIL: check mode read 1Password or changed configuration\n' >&2
    exit 1
  fi

  run_setup "$script"
  if [[ "$script" == setup-repository.sh ]]; then
    assert_logged 'gh api --method PATCH repos/OJILab-dev/idp --input .github/repository-settings.json'
  else
    assert_logged 'gh secret set OP_INTEGRATION_KEY --repo OJILab-dev/idp'
  fi

  export TEST_REPOSITORY=Example-Org/idp
  assert_refused "$script" 'repository must belong to OJILab-dev'
  export IDP_GITHUB_ORG=Example-Org
  run_setup "$script" --check
  run_setup "$script"
  if [[ "$script" == setup-repository.sh ]]; then
    assert_logged 'gh api --method PATCH repos/Example-Org/idp --input .github/repository-settings.json'
  else
    assert_logged 'gh secret set OP_INTEGRATION_KEY --repo Example-Org/idp'
  fi

  export TEST_REPOSITORY=OJILab-dev/idp
  assert_refused "$script" 'repository must belong to Example-Org'
  export IDP_GITHUB_ORG='Example-*'
  export TEST_REPOSITORY=Example-Org/idp
  assert_refused "$script" 'repository must belong to Example-*'
  unset IDP_GITHUB_ORG
  printf 'ok   %s organization checks and overrides\n' "$script"
done

export TEST_REPOSITORY=OJILab-dev/template-cf-stack
assert_refused setup-1password-integration.sh 'run this script in a repository generated from the template'
export IDP_GITHUB_ORG=OJILab-dev
assert_refused setup-1password-integration.sh 'run this script in a repository generated from the template'
unset IDP_GITHUB_ORG
export IDP_GITHUB_ORG=Example-Org
assert_refused setup-1password-integration.sh 'run this script in a repository generated from the template'
export TEST_REPOSITORY=Example-Org/template-cf-stack
assert_refused setup-1password-integration.sh 'run this script in a repository generated from the template'
unset IDP_GITHUB_ORG

export TEST_REPOSITORY=OJILab-dev/idp
run_setup setup-1password-integration.sh
assert_logged 'op read op://github-organization/OP_INTEGRATION_KEY/password --account ojilab.1password.com'
export IDP_GITHUB_ORG=Example-Org TEST_REPOSITORY=Example-Org/idp
export OP_ACCOUNT=example.1password.com OP_INTEGRATION_KEY_REF='op://organization vault/Integration Key/password'
run_setup setup-1password-integration.sh
assert_logged "op read $OP_INTEGRATION_KEY_REF --account $OP_ACCOUNT"
if grep -Fq fake-integration-key "$tree/output"; then
  printf 'FAIL: Integration Key was printed\n' >&2
  exit 1
fi
run_setup setup-1password-integration.sh --check
if grep -q '^op ' "$SETUP_LOG"; then
  printf 'FAIL: check mode read 1Password\n' >&2
  exit 1
fi
export IDP_GITHUB_ORG='' OP_ACCOUNT='' OP_INTEGRATION_KEY_REF=''
export TEST_REPOSITORY=OJILab-dev/idp
run_setup setup-1password-integration.sh
assert_logged 'op read op://github-organization/OP_INTEGRATION_KEY/password --account ojilab.1password.com'
run_setup setup-repository.sh --check
printf 'ok   Integration Key defaults, overrides, empty inputs, and check mode\n'
