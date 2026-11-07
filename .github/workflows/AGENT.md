# GitHub Actions agent contract

このディレクトリの workflow を作成または変更するエージェントは、各 job の実行環境、依存取得、KVM 要件を確認してから YAML を編集してください。

## Runner の選択

KVM を必要としない job は `runs-on: takumi-runner` を使用します。

`/dev/kvm` を必要とする E2E job は Takumi Runner で実行できません。
この job は GitHub-hosted `ubuntu-24.04` を使用し、Shisho Cloud 認証と cicd-sensor を同じ job の先頭に置きます。

Public リポジトリで Takumi Runner を使うには、GitHub Organization の runner group で `Allow public repositories` が有効でなければなりません。
job が `queued` のまま進まない場合は、workflow の再実行より先に runner group 設定を確認してください。

## Takumi Guard

npm、PyPI、RubyGems、Go Modules、Packagist から依存を取得する job は、最初の依存取得より前に対応する `flatt-security/setup-takumi-guard-*` Action を置きます。

Cargo、APT、依存取得を行わない job に、対応しない Guard Action を形式的に追加してはいけません。
すべての job は、対応 Guard を使用するか、対応対象の依存取得がないことを確認してください。

Guard の Action が設定した registry や proxy の環境変数を、後続の script で固定値に上書きしてはいけません。
既存値を保つ必要がある場合は、`${VARIABLE:-default}` の形で fallback だけを指定してください。

## KVM E2E の fallback

KVM E2E job は次の順序を保ちます。
sensor を checkout より前に起動すると、後続 workload の全体を観測できます。

```yaml
jobs:
  e2e:
    runs-on: ubuntu-24.04
    timeout-minutes: 60
    permissions:
      contents: read
      id-token: write
    steps:
      - id: auth
        name: Authenticate to Shisho Cloud
        uses: flatt-security/shisho-cloud-action@9b68d33503ebf75d7c285d489b288f96ef3df758 # v1.1.0
        with:
          bot-id: BT01M0MFTWGD1BQ2CKEPG92G53Y3
          export-token: true
          expires-in-minutes: 60

      - name: Start ci-cd sensor
        uses: cicd-sensor/cicd-sensor-action@a803a7bc1890f85d3f2feb7c29b74b5c730da6c2 # v0.0.37
        with:
          manager-url: https://manager.cicdsensor.cloud.shisho.dev
          manager-token: ${{ steps.auth.outputs.token }}

      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
```

Bot ID は secret ではなく、Shisho Cloud の bot を識別する公開値です。
`OJILab-dev` では `BT01M0MFTWGD1BQ2CKEPG92G53Y3` を workflow に直接記述します。
GitHub Free では private repository から Organization variable を参照できないため、`${{ vars.SHISHO_CICD_SENSOR_BOT_ID }}` へ置き換えてはいけません。
Bot ID を repository secret や repository variable として複製する必要もありません。

Shisho Cloud の認証 Action と cicd-sensor Action は別のサービスです。
workflow が認証 Action の step output を sensor Action に渡して両者を接続します。

## OIDC token の job 境界

OIDC 認証と sensor を別 job に分割してはいけません。
GitHub Actions は secret と判定した job output を downstream job に送信しないため、公式例の `needs.auth.outputs.token` はこの構成では空になります。

失敗時には次のいずれかが記録されます。

```text
Skip output 'token' since it may contain secret.
manager-token is empty
```

同じ job の `${{ steps.auth.outputs.token }}` を直接参照してください。
Base64 などの変換で masking を回避してはいけません。
job 分割が外部要件として必須になった場合は、外部 secret store の opaque handle または API key を別途設計し、このテンプレートの OIDC 構成を流用しないでください。

## 1Password Workload Identity

production deploy jobはGitHub Environment `production`を指定し、job-level permission `id-token: write`を付与します。
1PasswordのGitHub Actions destinationは、対象repository、workflow path、`main` branch、GitHub Environment `production`へ限定します。

認証にはrepository variables `OP_WORKLOAD_ID`と`OP_ENVIRONMENT_ID`、repository secret `OP_INTEGRATION_KEY`を使います。
`OP_SERVICE_ACCOUNT_TOKEN`とSecret Reference URIを使うService Account方式へ戻してはいけません。

```yaml
- name: Load deployment secrets
  uses: 1password/load-secrets-action@70062d7a876d3eb6334754fa26efd2fbd90c32f2 # v5.0.1
  with:
    export-env: true
  env:
    OP_WORKLOAD_ID: ${{ vars.OP_WORKLOAD_ID }}
    OP_ENVIRONMENT_ID: ${{ vars.OP_ENVIRONMENT_ID }}
    OP_INTEGRATION_KEY: ${{ secrets.OP_INTEGRATION_KEY }}
```

依存取得があるjobでは、依存取得を終えてからSecretを読み込みます。
pull requestのvalidation jobへOIDC permissionや1Password credentialを渡してはいけません。

## Merge Queue の workflow trigger

Public リポジトリで required check にする workflow は、`pull_request` と `merge_group` の両方で実行します。

```yaml
on:
  pull_request:
  merge_group:
```

required check が `merge_group` で起動しない場合、Merge Queue は結果を待ち続けた後に失敗します。

## External Action の pin

GitHub 公式の `actions/*` を含む外部 Action と reusable workflow は、mise で管理する pinact を使って40文字の commit SHAに固定します。
tag、branch、短縮SHAをチェックインしてはいけません。
SHAを手作業で検索、転記、更新してはいけません。

新規参照を固定する場合は、tagを指定してから pinact を実行します。

```sh
mise install pinact
GITHUB_TOKEN="$(gh auth token)" mise run actions:pin
GITHUB_TOKEN="$(gh auth token)" mise run actions:check
```

Action を更新する場合は、pinact の update を使います。

```sh
GITHUB_TOKEN="$(gh auth token)" mise run actions:update
GITHUB_TOKEN="$(gh auth token)" mise run actions:check
```

チェックインする参照には、pinact が生成した SHA と人間が読める version comment を残します。

```yaml
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
```

リポジトリ内の local Action（`./.github/actions/example`）は外部参照ではないため、pinact の対象外です。

## 検証

workflow を変更したら、少なくとも次を実行します。

```sh
GITHUB_TOKEN="$(gh auth token)" mise run actions:check
actionlint -ignore 'label "takumi-runner" is unknown' .github/workflows/*.yml .github/workflows/*.yaml
```

対象拡張子のファイルが存在しない場合は、actionlint の引数からその glob を外してください。
`takumi-runner` は Organization の custom runner label なので、その警告だけを除外します。
他の構文、式、権限、workflow エラーを除外してはいけません。

## 参照資料

- [Takumi Guard クイックスタート](https://shisho.dev/docs/ja/t/guard/quickstart/index.md)
- [Takumi Runner クイックスタート](https://shisho.dev/docs/ja/t/runner/quickstart)
- [cicd-sensor と Shisho Cloud の連携](https://shisho.dev/docs/ja/t/runner/features/cicdsensor-integration.md)
- [GitHub Actions job output](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idoutputs)
