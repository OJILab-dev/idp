# OJILab Cloudflare stack template

OJILabでCloudflare上へデプロイするリポジトリの共通設定、GitHub Actions運用契約、1Password Environments連携の標準形を提供するテンプレートです。

## このテンプレートが定めること

- GitHub ActionsはKVM不要のjobでTakumi Runnerを使用する
- npm依存を取得するjobではTakumi Guardを依存取得前に設定する
- 外部Actionとreusable workflowはpinactでcommit SHAへ固定する
- CI/CD用Secretの正本を1Password Environmentに置く
- Organization共通の1Password Workload Identity Providerを使う
- GitHub OIDCのrepository、workflow、branch、GitHub Environmentを接続条件にする
- GitHubには1Password Integration Key以外の長寿命Secretを保存しない
- 人間向けVaultとworkload向けEnvironmentのアクセス境界を分離する

## 1Password命名規則

本番Environmentは次の名前で作成します。

```text
<stack-name>-prod
```

実例:

```text
cloudflare-dns-prod
cloudflare-zero-trust-prod
```

Environment内の変数名は、deploy toolがそのまま参照する環境変数名に揃えます。

```text
CLOUDFLARE_API_TOKEN
CLOUDFLARE_ACCOUNT_ID
```

GitHub repositoryには次の値を登録します。

```text
Repository variable: OP_WORKLOAD_ID
Repository variable: OP_ENVIRONMENT_ID
Repository secret:   OP_INTEGRATION_KEY
```

`OP_INTEGRATION_KEY`はOrganization共通Providerのkeyですが、keyだけではEnvironmentを読み取れません。
Environmentごとに作成するGitHub Actions destinationの条件とOIDC tokenが一致して初めてアクセスできます。

詳細な作成手順、権限、移行、ローテーション方法は[docs/deployment/secret.md](docs/deployment/secret.md)を参照してください。

## GitHub Actionsへ導入する

[examples/github-actions/deploy.yml](examples/github-actions/deploy.yml)を、生成したリポジトリの`.github/workflows/deploy.yml`へコピーし、パッケージマネージャーとdeploy commandをプロジェクトに合わせて変更します。

1Password側でEnvironmentとGitHub Actions destinationを作成した後、表示されたWorkload IDとEnvironment IDを使ってGitHub側を設定します。

```sh
OP_WORKLOAD_ID='<workload-id>' \
OP_ENVIRONMENT_ID='<environment-id>' \
./setup-1password-integration.sh
```

設定値を変更せず確認する場合:

```sh
./setup-1password-integration.sh --check
```

外部ActionのSHAを更新・検証します。

```sh
mise install
GITHUB_TOKEN="$(gh auth token)" mise run actions:pin
GITHUB_TOKEN="$(gh auth token)" mise run actions:check
```

## Repository settings

```sh
./setup-repository.sh
```

設定変更を行わずドリフトだけを確認する場合:

```sh
./setup-repository.sh --check
```

## 前提コマンド

- `gh`
- `jq`
- `mise`
- `op`

生成後は、このREADMEと`AGENT.md`にプロジェクト固有の目的、Setup、Build、Test、Check、Deployコマンドを追記してください。
