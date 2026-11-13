# 開発

このリポジトリで開発するときの前提、コマンド、リポジトリの運用をまとめます。
変更する人とエージェントの契約の正本は [AGENT.md](../AGENT.md) です。ここと食い違うときは AGENT.md に従ってください。

## 前提とツールチェーン

- `gh`、`jq`、`mise`、`op`、`openssl`（3.x）を使います。
- Node.js、pnpm、Go、oapi-codegen、Terraform、ShellCheck、actionlint、pinact は、mise が [mise.toml](../mise.toml) に固定したバージョンを `mise install` で入れます。
- JavaScript のパッケージマネージャーは pnpm だけを使います。依存は `pnpm install --frozen-lockfile` で入れます。
- Cloudflare の操作には、ルートの `package.json` の devDependency の `cf` CLI（ベータ）を `pnpm exec cf …` で使います。wrangler は使いません。
- `cf auth login` は運用者が自分で実行します。

## コマンド

| コマンド | 内容 |
| --- | --- |
| `pnpm run check` | TypeScript の型検査、ESLint、Vitest を順に実行する。コミットの前に必ず通す |
| `pnpm run typecheck` / `pnpm run lint` / `pnpm run test` | 上の 3 つを個別に実行する |
| `pnpm run openapi:generate` | 管理用の Worker から `contract/openapi/admin.json` を作り直す |
| `mise run idpctl:generate` | `contract/openapi/admin.json` から `idpctl` の管理 API のクライアントを作り直す |
| `mise run idpctl:check` | `idpctl` の gofmt、go vet、ビルド、テスト（生成物のずれの検出を含む） |
| `mise run actions:pin` / `mise run actions:check` | 外部 Action の commit SHA への固定と、その確認 |

Terraform とシェルスクリプトの検査は CI（[.github/workflows/ci.yml](../.github/workflows/ci.yml)）の `infra` のジョブで動きます。内容は `infra/` に対する `terraform fmt -check`、`terraform validate`、`terraform test`（モックの provider でオフラインに動く）と、`scripts/` に対する `shellcheck` です。

## CI とデプロイ

- PR では [.github/workflows/ci.yml](../.github/workflows/ci.yml) が検査と e2e テスト（Playwright）を流します。e2e は、カスタムドメインの形と `workers.dev` の形の issuer の両方で同じシナリオを流します。
- [.github/workflows/deploy.yml](../.github/workflows/deploy.yml) は、main へのマージ（と手動の起動）から、Terraform の apply、D1 のマイグレーション、IdP の Worker、管理用の Worker の順にデプロイし、外から確かめます。ブートストラップの段階 5 以降にあたります。流れの設計は [デプロイと設定](design/deployment.md) の「デプロイのパイプライン」にあります。
- 最初のデプロイは、運用者が [ブートストラップの実行手順](deployment/runbook.md) に沿って行います。

## 貢献者とエージェント向けのセキュリティ規則

詳細と正本は [AGENT.md](../AGENT.md) です。

- 署名鍵と管理者の秘密鍵は、`scripts/` のレビュー済みの生成スクリプトでだけ生成する。手で生成したり、鍵の値を読み出したり受け渡したりしない。
- 秘密（鍵、API トークン、IdP が発行するクライアントシークレットや登録トークン）を AI のコンテキストに入れない。
- `cf auth login` は運用者が実行する。エージェントがブートストラップの認証情報を準備するときは、運用者が認証したセッションの下で、値をコンテキストに入れずにパイプで流す（[エージェントによる認証情報の準備](deployment/agent-setup.md)）。
- 管理操作は管理用の Worker だけに置く。IdP の Worker は共有コアの管理系のモジュールを import しない（ESLint の規則で検査する）。

## リポジトリの運用

実行するコマンドそのものは [AGENT.md](../AGENT.md) の該当する節にあります。

### Repository settings

GitHub 上のリポジトリ設定は、リポジトリのルートの `./setup-repository.sh` で適用します。設定を変更せずドリフトだけを確認するときは `--check` を付けます（AGENT.md の「Repository settings」）。

### 1Password Environments による CD

CD 用 Secret の正本は 1Password Environment に置き、GitHub Actions の OIDC token を 1Password が検証して、許可された job にだけ実行時に渡します。
GitHub には 1Password Integration Key 以外の長寿命 Secret を保存しません。
1Password 側で作成した Workload ID と Environment ID は、`./setup-1password-integration.sh` で GitHub 側へ設定します。ドリフトだけを確認するときは `--check` を付けます（AGENT.md の「1Password integration」）。
Environment と GitHub Actions destination の作成手順、命名規則、権限、ローテーションは [1Password Environments と GitHub Actions](deployment/secret.md) を参照してください。

### GitHub Actions の pin

外部 Action と reusable workflow は、mise で管理する pinact で commit SHA に固定します。`mise install` の後、`GITHUB_TOKEN` に `gh auth token` の値を渡して `mise run actions:pin` と `mise run actions:check` を実行します（AGENT.md の「GitHub Actions」）。
