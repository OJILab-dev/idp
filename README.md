# idp

Cloudflare Workers の無料枠と D1 だけで動く、パスキー専用の最小構成 OIDC IdP です。
対象は自分と家族のセルフホストアプリです。管理は、mTLS の背後に置いた別の管理用の Worker を、手元の Go の CLI `idpctl` から呼んで行います。

## 現在の状態

実装済みで、まだデプロイしていません。
設計の段階 1〜6（共有コア、D1 アダプタ、IdP の Worker、管理用の Worker、`idpctl`）と、Terraform とブートストラップのスクリプトは main にマージ済みです。

残っている作業は次のとおりです。

- 検証用の Cloudflare アカウントへの最初のデプロイ。運用者が [ブートストラップの実行手順](docs/deployment/runbook.md) に沿って行います。Worker のデプロイの workflow はまだありません（雛形は [examples/github-actions/deploy.yml](examples/github-actions/deploy.yml)）。
- e2e テスト（Playwright）。[セキュリティ要件チェックリスト](docs/design/security-checklist.md) の攻撃ケースを実装します。

## ゴール

- Cloudflare Workers と D1 の無料枠の範囲で常時稼働する
- ユーザーの認証手段はパスキーだけにし、OIDC と WebAuthn の標準に厳格に準拠する
- アプリ単位で「誰が使えるか」を管理できる
- 管理操作は手元の CLI から行い、管理者は IdP 自身ではなく mTLS で確かめる
- 将来、Worker を Rust で書き直せる余地を残す

## 構成

| 要素 | 役割 |
| --- | --- |
| IdP の Worker（TypeScript + Hono） | 利用者と RP に公開する要素。OIDC エンドポイント、パスキー API、サインイン・登録・アカウントページを提供する |
| 管理用の Worker（TypeScript） | 別のホスト名に置く管理 API。エッジの mTLS と証明書のフィンガープリントの許可リストで管理者を確かめる |
| 共有コア（TypeScript） | ドメインの規則、入力の検証、SQL、ユースケースを 1 か所に持ち、2 つの Worker が使う |
| D1 | IdP の全状態を置くデータベース。2 つの Worker が同じものをバインドする |
| `idpctl`（Go） | 手元で動かす管理 CLI。管理 API を呼ぶだけの薄いクライアントで、ドメインの規則は評価しない |

IdP の Worker には管理用のエンドポイントや管理 UI を置きません。
設計原則、全体構成の図、各トピックの設計は [設計ドキュメントの索引](docs/design/README.md) を参照してください。

## リポジトリの構成

| パス | 内容 |
| --- | --- |
| [apps/worker/](apps/worker) | IdP の Worker。OIDC エンドポイント、`/webauthn/*` の API、サインイン・登録・アカウントの静的ページ |
| [apps/admin-worker/](apps/admin-worker) | 管理用の Worker。mTLS の再確認と許可リストの後ろの管理 API と、その OpenAPI の仕様の生成 |
| [packages/core/](packages/core) | 共有コア。利用者向け（`user`）、管理系（`admin`）、共通（`shared`）のユースケースとドメインの規則 |
| [packages/d1-adapter/](packages/d1-adapter) | 共有コアのデータベースのポートを D1 で実装するアダプタと、その適合テスト |
| [contract/](contract) | 実装に依存しない契約。D1 のマイグレーション（`migrations`）、管理 API の仕様（`openapi`）、テストベクタ（`testdata`）、スキーマのテスト（`test`） |
| [cmd/idpctl/](cmd/idpctl) | Go の管理 CLI。管理 API のクライアントは `contract/openapi/admin.json` から生成する |
| [infra/](infra) | 管理者のクライアント証明書と、IdP のホスト名に絞ったゾーンのルール（管理用のホスト名の mTLS と WAF、issuer の HTTPS へのリダイレクト、レート制限）を持つ Terraform と、そのオフラインのテスト。ゾーンをサービスと共有するときは、ルールの定義をゾーンの持ち主に出力する |
| [scripts/](scripts) | ブートストラップのスクリプト（state のバケット、D1、マイグレーション、署名鍵と管理者の鍵の生成、Terraform の実行） |
| [deployments/](deployments) | デプロイごとの設定ファイル（`<デプロイの名前>.tfvars.json`）とその雛形 |
| [docs/](docs) | 設計思想、設計ドキュメント、デプロイの手順 |
| [examples/](examples) | GitHub Actions の deploy workflow の雛形 |

## 前提とツールチェーン

- `gh`、`jq`、`mise`、`op`、`openssl`（3.x）を使います。
- Node.js、pnpm、Go、oapi-codegen、Terraform、ShellCheck、actionlint、pinact は、mise が [mise.toml](mise.toml) に固定したバージョンを `mise install` で入れます。
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

Terraform とシェルスクリプトの検査は CI（[.github/workflows/ci.yml](.github/workflows/ci.yml)）の `infra` のジョブで動きます。内容は `infra/` に対する `terraform fmt -check`、`terraform validate`、`terraform test`（モックの provider でオフラインに動く）と、`scripts/` に対する `shellcheck` です。

## ドキュメント

| ドキュメント | 内容 |
| --- | --- |
| [docs/philosophy/README.md](docs/philosophy/README.md) | OJILab の設計思想とエンジニアリング原則 |
| [docs/design/README.md](docs/design/README.md) | IdP の設計ドキュメントの索引。概要、ゴール、設計原則、全体構成 |
| [docs/design/cross-language-contract.md](docs/design/cross-language-contract.md) | SQL、エンコーディング、ID、鍵の形式、テストベクタ、管理 API の仕様の取り決め |
| [docs/deployment/bootstrap.md](docs/deployment/bootstrap.md) | 空の Cloudflare アカウントから最初のユーザーと RP をつなぐまでの手順の設計 |
| [docs/deployment/runbook.md](docs/deployment/runbook.md) | ブートストラップを `infra/` と `scripts/` で実行するときの運用者の操作の順番 |
| [docs/deployment/secret.md](docs/deployment/secret.md) | 1Password Environments と GitHub Actions による CD 用 Secret の扱い |
| [AGENT.md](AGENT.md) | このリポジトリを変更するエージェントの契約 |

## 貢献者とエージェント向けのセキュリティ規則

詳細と正本は [AGENT.md](AGENT.md) です。

- 署名鍵と管理者の秘密鍵は、`scripts/` のレビュー済みの生成スクリプトでだけ生成する。手で生成したり、鍵の値を読み出したり受け渡したりしない。
- 秘密（鍵、API トークン、IdP が発行するクライアントシークレットや登録トークン）を AI のコンテキストに入れない。
- `cf auth login` は運用者が実行する。エージェントは Cloudflare の認証情報を作成、読み出し、受け渡ししない。
- 管理操作は管理用の Worker だけに置く。IdP の Worker は共有コアの管理系のモジュールを import しない（ESLint の規則で検査する）。

## リポジトリの運用

### Repository settings

GitHub 上のリポジトリ設定を適用します。

```sh
./setup-repository.sh
```

設定を変更せずドリフトだけを確認する場合:

```sh
./setup-repository.sh --check
```

### 1Password Environments による CD

CD 用 Secret の正本は 1Password Environment に置き、GitHub Actions の OIDC token を 1Password が検証して、許可された job にだけ実行時に渡します。
GitHub には 1Password Integration Key 以外の長寿命 Secret を保存しません。
Environment と GitHub Actions destination の作成手順、命名規則、権限、ローテーションは [docs/deployment/secret.md](docs/deployment/secret.md) を参照してください。

1Password 側で作成した Workload ID と Environment ID を GitHub 側へ設定します。

```sh
OP_WORKLOAD_ID='<workload-id>' \
OP_ENVIRONMENT_ID='<environment-id>' \
./setup-1password-integration.sh
```

設定を変更せずドリフトだけを確認する場合:

```sh
./setup-1password-integration.sh --check
```

### GitHub Actions の pin

外部 Action と reusable workflow は、mise で管理する pinact で commit SHA に固定します。

```sh
mise install
GITHUB_TOKEN="$(gh auth token)" mise run actions:pin
GITHUB_TOKEN="$(gh auth token)" mise run actions:check
```
