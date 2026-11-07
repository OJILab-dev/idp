# idp

Cloudflare Workers の無料枠だけで動く、パスキー専用の最小構成 OIDC IdP です。
対象は自分と家族のセルフホストアプリで、管理は手元の CLI から行います。

## 現在の状態

設計段階です。実装はまだありません。
設計は [docs/design/](docs/design/README.md) に記録しています。

## ゴール

- Cloudflare Workers と D1 の無料枠の範囲で常時稼働する
- ユーザーの認証手段はパスキーだけにし、OIDC と WebAuthn の標準に厳格に準拠する
- アプリ単位で「誰が使えるか」を管理できる
- 管理操作は手元の CLI から行い、後から MCP でも操作できる
- 将来、Worker を Rust で書き直せる余地を残す

## 構成

| 要素 | 役割 |
| --- | --- |
| Worker（TypeScript + Hono） | インターネットに公開する唯一の要素。OIDC エンドポイント、パスキー API、サインイン・登録ページを提供する |
| D1 | IdP の全状態を置くデータベース |
| `idpctl`（Go） | 手元で動かす管理 CLI。D1 REST API で直接操作し、同じバイナリに stdio の MCP サーバーを同梱する |

Worker には管理用のエンドポイントや管理 UI を置きません。
設計原則、全体構成の図、各トピックの設計は [設計ドキュメントの索引](docs/design/README.md) を参照してください。

## ドキュメント

| ドキュメント | 内容 |
| --- | --- |
| [docs/design/README.md](docs/design/README.md) | IdP の設計ドキュメントの索引。概要、ゴール、設計原則、全体構成 |
| [docs/philosophy/README.md](docs/philosophy/README.md) | OJILab の設計思想とエンジニアリング原則 |
| [docs/deployment/secret.md](docs/deployment/secret.md) | 1Password Environments と GitHub Actions による CD 用 Secret の扱い |
| [AGENT.md](AGENT.md) | このリポジトリを変更するエージェントの契約 |

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

deploy workflow の雛形は [examples/github-actions/deploy.yml](examples/github-actions/deploy.yml) にあります。

### GitHub Actions の pin

外部 Action と reusable workflow は、mise で管理する pinact で commit SHA に固定します。

```sh
mise install
GITHUB_TOKEN="$(gh auth token)" mise run actions:pin
GITHUB_TOKEN="$(gh auth token)" mise run actions:check
```

## 前提コマンド

- `gh`
- `jq`
- `mise`
- `op`
