# Repository agent contract

このリポジトリは、Cloudflare Workers の無料枠で動くパスキー専用の最小構成 OIDC IdP です。
変更するエージェントは、変更対象に必要なコマンドを非対話 shell から実行できる状態に保ってください。

## 変更前に読むもの

変更を始める前に、[docs/philosophy/](docs/philosophy/README.md) と、変更対象に関係する [docs/design/](docs/design/README.md) のドキュメントを読んでください。
設計と食い違う変更をする場合は、先に設計ドキュメントを更新します。

## 設計ドキュメントの規約

- 日本語で書く。
- サンプルコードを載せない。例外は SQL のスキーマだけ。
- 決定事項は各トピックのドキュメントに記録する。[docs/design/open-questions.md](docs/design/open-questions.md) には、作りながら実測・確認する項目だけを残す。
- 仕様に関する記述は、一次資料（RFC、OpenID Connect、W3C、NIST、ベンダーのドキュメント）で確認し、節番号を付けて引用する。
- セキュリティ上の SHOULD を弱めてはいけない。従わない場合は、例外であることと理由を明示して記録する。

## セキュリティ

- 署名鍵は、運用者が AI や MCP のセッションの外で手作業で生成する。エージェントは署名鍵の生成、読み出し、登録、受け渡しを行ってはいけない。
- 秘密（署名鍵、API トークン、client secret、登録トークンなど）を AI のコンテキストに入れてはいけない。`idpctl` は平文を戻り値に含めず、権限 `0600` のファイルに書き出してパスだけを返す設計であり、これを崩してはいけない。
- MCP 経由の書き込み操作は、Claude Code の permissions で毎回人間の確認を必要とする設定にする。取り返しのつかない操作は MCP に出さない。

詳細は [管理 CLI / MCP（idpctl）](docs/design/idpctl.md)、[トークン設計](docs/design/tokens.md)、[デプロイと設定](docs/design/deployment.md) を参照してください。

## GitHub Actions

`.github/workflows/` 配下を作成または変更する前に、[.github/workflows/AGENT.md](.github/workflows/AGENT.md) を読んで従ってください。

外部 Action と reusable workflow の参照は、mise で管理する pinact を使って40文字の commit SHA に固定します。
tag、branch、短縮 SHA をチェックインしてはいけません。

```sh
GITHUB_TOKEN="$(gh auth token)" mise run actions:pin
GITHUB_TOKEN="$(gh auth token)" mise run actions:check
```

## Repository settings

GitHub 上の設定を適用する場合は、リポジトリのルートで次を実行します。

```sh
./setup-repository.sh
```

設定ドリフトだけを確認する場合は、次を実行します。

```sh
./setup-repository.sh --check
```

スクリプトが拒否した owner、visibility、default branch を推測で変更してはいけません。

## 1Password integration

1Password Environment に GitHub Actions destination を作成してから次を実行します。

```sh
OP_WORKLOAD_ID='<workload-id>' \
OP_ENVIRONMENT_ID='<environment-id>' \
./setup-1password-integration.sh
```

設定ドリフトだけを確認する場合は、次を実行します。

```sh
./setup-1password-integration.sh --check
```

1Password Service Account と `OP_SERVICE_ACCOUNT_TOKEN` を追加してはいけません。
このリポジトリは Organization 共通の Workload Identity Provider と GitHub OIDC を使います（[docs/deployment/secret.md](docs/deployment/secret.md) 参照）。

## Project commands

実装はまだありません。
Worker（pnpm）、`idpctl`（Go）、e2e（Playwright）を追加したら、それぞれの Setup、Build、Test、Check の正規コマンドをこの節へ記録してください。
