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

- 署名鍵と管理者の秘密鍵（RFC 9421 の署名に使う管理者の鍵）は、必ずリポジトリのレビュー済みの生成スクリプトで生成する。手で生成してはいけない。スクリプトを通せば誰が実行しても結果は同じなので、エージェントもそのスクリプトを実行してよい。スクリプトは鍵を 1Password と Worker Secret に直接渡し、秘密でない値（`kid`、`keyid`、公開鍵。移行の間の今のスクリプトでは CSR とフィンガープリントも）だけを出力する（[デプロイと設定](docs/design/deployment.md)参照）。
- エージェントは、生成スクリプトを通さずに鍵を生成したり、鍵の値を読み出したり、受け渡したりしてはいけない。生成スクリプトを、秘密を出力するように変えてはいけない。
- 秘密（署名鍵、管理者の秘密鍵、API トークン、IdP が発行するクライアントシークレットと登録トークンなど）を AI のコンテキストに入れてはいけない。IdP が発行する秘密は、管理用の Worker が応答で 1 回だけ返し、`idpctl` が権限 `0600` のファイルに書き出してパスだけを表示する設計であり、これを崩してはいけない。
- 管理操作は管理用の Worker の管理 API だけに置き、IdP の Worker には置かない。IdP の Worker から共有コアの管理系のモジュールを import してはいけない。
- 今は MCP を提供しない。追加する場合は、先に [将来拡張](docs/design/future-extensions.md) の MCP の節を見直す。

詳細は [管理 CLI と管理用の Worker（idpctl）](docs/design/idpctl.md)、[トークン設計](docs/design/tokens.md)、[デプロイと設定](docs/design/deployment.md) を参照してください。

## GitHub Actions

`.github/workflows/` 配下を作成または変更する前に、[.github/workflows/AGENT.md](.github/workflows/AGENT.md) を読んで従ってください。

外部 Action と reusable workflow の参照は、mise で管理する pinact を使って40文字の commit SHA に固定します。
tag、branch、短縮 SHA をチェックインしてはいけません。

```sh
GITHUB_TOKEN="$(gh auth token)" mise run actions:pin
GITHUB_TOKEN="$(gh auth token)" mise run actions:check
```

## Cloudflare CLI

Cloudflare の操作には、ルートの `package.json` で固定した `cf` CLI を `pnpm exec cf …` で使います。グローバルに入れた `cf` に頼ってはいけません。
`cf` のバージョンは範囲ではなく完全なバージョンで指定し、`package.json` と `pnpm-lock.yaml` をまとめてコミットします。
公開から 14 日たっていない版は、`pnpm-workspace.yaml` の `minimumReleaseAge` で入れられません。この設定と `allowBuilds` を緩めてはいけません。
`cf auth login` は運用者が実行します。エージェントは Cloudflare の認証情報を作成、読み出し、受け渡ししてはいけません。
運用者がすでに認証した `cf` と `op` のセッションの下で、エージェントがレビュー済みの生成スクリプトを実行することは許されます。その場合も、エージェント自身が Cloudflare の認証情報や秘密を作成、読み出し、表示、受け渡ししてはいけません（値はスクリプトの中で `cf` と `op` の間だけを流れます）。

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

Setup はリポジトリのルートで次を実行します。

```sh
mise install
pnpm install --frozen-lockfile
```

TypeScript の workspace（`packages/core`、`apps/worker`、`apps/admin-worker`）と、D1 のスキーマ（`contract/migrations`）の正規コマンドは次のとおりです。CI（`.github/workflows/ci.yml`）も同じ `pnpm run check` を実行します。

```sh
pnpm run typecheck   # tsc
pnpm run lint        # ESLint。IdP の Worker から管理系のモジュールへの import を禁止する規則を含む
pnpm run test        # Vitest。D1 のスキーマのテストはローカルの D1（miniflare、workerd の SQLite）で動く
pnpm run check       # 上の 3 つを順に実行する。コミットの前に必ず通す
```

- `contract/migrations/` の番号順のマイグレーション（`0001_init.sql`、`0002_audit_log_append_only.sql`、…）は、[データモデル](docs/design/data-model.md) の SQL のブロックと、出てくる順に 1 対 1 で同じ内容でなければならず、テストがずれを検出します。スキーマを変えるときは、先にドキュメントを更新してからマイグレーションに写します。適用済みのマイグレーションは書き換えず、次の番号のファイルを足します。
- テストの D1 は `cf` が同梱するのと同じ版の miniflare を使います。`cf` を更新するときは、`package.json` の `miniflare` も `cf` の依存と同じ版に揃えます。wrangler は使いません。

`idpctl`（Go）と e2e（Playwright）を追加したら、それぞれの Setup、Build、Test、Check の正規コマンドをこの節へ記録してください。
Check には、IdP の Worker が管理系のモジュールに依存しないことの lint とビルド成果物の検査、管理 API の仕様と Go の生成物のずれの検出、D1 アダプタの適合テストを含めます。
