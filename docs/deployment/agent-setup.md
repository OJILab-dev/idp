# エージェントによる認証情報の準備

ブートストラップの前提のうち、API トークン、state のバケットの R2 の S3 互換の認証情報、1Password の Vault のアイテム、CI 用の 1Password Environment の準備を、秘密の値をエージェントのコンテキストに一度も入れずにエージェントが行う方法を置く。

- 経緯：2026-11-12 に運用者が、運用者がすでに認証したセッション（`cf auth login`、`op` のサインイン、1Password のデスクトップアプリによる MCP サーバーの承認）の下でなら、エージェントがこの準備を行ってよいと決めた。それまでは、これらはダッシュボードでの運用者の手作業だった。
- 変わらない規則：エージェントは秘密を生成せず、秘密をコンテキストに読み込まない。`wrangler` は使わない。`cf auth login` は運用者が行う（[AGENT.md](../../AGENT.md) 参照）。
- この文書は方法だけを置く。アカウント ID、トークンの ID、Vault の ID、Environment の ID などの値は、ここにもリポジトリのどこにも書かない。

## 値を流す経路の原則

- 秘密は、パイプの中で、あるコマンドの出力から次のコマンドの入力か環境変数へ直接渡す。エージェントのツールの出力、コマンドの引数（`ps` で見える）、xtrace の表示、リポジトリの中のファイルには出さない。
- 値を扱うスクリプトは `-x` を付けずに動かす。xtrace は代入の右辺を表示するため。
- 表示してよいのは、名前、ID（トークンの ID は秘密ではないが、記録には残さない）、フィールドが空でないかの真偽だけ。値そのものを確かめる手順は置かない。
- 失敗したときにエラーの本文を表示する場合も、API の応答に値が含まれうる（トークンの作成の応答は値を含む）ので、作成の応答を表示しない。

## `cf` の OAuth トークンの使い方

- Cloudflare API を直接呼ぶときは、運用者の `cf auth login` が `cf` 自身の設定ファイルに保存した OAuth のトークンを、スクリプトがそのファイルから読む。
- トークンは `curl` の環境にだけ渡し、`curl` の `--variable` と `--expand-header` で Authorization のヘッダーに展開する（`curl` 8.3 以降）。引数に書かず、表示しない。
- 固定した `cf` にない操作（下の読み取りの確認、アカウントのトークンの作成）だけを API で行う。`cf` にある操作は `cf` で行う。

## 読み取りの確認を先に行う

作る前に、Cloudflare API で次を読み取りだけで確かめる。どれかが欠けていれば、何も作らずに止まり、運用者に頼む（下の「運用者だけが行うこと」）。

1. アカウントの `workers.dev` のサブドメイン（Cloudflare API「Get a Workers Subdomain」。固定した `cf` にはこれを読むコマンドがない）。`workers.dev` のモードでは、デプロイの設定ファイルの `workers_dev_subdomain` と一致すること。
2. R2 が有効なこと（バケットの一覧の取得が成功すること）。
3. 権限のグループの ID（アカウントの `tokens/permission_groups` の GET）。名前から ID を引き、ID をスクリプトに直書きしない。

## API トークンの作成

- アカウントが持つ API トークンを、Cloudflare API「Create account token」で作る。`cf` の OAuth のセッションは `account_api_tokens:create` の範囲を持つ。
- 範囲は[デプロイと設定](../design/deployment.md)の「API トークン」のとおりにする。
  - Terraform 用：`workers_dev` では、アカウントの `Workers Scripts Read` だけ。`custom_domain` では、同じ文書のとおりゾーンの読み取り。
  - デプロイ用：`workers_dev` では、`Workers Scripts Write` と `D1 Write`。`custom_domain` では、同じ文書が挙げるゾーンの権限（Workers のルートの編集と DNS の編集）も足す。
  - state 用：`Workers R2 Storage Bucket Item Write` を、state のバケット 1 つだけに限る。
- 同じ名前のトークンがすでにあれば、スクリプトは何も作らずに止まる。二重に作ると、どれが使われているか分からなくなり、古いものが失効されずに残るため。
- 表示するのはトークンの名前と ID だけ。トークンの値は、作成の応答からパイプで次の段（下の R2 の認証情報と Vault のアイテム）へだけ渡す。
- デプロイ用のトークンの最小の権限の組み合わせは、まだ確かめていない。デプロイと設定の「必要な権限の正確な名前は、実装で `cf deploy` が成功する最小の組み合わせを確かめて記録する」はそのまま残り、最初の `cf deploy` が成功するまで未確認とする。

## R2 の S3 互換の認証情報

- state 用のトークンから、パイプの中で導く（Cloudflare の R2 の文書の、API トークンから S3 互換の認証情報を得る方法）。
  - アクセスキーの ID：トークンの ID
  - シークレットアクセスキー：トークンの値の SHA-256 の 16 進
- ダッシュボードで別の R2 のトークンを作らずに済み、失効もトークン 1 つで済むため。

## 1Password の Vault のアイテム

- 設定ファイルの `onepassword_vault` に、`onepassword_cloudflare_item` の名前のアイテムを `op item create` で作る。`account_id` は秘密ではないのでこのときに入れ、秘密のフィールド（`terraform_api_token`、`r2_access_key_id`、`r2_secret_access_key`）は空で作る。
- 秘密のフィールドは、JSON を `op item edit` の標準入力にパイプして埋める（`op` はパイプで JSON を受け付ける）。JSON は `jq` が自分の環境変数から値を取って組み立てるので、値は引数に出ない。
- 確かめるのは、それぞれのフィールドが空でないことだけで、値は読み返さない。
- デプロイ用のトークンは Vault のアイテムに置かない（手元では使わず、CI 用の Environment にだけ置く）。

## CI 用の 1Password Environment

- Environment は 1Password の MCP サーバーの `create_environment` で作る。MCP サーバーは Environment の秘密の名前だけを一覧でき、値は読めない。
- 秘密でない値（`CLOUDFLARE_ACCOUNT_ID`）は、MCP の `append_secrets` で置いてよい。
- 秘密の値は、エージェントのコンテキストを通さずにエージェントが書く方法がない。`op environment secret`（`op` 2.42）は一覧しかできず、MCP の `append_secrets` はツールの呼び出しの中に値を取るため。
- そのため、スクリプトが秘密の値を、リポジトリの外の権限 `0600` の一時的な `.env` のファイルに書き、運用者が 1Password のアプリでそのファイルを Environment に取り込み、取り込んだらすぐにファイルを消す。
- 残るリスク：macOS の APFS と SSD では、上書きしてからの削除（`shred`、`rm -P`）は消去を保証しない。残ったブロックを守るのは FileVault だけなので、ファイルの寿命をできるだけ短くする（作ったらすぐ取り込み、すぐ消す）。
- GitHub Actions の destination の作成と限定は、[実行手順](runbook.md)の「CI のデプロイの一度だけの準備」と[1Password Environments と GitHub Actions](secret.md)のとおり運用者が行う。

## 1Password の MCP サーバーの準備

- 1Password の公式の Claude Code の plugin（marketplace `1Password/1password-claude-plugin`、plugin `1password@1password`）を入れ、デスクトップアプリの「Settings > Developer > Integrate with MCP clients」を有効にする。
- MCP サーバーが扱うのは Environment だけで、Vault のアイテムは扱えない。Vault のアイテムは上のとおり `op` で扱う。
- `authenticate` のツールはアカウントを引数に取らず、デスクトップアプリの承認の画面で選んだアカウントに結び付く。承認は 1Password がロックされるまで残るので、アカウントを切り替えるときは、1Password をロックしてからもう一度 `authenticate` する。

## 運用者だけが行うこと

- `cf auth login` と `op` のサインイン
- 1Password の承認の画面での承認
- 一時的な `.env` のファイルの Environment への取り込み（とその直後の削除の確認）
- R2 の有効化（支払いの手続きが要る）と、`workers.dev` のサブドメインがないときのその作成
- 署名鍵と管理者の鍵の生成。これらはレビュー済みの `generate-*.sh` のスクリプトに残し、運用者が Claude Code のプロンプトで `!` を付けて実行する。出力はエージェントのコンテキストの外に残る。スクリプトは公開の情報（公開鍵、`kid`、`keyid`）だけを表示するので、出力がコンテキストに入っても秘密は入らない。
- ゾーンの追加と、ゾーンの持ち主との確認（カスタムドメインのモード）、Rate Limiting の名前空間の ID の選択は、これまでどおり[ブートストラップ](bootstrap.md)の前提のとおり行う。
