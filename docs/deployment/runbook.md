# ブートストラップの実行手順（運用者向け）

[ブートストラップ](bootstrap.md)の段階 0〜5b を、リポジトリの Terraform（`infra/`）とスクリプト（`scripts/`）で実行するときの、運用者の操作の順番。順番と各段階で確かめることの設計はブートストラップに置き、このドキュメントはどのスクリプトをどの順に動かすかだけを書く。どのスクリプトも `--help` で使い方を表示する。

すべてのスクリプトは、第 1 引数にデプロイの名前（`deployments/<デプロイの名前>.tfvars.json` の `<デプロイの名前>`）を取る。アカウント ID は設定ファイルに書かず、1Password のアイテムから実行時に読む。

## 前提（ダッシュボードと 1Password での手作業）

ブートストラップの「前提」に挙げた手作業を先に済ませる。スクリプトはこれらを作らない。

1. ゾーンを対象のアカウントに追加し、ネームサーバーを切り替える。
2. R2 を有効にする。
3. API トークンを役割ごと（Terraform 用、デプロイ用、plan 用）に作り、state のバケット用の R2 の S3 互換の認証情報を作る。
4. 1Password の Vault（設定ファイルの `onepassword_vault`）に、設定ファイルの `onepassword_cloudflare_item` の名前でアイテムを作り、次のラベルのフィールドを置く。ラベルはスクリプトが決めた名前で、デプロイごとに変えない。
   - `account_id`：Cloudflare のアカウント ID
   - `terraform_api_token`：Terraform 用の API トークン
   - `r2_access_key_id` と `r2_secret_access_key`：state のバケットの R2 の認証情報
5. CI 用の 1Password Environment と GitHub Actions の destination を作る（[1Password Environments と GitHub Actions](secret.md)参照）。これは段階 5 の前までに済ませればよい。

## 手元の準備

1. リポジトリのルートで `mise install` と `pnpm install --frozen-lockfile` を実行し、mise が固定した Terraform と、`package.json` が固定した `cf` を入れる。`jq`、`openssl`（3.x）、`op` も使う。
2. `op` で 1Password にサインインする。
3. `pnpm exec cf auth login` を実行し、`cf` を認証する。エージェントにはさせない（[AGENT.md](../../AGENT.md) 参照）。

## 段階ごとの操作

| 段階 | 運用者の操作 | 確かめること |
| --- | --- | --- |
| 0 | `deployments/verification.tfvars.json.example` を写して `deployments/<デプロイの名前>.tfvars.json` を作り、値を埋める。`admin_client_certificates` と `admin_allowlist` は空のままにする。PR でレビューしてマージする | アカウント ID がファイルにないこと。issuer と管理用のホスト名が、そのアカウントのゾーンの中にあり、互いに違うこと |
| 1 | `scripts/bootstrap-state-bucket.sh` を実行して state のバケットを作り、`scripts/bootstrap-d1.sh` を実行して D1 を作る | 両方のスクリプトが、`cf` の対象のアカウントが入力のものであることを確かめてから動くこと。D1 のスクリプトが production バックエンドであることを確かめて正常に終わること |
| 2 | `scripts/d1-migrate.sh` を実行する | マイグレーションが適用されること。本物の D1 でトリガーが更新と削除を拒否することは、[未決事項](../design/open-questions.md)の項目として確かめる |
| 3 | `scripts/generate-signing-key.sh` を実行する | 出力が公開鍵の JWK（`kid` を含む）だけであること。1Password のアイテムに `jwk`、`kid`、`public_jwk` があること |
| 4a | 管理者ごとに `scripts/generate-admin-key.sh` を実行する。スクリプトは秘密鍵を 1Password に入れ、CSR を設定ファイルの `admin_client_certificates` に書く。設定ファイルの変更を PR でレビューしてマージする | 出力が CSR と公開鍵だけであること。秘密鍵が 1Password のアイテムにだけあること |
| 4b | `scripts/terraform.sh` で `init`、`plan`、`apply` の順に実行する。`apply` は Terraform が承認を求めるので、plan の内容を読んでから承認する | plan が、管理用のホスト名の mTLS の割り当て、WAF のカスタムルール、レート制限ルール、管理者ごとのクライアント証明書、ゾーンの設定（Always Use HTTPS を有効、TLS の最小バージョンを 1.2）だけを作ること。D1 と DNS のレコードを含まないこと |
| 4c | `scripts/terraform.sh` の `output` で、管理者ごとの証明書とフィンガープリントを表示する。フィンガープリントと管理者の名前を設定ファイルの `admin_allowlist` に足し、PR でレビューしてマージする。証明書は `idpctl` の管理者が手元に置く | フィンガープリントが小文字の 16 進 64 文字であること |
| 5 | 2 つの Worker の最初のデプロイを CI で行う（デプロイの workflow は別の作業） | ブートストラップの段階 5 の確認 |
| 5b | `scripts/upload-signing-key.sh` を実行する | 出力が `kid` だけで、段階 3 の `kid` と一致すること。JWKS にその `kid` が載ること |

- 段階 3、4a、5b のスクリプトは秘密を扱うので xtrace を付けずに動く。実行中の表示や出力に秘密が出たら、その鍵は漏れたものとして作り直す（[ブートストラップ](bootstrap.md)の失敗したとき）。
- 段階 3 と 4a のスクリプトは、同じ名前の 1Password のアイテムがあれば止まる。作り直すときだけ `--replace` を付け、古いアイテムをアーカイブさせる（削除はしない）。
- 段階 4b の `apply` は、ゾーンに WAF のカスタムルールやレート制限ルールの entry point のルールセットがすでにあると失敗する。Terraform はゾーンのそれぞれのフェーズのルールセットを丸ごと持つので、既存のルールを Terraform の設定に移すか、消してから適用する。どちらにするかは運用者が決める。
- Always Use HTTPS と TLS の最小バージョンはゾーン全体の設定なので、同じゾーンのほかのホスト名にも効く。検証用のアカウントのゾーンに、平文の HTTP や TLS 1.1 以下を必要とするホスト名がないことを、apply の前に確かめる。
- 2 回目以降の Terraform の apply は CI で行う（[ブートストラップ](bootstrap.md)の実行する場所と認証情報）。

## 未確認のこと

次は、`cf` と `op` を実際に動かして初めて確かめられる。最初の実行で確かめ、違えばスクリプトを直す。

- `cf workers secrets update` が、要求の本文を `--body @/dev/stdin` で標準入力から受け取り、`--type` と一緒に渡しても受け付けること（段階 5b）
- `cf d1 migrations apply` が、非対話の実行で確認を求めずに適用すること（段階 2）
- `cf accounts get` と `cf d1 get` が、`CLOUDFLARE_ACCOUNT_ID` のアカウントを対象にすること（[デプロイと設定](../design/deployment.md)の直書きの禁止）
- `op item create` が、標準入力から JSON のテンプレートを受け取ること（段階 3 と 4a。スクリプトは作った後に秘密でないフィールドを読み返して確かめる）
- Terraform の provider が返す `fingerprint_sha256` が、Workers の `certFingerprintSHA256` と同じ値であること（段階 4c）
