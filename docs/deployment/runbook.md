# ブートストラップの実行手順（運用者向け）

[ブートストラップ](bootstrap.md)の段階 0〜5b を、リポジトリの Terraform（`infra/`）とスクリプト（`scripts/`）で実行するときの、運用者の操作の順番。順番と各段階で確かめることの設計はブートストラップに置き、このドキュメントはどのスクリプトをどの順に動かすかだけを書く。どのスクリプトも `--help` で使い方を表示する。

すべてのスクリプトは、第 1 引数にデプロイの名前（`deployments/<デプロイの名前>.tfvars.json` の `<デプロイの名前>`）を取る。アカウント ID は設定ファイルに書かず、1Password のアイテムから実行時に読む。

管理者の認証は、両方のホスティングのモードで RFC 9421 の署名だけにすると決まった（[ホスティングのモード](../design/hosting-modes.md)。2026-11-10）。今のスクリプトと Terraform はまだ mTLS の形（CSR、クライアント証明書、証明書のフィンガープリントの許可リスト）で、署名への切り替えは同じ文書の実装の順番の 5 から 7 で行う。それまでは、段階 0 と段階 4 を下の「移行の間の手順」で行う。今のスクリプトはカスタムドメインのモードだけに対応し、`workers.dev` のモードの入力は実装の順番の 8 で足す。

## 前提（ダッシュボードと 1Password での手作業）

ブートストラップの「前提」に挙げた手作業を先に済ませる。スクリプトはこれらを作らない。

1. ゾーンがまだなければ、対象のアカウントに追加し、ネームサーバーを切り替える。サービスのゾーンを使うときは、ブートストラップの前提のとおり、ゾーンの持ち主にゾーンの TLS の最小バージョンを確かめる。mTLS の撤去（実装の順番の 7）までは、ゾーンの managed CA にほかのホスト名の割り当てがないことも確かめる（ダッシュボードの SSL/TLS の「Client Certificates」でホスト名の一覧を見る。あれば段階 4b の apply が外してしまう）。IdP はゾーンのルールセットを持たないので、ルールの合意は要らない。
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
| 0 | `deployments/verification.tfvars.json.example` を写して `deployments/<デプロイの名前>.tfvars.json` を作り、値を埋める。管理者の許可リスト（署名に切り替えた後は `admin_signing_keys`、移行の間は `admin_client_certificates` と `admin_allowlist`）は空のままにする。PR でレビューしてマージする | アカウント ID がファイルにないこと。issuer と管理用のホスト名が、そのアカウントのゾーンの中にあり、互いに違うこと |
| 1 | `scripts/bootstrap-state-bucket.sh` を実行して state のバケットを作り、`scripts/bootstrap-d1.sh` を実行して D1 を作る | 両方のスクリプトが、`cf` の対象のアカウントが入力のものであることを確かめてから動くこと。D1 のスクリプトが production バックエンドであることを確かめて正常に終わること |
| 2 | `scripts/d1-migrate.sh` を実行する | マイグレーションが適用されること。本物の D1 でトリガーが更新と削除を拒否することは、[未決事項](../design/open-questions.md)の項目として確かめる |
| 3 | `scripts/generate-signing-key.sh` を実行する | 出力が公開鍵の JWK（`kid` を含む）だけであること。1Password のアイテムに `jwk`、`kid`、`public_jwk` があること |
| 4a | 管理者ごとに `scripts/generate-admin-key.sh <デプロイの名前> <管理者の名前>` を実行する。スクリプトは秘密鍵を 1Password に入れ、`keyid`、`name`、`public_key` の行を設定ファイルの `admin_signing_keys` に書く（mTLS の撤去までは CSR も書く。下の移行の間の手順）。前の設計で作った鍵があれば、新しく作らず、`--from-existing` を付けて、既存のアイテムの `public_key` と `public_key_sha256` だけを読んで行を書く（秘密鍵のフィールドは読まない）。設定ファイルの変更を PR でレビューしてマージする | 出力が公開鍵と `keyid` の行（新しく作ったときは CSR も）だけであること。秘密鍵が 1Password のアイテムにだけあること。`keyid` がアイテムの `public_key_sha256` と一致すること |
| 4b | `scripts/terraform.sh` で `init`、`plan`、`apply` の順に実行する。`apply` は Terraform が承認を求めるので、plan の内容を読んでから承認する | plan が、ゾーンのルールセット、ゾーンの設定、D1、DNS のレコード、mTLS の割り当て、クライアント証明書を含まないこと |
| 5 | 2 つの Worker の最初のデプロイを CI で行う（デプロイの workflow は別の作業） | ブートストラップの段階 5 の確認 |
| 5b | `scripts/upload-signing-key.sh` を実行する | 出力が `kid` だけで、段階 3 の `kid` と一致すること。JWKS にその `kid` が載ること |

- 段階 3、4a、5b のスクリプトは秘密を扱うので xtrace を付けずに動く。実行中の表示や出力に秘密が出たら、その鍵は漏れたものとして作り直す（[ブートストラップ](bootstrap.md)の失敗したとき）。
- 段階 3 と 4a のスクリプトは、同じ名前の 1Password のアイテムがあれば止まる。作り直すときだけ `--replace` を付け、古いアイテムをアーカイブさせる（削除はしない）。段階 4a の `--replace` は、その管理者のほかの `admin_signing_keys` の行も消すので、デプロイの後は古い鍵が使えなくなる。
- 段階 4a のスクリプトは、1Password に触れる前に設定ファイルの `admin_signing_keys` を確かめ、リストがない、形が違う、`keyid` が公開鍵の SHA-256 と食い違う、P-384 でない、`keyid` が重複する、のどれかなら止まる。新しいデプロイでは、段階 0 で空のリスト（`[]`）を書いておく。
- IdP の Terraform は、ゾーンのルールセット（WAF のカスタムルール、レート制限ルール、シングルリダイレクト）を持たないので、ゾーンにほかのルールがあっても段階 4b の `apply` は失敗せず、それらを変えない（[ドメインの置き場所](../design/domain-placement.md)の決定 ③）。
- Terraform はゾーン全体の設定（Always Use HTTPS と TLS の最小バージョン）を変えない。ゾーンの TLS の最小バージョンが 1.2 以上であることは、ゾーンの持ち主に確かめる。
- 前の形（`zone_singletons_owner` で IdP のルールを作った）で apply したデプロイでは、③ の後の最初の apply が、IdP が作ったゾーンのルールセット（WAF のカスタムルール、レート制限ルール、シングルリダイレクト）を削除する。plan で、削除されるのがそれらだけであることを確かめる。mTLS の割り当ては `moved` のブロックで同じものとして引き継ぎ、作り直さない。
- mTLS の撤去（実装の順番の 7）の後の最初の apply は、管理用のホスト名の mTLS の割り当てと、管理者ごとのクライアント証明書を削除する。apply は運用者が行い、plan で削除されるのがそれらだけであることを確かめる。署名に切り替えた管理用の Worker のデプロイ（実装の順番の 6）で、署名の `idpctl` が通ることを確かめた後に行う。
- 2 回目以降の Terraform の apply は CI で行う（[ブートストラップ](bootstrap.md)の実行する場所と認証情報）。

## 移行の間の手順

[ホスティングのモード](../design/hosting-modes.md)の実装の順番の 6 が main に入るまで、管理用の Worker は mTLS と証明書のフィンガープリントの許可リストで管理者を確かめる。そのときは、段階 4a と 4b を次の 4a、4b、4c で置き換える。今のスクリプトと Terraform は、この形で動く。

| 段階 | 運用者の操作 | 確かめること |
| --- | --- | --- |
| 4a | 管理者ごとに `scripts/generate-admin-key.sh <デプロイの名前> <管理者の名前>` を実行する。スクリプトは秘密鍵を 1Password に入れ、CSR を設定ファイルの `admin_client_certificates` に、`keyid`、`name`、`public_key` の行を `admin_signing_keys` に書く。設定ファイルの変更を PR でレビューしてマージする | 出力が CSR と、公開鍵と `keyid` の行だけであること。秘密鍵が 1Password のアイテムにだけあること |
| 4b | `scripts/terraform.sh` で `init`、`plan`、`apply` の順に実行する。`apply` は Terraform が承認を求めるので、plan の内容を読んでから承認する | plan が、管理者ごとのクライアント証明書と、管理用のホスト名の mTLS の割り当てだけを作ること。ゾーンのルールセット、ゾーンの設定、D1、DNS のレコードを含まないこと |
| 4c | `scripts/terraform.sh` の `output` で、管理者ごとの証明書とフィンガープリントを表示する。フィンガープリントと管理者の名前を設定ファイルの `admin_allowlist` に足し、PR でレビューしてマージする。証明書は `idpctl` の管理者が手元に置く | フィンガープリントが小文字の 16 進 64 文字であること |

- mTLS の割り当ては、ゾーンの managed CA に割り当てたホスト名の一覧を丸ごと持つ。管理用のホスト名のほかに割り当てがあると、段階 4b の `apply` がそれを外すので、plan で mTLS の割り当ての変更が管理用のホスト名の追加だけであることを確かめる。
- 段階 6 の管理者の確認は、証明書のない要求が `forbidden` になり、許可リストの証明書の要求が通ることで行う。
- 移行の間に作った P-384 の鍵は、署名に切り替えた後もそのまま使える。署名に切り替える前（実装の順番の 6 の前）に、`scripts/generate-admin-key.sh --from-existing <デプロイの名前> <管理者の名前>` で、まだ行のない鍵の行を `admin_signing_keys` に足しておく。行がないと、切り替えのデプロイの後にその管理者は締め出される。

## 未確認のこと

次は、`cf` と `op` を実際に動かして初めて確かめられる。最初の実行で確かめ、違えばスクリプトを直す。

- `cf workers secrets update` が、要求の本文を `--body @/dev/stdin` で標準入力から受け取り、`--type` と一緒に渡しても受け付けること（段階 5b）
- `cf d1 migrations apply` が、非対話の実行で確認を求めずに適用すること（段階 2）
- `cf accounts get` と `cf d1 get` が、`CLOUDFLARE_ACCOUNT_ID` のアカウントを対象にすること（[デプロイと設定](../design/deployment.md)の直書きの禁止）
- `op item create` が、標準入力から JSON のテンプレートを受け取ること（段階 3 と 4a。スクリプトは作った後に秘密でないフィールドを読み返して確かめる）
- Terraform の provider が返す `fingerprint_sha256` が、Workers の `certFingerprintSHA256` と同じ値であること（移行の間の段階 4c）
