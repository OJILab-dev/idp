# ブートストラップの実行手順（運用者向け）

[ブートストラップ](bootstrap.md)の段階 0〜5b を、リポジトリの Terraform（`infra/`）とスクリプト（`scripts/`）で実行するときの、運用者の操作の順番。順番と各段階で確かめることの設計はブートストラップに置き、このドキュメントはどのスクリプトをどの順に動かすかだけを書く。どのスクリプトも `--help` で使い方を表示する。

すべてのスクリプトは、第 1 引数にデプロイの名前（`deployments/<デプロイの名前>.tfvars.json` の `<デプロイの名前>`）を取る。アカウント ID は設定ファイルに書かず、1Password のアイテムから実行時に読む。

管理者の認証は、両方のホスティングのモードで RFC 9421 の署名だけにすると決まった（[ホスティングのモード](../design/hosting-modes.md)。2026-11-10）。管理用の Worker は実装の順番の 6 で署名だけで管理者を確かめるようになり、`admin_signing_keys` だけを読む。実装の順番の 7 で、スクリプトと Terraform からも mTLS の形（CSR、クライアント証明書、証明書のフィンガープリントの許可リスト）を外した。mTLS を使ったデプロイは一度もなかったので、移行の手順はない。実装の順番の 8 で、モードの入力（`hosting_mode` と `workers_dev_subdomain`）を足した。すべてのスクリプトと Terraform は、`hosting_mode` がない設定ファイル、知らないモード、モードで必須の入力がない設定ファイル、モードで禁止の入力が（値が空や `null` でも）ある設定ファイルで止まる。カスタムドメインのモードで作った既存の設定ファイルは、`"hosting_mode": "custom_domain"` を足すだけでよく、ほかの入力も Terraform の plan も変わらない。`workers.dev` のモードの手順を最後まで通すことは実装の順番の 9 で確かめる。

## 前提（ダッシュボードと 1Password での手作業）

ブートストラップの「前提」に挙げた手作業を先に済ませる。スクリプトはこれらを作らない。

1. ゾーンがまだなければ、対象のアカウントに追加し、ネームサーバーを切り替える。サービスのゾーンを使うときは、ブートストラップの前提のとおり、ゾーンの持ち主にゾーンの TLS の最小バージョンを確かめる。IdP はゾーンの managed CA の割り当ても持たないので、ゾーンの持ち主が mTLS を使っていても構わない。IdP はゾーンのルールセットを持たないので、ルールの合意は要らない。
2. R2 を有効にする。
3. API トークンを役割ごと（Terraform 用、デプロイ用、plan 用）に作り、state のバケット用の R2 の S3 互換の認証情報を作る。
4. 1Password の Vault（設定ファイルの `onepassword_vault`）に、設定ファイルの `onepassword_cloudflare_item` の名前でアイテムを作り、次のラベルのフィールドを置く。ラベルはスクリプトが決めた名前で、デプロイごとに変えない。
   - `account_id`：Cloudflare のアカウント ID
   - `terraform_api_token`：Terraform 用の API トークン
   - `r2_access_key_id` と `r2_secret_access_key`：state のバケットの R2 の認証情報
5. CI 用の 1Password Environment と GitHub Actions の destination を作る（下の「CI のデプロイの一度だけの準備」と[1Password Environments と GitHub Actions](secret.md)参照）。これは段階 5 の前までに済ませればよい。

## 手元の準備

1. リポジトリのルートで `mise install` と `pnpm install --frozen-lockfile` を実行し、mise が固定した Terraform と、`package.json` が固定した `cf` を入れる。`jq`、`openssl`（3.x）、`op` も使う。
2. `op` で 1Password にサインインする。
3. `pnpm exec cf auth login` を実行し、`cf` を認証する。エージェントにはさせない（[AGENT.md](../../AGENT.md) 参照）。

## 段階ごとの操作

| 段階 | 運用者の操作 | 確かめること |
| --- | --- | --- |
| 0 | モードに合わせて、カスタムドメインのモードは `deployments/verification.tfvars.json.example`、`workers.dev` のモードは `deployments/workers-dev.tfvars.json.example` を写して `deployments/<デプロイの名前>.tfvars.json` を作り、値を埋める。管理者の許可リスト（`admin_signing_keys`）は空のまま（`[]`）にする。PR でレビューしてマージする | アカウント ID がファイルにないこと。`hosting_mode` があること。カスタムドメインのモードでは、issuer と管理用のホスト名が、そのアカウントのゾーンの中にあり、互いに違い、`workers.dev` の下にないこと、`workers_dev_subdomain` がないこと。`workers.dev` のモードでは、`workers_dev_subdomain` がアカウントのサブドメインのラベルで、`zone`、`issuer_host`、`admin_host` がないこと（issuer は `https://idp.<workers_dev_subdomain>.workers.dev`、管理用のホスト名は `idp-admin.<workers_dev_subdomain>.workers.dev` に導かれる）。廃止した入力（`admin_allowlist`、`admin_client_certificates`、`zone_singletons_owner`）がないこと（あれば、どのスクリプトも Terraform も止まる） |
| 1 | `scripts/bootstrap-state-bucket.sh` を実行して state のバケットを作り、`scripts/bootstrap-d1.sh` を実行して D1 を作る | 両方のスクリプトが、`cf` の対象のアカウントが入力のものであることを確かめてから動くこと。D1 のスクリプトが production バックエンドであることを確かめて正常に終わること |
| 2 | `scripts/d1-migrate.sh` を実行する | マイグレーションが適用されること。本物の D1 でトリガーが更新と削除を拒否することは、[未決事項](../design/open-questions.md)の項目として確かめる |
| 3 | `scripts/generate-signing-key.sh` を実行する | 出力が公開鍵の JWK（`kid` を含む）だけであること。1Password のアイテムに `jwk`、`kid`、`public_jwk` があること |
| 4a | 管理者ごとに `scripts/generate-admin-key.sh <デプロイの名前> <管理者の名前>` を実行する。スクリプトは秘密鍵を 1Password に入れ、`keyid`、`name`、`public_key` の行を設定ファイルの `admin_signing_keys` に書く。CSR は作らない。前の設計で作った鍵があれば、新しく作らず、`--from-existing` を付けて、既存のアイテムの `public_key` と `public_key_sha256` だけを読んで行を書く（秘密鍵のフィールドは読まない。前の設計のアイテムに残る `csr` のフィールドは使わない）。設定ファイルの変更を PR でレビューしてマージする | 出力が公開鍵と `keyid` の行だけであること。秘密鍵が 1Password のアイテムにだけあること。`keyid` がアイテムの `public_key_sha256` と一致すること |
| 4b | `scripts/terraform.sh` で `init`、`plan`、`apply` の順に実行する。`apply` は Terraform が承認を求めるので、plan の内容を読んでから承認する。`workers.dev` のモードでは、`plan` と `apply` が Terraform を動かす前に、アカウントの `workers.dev` のサブドメインを Cloudflare API で読み、`workers_dev_subdomain` と違えば止まる | plan が資源を何も作らず、変えないこと（今の `infra/` は、カスタムドメインのモードではゾーンを引く data source と入力の検証だけを、`workers.dev` のモードでは入力の検証だけを持つ）。ゾーンのルールセット、ゾーンの設定、D1、DNS のレコード、mTLS の割り当て、クライアント証明書を含まないこと |
| 5 | 下の「CI のデプロイの一度だけの準備」を済ませ、Actions の **Deploy** を main から手動で起動する。デプロイの名前を選び、「署名鍵の前」（`before_signing_key`）を有効にする | Terraform の apply、マイグレーション、IdP の Worker、管理用の Worker の順に成功し、最後の確認が通ること（IdP の Worker は署名鍵がないので discovery に 500 を返し、管理用の Worker は署名のない要求に `forbidden` を返す）。ブートストラップの段階 5 の確認 |
| 5b | `scripts/upload-signing-key.sh` を実行する。その後、**Deploy** を「署名鍵の前」なしでもう一度手動で起動する | 出力が `kid` だけで、段階 3 の `kid` と一致すること。JWKS にその `kid` が載ること。2 回目のデプロイの最後の確認（discovery と JWKS、平文の HTTP の 308 と 404、管理用の Worker の `forbidden`）がすべて通ること |

- 段階 3、4a、5b のスクリプトは秘密を扱うので xtrace を付けずに動く。実行中の表示や出力に秘密が出たら、その鍵は漏れたものとして作り直す（[ブートストラップ](bootstrap.md)の失敗したとき）。
- 段階 3 と 4a のスクリプトは、同じ名前の 1Password のアイテムがあれば止まる。作り直すときだけ `--replace` を付け、古いアイテムをアーカイブさせる（削除はしない）。段階 4a の `--replace` は、その管理者のほかの `admin_signing_keys` の行も消すので、デプロイの後は古い鍵が使えなくなる。
- 段階 4a のスクリプトは、1Password に触れる前に設定ファイルの `admin_signing_keys` を確かめ、リストがない、形が違う、`keyid` が公開鍵の SHA-256 と食い違う、P-384 でない、`keyid` が重複する、のどれかなら止まる。新しいデプロイでは、段階 0 で空のリスト（`[]`）を書いておく。空のリストを受け付けるのは、最初の行を書く段階 4a のスクリプトだけで、段階 4b の Terraform の変数と、管理用の Worker の `cloudflare.config.ts` と、管理用の Worker 自身は、空のリストを拒否する。空のリストのまま段階 4b に進むと plan が止まる。
- IdP の Terraform は、ゾーンのルールセット（WAF のカスタムルール、レート制限ルール、シングルリダイレクト）を持たないので、ゾーンにほかのルールがあっても段階 4b の `apply` は失敗せず、それらを変えない（[ドメインの置き場所](../design/domain-placement.md)の決定 ③）。
- Terraform はゾーン全体の設定（Always Use HTTPS と TLS の最小バージョン）を変えない。ゾーンの TLS の最小バージョンが 1.2 以上であることは、ゾーンの持ち主に確かめる。
- 前の形（`zone_singletons_owner` で IdP のルールを作った）で apply したデプロイでは、③ の後の最初の apply が、IdP が作ったゾーンのルールセット（WAF のカスタムルール、レート制限ルール、シングルリダイレクト）を削除する。plan で、削除されるのがそれらだけであることを確かめる。
- mTLS の撤去（実装の順番の 7）は、どのデプロイも mTLS の割り当てとクライアント証明書を apply する前に入ったので、証明書を消す apply はない。Terraform の `removed` のブロックも置いていない。万一、撤去の前のコミットで apply した state があれば、次の apply が管理用のホスト名の mTLS の割り当てとクライアント証明書を削除する。そのときは運用者が apply し、plan で削除されるのがそれらだけであることを確かめる。
- 段階 2 の `scripts/d1-migrate.sh` は `0004` も適用する。`0004` は、署名に切り替えた管理用の Worker と同じデプロイ（段階 5）の前にだけ適用し、署名の前の管理用の Worker が動いているデプロイに先に適用しない。段階 2 と段階 5 の間に管理用の Worker はまだないか、管理操作を送らないので、間が空いても害はない。
- 管理者が締め出されたら、管理用の Worker を戻さず、許可リストの行か鍵を PR で直してデプロイし直す。`0004` の後に署名の前の管理用の Worker へ戻すと、管理操作の書き込みがすべて失敗する。`0004` より前からあるデプロイで戻すことがどうしても避けられないときは、先に break-glass で `0004` のトリガーを外す（[ブートストラップ](bootstrap.md)の失敗したとき）。
- `workers.dev` のモードでは、アカウントの `workers.dev` のサブドメインが `workers_dev_subdomain` と一致することを、CI のデプロイが毎回、何かを変える前に確かめる（`scripts/terraform.sh --ci` は Terraform 用のトークンで apply の前に、`scripts/deploy.sh --ci` はデプロイ用のトークンで `cf deploy` の前に）。違えば何も変えずに止まる。手元では、運用者が `scripts/check-workers-dev-subdomain.sh <デプロイの名前>` で同じ確認をできる。手元で読むのは Vault のアイテムの Terraform 用のトークンで、`workers.dev` のモードでは、このトークンにゾーンの権限を持たせず、アカウントの `Workers Scripts Read` を持たせる（[デプロイと設定](../design/deployment.md)の API トークン）。アカウントにサブドメインがなければ止まるので、前提のとおりダッシュボードで先に作る。`curl` は 8.3 以降を使う（トークンを引数に出さずに環境変数から読むため）。
- 2 回目以降の Terraform の apply は CI で行う（[ブートストラップ](bootstrap.md)の実行する場所と認証情報）。

- 段階 6 の管理者の確認は、[ブートストラップ](bootstrap.md)の段階 6 のとおり署名で行う（署名のない要求が `forbidden` になり、許可リストの鍵で署名した `idpctl` の要求が通る）。`idpctl` にクライアント証明書は渡さない（`--cert` は使い方の誤りになる）。
- 前の設計で作った P-384 の鍵は、署名でもそのまま使える。最初のデプロイの前に、`scripts/generate-admin-key.sh --from-existing <デプロイの名前> <管理者の名前>` で、まだ行のない鍵の行を `admin_signing_keys` に足しておく。行がないと、そのデプロイの後にその管理者は締め出される。リストが空なら、Terraform の変数と管理用の Worker の設定の組み立てが止まる。
- `scripts/terraform.sh` の `output` は外した。Terraform に秘密でない出力も含めて出力がなくなったため（以前は証明書とフィンガープリントを表示していた）。

## CI のデプロイ（段階 5 以降）

段階 5 以降の Terraform の apply、マイグレーション、2 つの Worker のデプロイは、すべて `.github/workflows/deploy.yml` が行う。流れと確かめることの設計は[デプロイと設定](../design/deployment.md)の「デプロイのパイプライン」に置く。

- main への push で、`IDP_DEPLOYMENT` にあるすべてのデプロイが、その 1 つのコミットから動く。手動の起動（main からだけ）は、そのうちの 1 つだけを動かし、段階 5 では「署名鍵の前」を付ける。
- 順番は、Terraform の `init` と `apply`（`scripts/terraform.sh --ci`）、入力の検証、2 つの Worker のビルド、D1 のマイグレーション（`0004` を含む）、IdP の Worker、管理用の Worker、外からの確認で、最初の失敗で止まる。
- 外からの確認が失敗したときは、2 つの Worker はすでにデプロイされている。どちらの Worker も、確かめた振る舞いが崩れても、要求を処理せずに拒否する側に倒れる。原因を直して main にもう一度マージする。
- `custom_domain` で、平文の HTTP に 301 が返って確認が失敗したときは、ゾーンの「Always Use HTTPS」かリダイレクトのルールが IdP の Worker より先に答えている。IdP はゾーンの設定を持たないので、ゾーンの持ち主と相談する（そのルールは、資格情報を持つ平文の要求も https へ送り直させる）。
- `IDP_DEPLOYMENT` を空にすると、workflow は認証情報を使う job を含めて何も動かさない。デプロイを止めたいときも、こうする。
- デプロイの job は、そのコミットが今の main の先頭でなければ、認証情報を読む前に止まる（続けてマージしたときの古い実行と、古い実行の再実行）。その失敗は正常で、新しい実行がデプロイする。前の版に戻したいときは、古い実行を再実行せず、戻す変更を PR でマージする。
- 手元で動かすスクリプト（`scripts/terraform.sh`、`scripts/deploy.sh`、ほかのブートストラップのスクリプト）は xtrace で動くので、表示にアカウント ID が出る（`IDP_ACCOUNT_ID`、`AWS_ENDPOINT_URL_S3`、`CLOUDFLARE_ACCOUNT_ID` の代入）。秘密ではないが、手元の表示は隠されないので、公開の場所に貼らない。隠すのは CI の記録だけ。

### CI のデプロイの一度だけの準備

デプロイごとに次を行う。値（アカウント ID、トークン、ID）はリポジトリにも、この手順の外のファイルにも書かない。

1. デプロイの設定ファイル（`deployments/<デプロイの名前>.tfvars.json`）が段階 0 と 4a のとおり main にあること。`github_deploy_environment` は英数字、`_`、`-` だけにする。
2. GitHub のリポジトリの設定で、`github_deploy_environment` の名前の GitHub Environment を作り、デプロイできるブランチを `main` だけにする。
3. 1Password に、`onepassword_deploy_environment` の名前の Environment を作り、次の変数を置く。
   - `CLOUDFLARE_ACCOUNT_ID`：デプロイ先のアカウント ID（1Password のアイテムの `account_id` と同じ値）
   - `DEPLOY_CLOUDFLARE_API_TOKEN`：デプロイ用の API トークン（[デプロイと設定](../design/deployment.md)の API トークン。`workers_dev` では、アカウントの `workers.dev` のサブドメインを読める権限も要る）
   - `TERRAFORM_CLOUDFLARE_API_TOKEN`：Terraform 用の API トークン
   - `R2_ACCESS_KEY_ID` と `R2_SECRET_ACCESS_KEY`：state のバケットの R2 の認証情報
4. その Environment に GitHub Actions の destination を作り、このリポジトリ、workflow のパス `.github/workflows/deploy.yml`、ブランチ `main`、手順 2 の GitHub Environment に限る（OIDC の信頼の条件。[1Password Environments と GitHub Actions](secret.md)）。
5. デプロイが 1 つなら、`setup-1password-integration.sh` で `OP_WORKLOAD_ID`、`OP_ENVIRONMENT_ID`、`OP_INTEGRATION_KEY` をリポジトリに登録する。デプロイが 2 つ以上なら、デプロイごとの値を、手順 2 の GitHub Environment の変数と secret として同じ名前で置く（GitHub Environment のものがリポジトリのものより優先される）。
6. 段階 5 の直前に、リポジトリの変数 `IDP_DEPLOYMENT` にデプロイの名前を足す（空白で区切って並べる）。手動の起動も `IDP_DEPLOYMENT` にあるデプロイしか選べない。足した後の main への push からは、そのデプロイも動く。段階 5 と 5b の間に main へマージすると、署名鍵がないので外からの確認で失敗する（デプロイそのものは済み、Worker は要求を拒否するだけ）ので、その間はマージしない。

## 未確認のこと

次は、`cf` と `op` を実際に動かして初めて確かめられる。最初の実行で確かめ、違えばスクリプトを直す。

- `cf workers secrets update` が、要求の本文を `--body @/dev/stdin` で標準入力から受け取り、`--type` と一緒に渡しても受け付けること（段階 5b）
- `cf d1 migrations apply` が、非対話の実行で確認を求めずに適用すること（段階 2）
- `cf accounts get` と `cf d1 get` が、`CLOUDFLARE_ACCOUNT_ID` のアカウントを対象にすること（[デプロイと設定](../design/deployment.md)の直書きの禁止）
- `op item create` が、標準入力から JSON のテンプレートを受け取ること（段階 3 と 4a。スクリプトは作った後に秘密でないフィールドを読み返して確かめる）
- `cf build` と `cf deploy --prebuilt --message` が、それぞれの Worker のディレクトリで、宣言した Vite plugin でビルドし、ビルドの成果物と静的なページをそのまま上げること（段階 5。手元では Vite plugin 自身のビルドで、2 つの Worker の成果物と設定が期待どおりになることだけを確かめた）
- `cf workers get <Worker の名前>` の応答の `subdomain.enabled` と `subdomain.previews_enabled` が、`workers.dev` とプレビューの URL の有効と無効を表すこと（段階 5 の外からの確認）
- `IDP` の Service Binding の `exportName` が、名前付きのエントリーポイントへのバインディングとして API に届き、IdP の Worker の最初のデプロイの直後から解決すること（段階 5）
- デプロイ用のトークン（Workers の編集の権限）で、Cloudflare API の「Get a Workers Subdomain」を読めること（`workers.dev` のモードの CI のデプロイ）
- `workers.dev` が平文の HTTP の要求を Worker に届けるか、自分で https へリダイレクトするか（`workers.dev` のモードの外からの確認は、どちらも受け付けて、どちらが答えたかを記録する）
- 1Password の `load-secrets-action` が、Workload Identity と `export-env: false` で、Environment の変数を変数と同じ名前の step の出力として出すこと（Terraform とデプロイの step が、役割の名前の出力を道具の読む名前に写す）
- `pnpm install --ignore-scripts` の後の `cf build` が、Takumi Runner でも成功すること（手元では Vite plugin 自身のビルドで確かめた）
- GitHub Environment の変数と secret（`OP_WORKLOAD_ID`、`OP_ENVIRONMENT_ID`、`OP_INTEGRATION_KEY`）が、デプロイが 2 つ以上のときに、リポジトリのものより優先されること
- Takumi Runner に、`curl` 8.3 以降、`git`、`openssl` があること（`jq` と Terraform は mise が入れる）
- Worker Secret（署名鍵）が、`cf deploy --prebuilt` の後も残ること（段階 5b の後のデプロイ）