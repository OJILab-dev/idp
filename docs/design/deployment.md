# デプロイと設定

ホスト名などのデプロイ先に依存する値は、コードにも設計書にも書かず、デプロイごとの設定として与える。同じ実装をどのドメイン・どのアカウントにも置けるようにする。

**アカウントの移植性**

最初のデプロイは、検証用のアカウントに置く。これは最終的なアカウントではない。本番は、IdP 専用の別の Cloudflare アカウントに、同じ構成を作り直して置く。そのため、構成の全体を、下の「デプロイごとの入力」を変えるだけで、別のアカウントに同じ形で再現できるようにする。

- 検証用のアカウントの名前と、どのアカウントの ID も、リポジトリに書かない。リポジトリは公開しているため。ドキュメントでは「検証用のアカウント」とだけ呼ぶ。
- 移植性は「同じ構成」を意味し、「同じデータ」を意味しない。新しいアカウントには、新しい D1、新しい署名鍵、新しい管理者の証明書を作る。issuer と RP ID が変わるので、利用者はパスキーを登録し直す（下の「ホスト名を変えるときの影響」を参照）。アカウントの間でデータ（D1 の行、署名鍵、証明書）を移すことは、この設計の範囲外とする。
- 検証用のアカウントは、IdP 専用とは限らない。そこで行うのは検証だけで、本物の利用者のデータを置かない。IdP 専用のアカウントに置く理由（下の「Cloudflare アカウント」）は、本番のアカウントで満たす。
- 移植できることは、本番の前に、入力だけを使って 2 つ目のアカウントにブートストラップを最後まで通して確かめる（[未決事項](open-questions.md)参照）。

**デプロイごとの入力**

デプロイごとに変えてよいのは、次の入力だけとする。これ以外の値（リソースの構成、権限の範囲、手順、コード）は、すべてのデプロイで同じにする。入力が増えるときは、この表を先に更新する。

| 入力 | 置き場所 | 使うもの |
| --- | --- | --- |
| Cloudflare のアカウント ID | 1Password（CI は Environment の `CLOUDFLARE_ACCOUNT_ID`、手元は Vault のアイテム）。リポジトリには置かない | Terraform、`cf` のスクリプト、CI、R2 の backend の endpoint |
| ゾーン（ドメイン） | デプロイの設定ファイル | Terraform（ゾーン ID はここから引く） |
| issuer のホスト名 | デプロイの設定ファイル | IdP の Worker の `cloudflare.config.ts`（カスタムドメイン）、IdP の Worker と管理用の Worker の環境変数 |
| 管理用のホスト名 | デプロイの設定ファイル | 管理用の Worker の `cloudflare.config.ts`（カスタムドメイン）、Terraform（mTLS、WAF）、管理用の Worker の環境変数 |
| D1 のデータベースの名前 | デプロイの設定ファイル | `cf` のスクリプト（ID は名前から引く） |
| Terraform の state を置く R2 のバケットの名前 | デプロイの設定ファイル | `cf` のスクリプト（作成）、`terraform init` の backend の設定 |
| 1Password の Environment と Vault のアイテムの名前 | デプロイの設定ファイル | 生成スクリプト、Secret の登録スクリプト、手元の Terraform、1Password の連携のスクリプト |
| GitHub Environment の名前（デプロイ用と plan 用） | デプロイの設定ファイル | CI の workflow、1Password の destination の条件 |
| 管理者の証明書のフィンガープリントの許可リスト | デプロイの設定ファイル | 管理用の Worker の設定 |

- デプロイの設定ファイルは、デプロイごとに 1 つ、`deployments/<デプロイの名前>.tfvars.json` に置く。秘密を含まない値だけを書く。Terraform は `-var-file` で読み、`cf` のスクリプトと CI も同じファイルを読む。同じ値を 2 か所に持たないため。
- アカウント ID だけは設定ファイルに書かず、1Password から実行時に環境変数で受け取る。公開リポジトリにアカウント ID を残さないため。ゾーン、ホスト名、許可リストは、DNS、discovery、証明書で外から見える値なので、設定ファイルに書いてよい。
- CI が使うデプロイは、GitHub のリポジトリの変数 `IDP_DEPLOYMENT`（デプロイの名前）で選ぶ。workflow の最初の job が設定ファイルを読み、GitHub Environment の名前を後の job に渡す。
- 入力から導ける値は入力にしない。ゾーン ID は Terraform がゾーンの名前から引く。D1 の ID は、ブートストラップとデプロイのスクリプトが名前から引き、Worker のバインディングに渡す。R2 の backend の endpoint はアカウント ID から組み立てる。1Password の Workload ID と Environment ID は、1Password の連携のスクリプトが GitHub の変数に登録する。どれも人が手で書き写さない。
- 設定ファイルが入力のどれかを欠いていたら、Terraform、スクリプト、CI は処理を始めずに止まる（fail-closed）。既定値で補わない。

**直書きの禁止**

- アカウント ID、ゾーン ID、D1 のデータベースの ID、ホスト名、証明書のフィンガープリントを、Terraform、スクリプト、CI の workflow、Worker のコード、ドキュメントに直接書かない。値はすべて上の入力から受け取るか、入力から引く。ドキュメントでは `<ホスト名>` のような置き換えの印で書く。
- スクリプトの `cf` の呼び出しは、すべて対象のアカウントを明示する。運用者の `cf auth login` のセッションは、複数のアカウントにまたがりうるため。`cf` 1.0.0-beta.21 のグローバルフラグには、アカウントを指定するものがない（`cf --help` の Global flags にあるのは `--zone` や `--profile` など）。そのため、スクリプトは呼び出しごとに入力のアカウント ID を `CLOUDFLARE_ACCOUNT_ID` に設定し、変更を加える前に、対象のアカウントが入力のものであることを確かめる。手元の `cf` のセッションがこの環境変数に従うかは、実装の前に確かめる（[未決事項](open-questions.md)参照）。従わなければ、アカウントごとの `--profile` か Cloudflare API のスクリプトにする。

**設定値**

- issuer の URL を 1 つの設定値（Worker の環境変数）として持つ。形式は `https://<ホスト名>` で、パス、クエリ、フラグメント、末尾のスラッシュは付けない。
- RP ID、WebAuthn の origin、discovery に載せる各エンドポイントの URL、アクセストークンの `aud` は、すべて issuer から導く。別々の設定値として持たない（値の食い違いを構造的に起こさないため）。
- 管理用の Worker も同じ issuer を設定として持ち、登録リンク（`/enroll#<token>`）の組み立てに使う。管理用のホスト名は、issuer とは別の設定値として持つ。
- リクエストの `Host` ヘッダーから issuer や origin を作らない。`Host` は送信側が自由に書き換えられるため。
- issuer が未設定、または形式が不正（`https` でない、パスが付いている、ホストが IP アドレスなど）なら、リクエストを処理せずエラーを返す（fail-closed）。

**デプロイの道具**

- 最初の構築の順番は[ブートストラップ](../deployment/bootstrap.md)にまとめる。
- Worker のデプロイ、D1 のデータベースの作成とマイグレーション、break-glass の D1 の操作は、すべて Cloudflare の `cf` CLI で行う。wrangler はどこにも使わない。`cf` は Worker のデプロイ（`cf deploy`。Cloudflare「Deploy your first Worker」）と D1 のマイグレーション（`cf d1 migrations apply`。Cloudflare「Wrangler to cf reference」）を挙げている。
- `cf` は自分でバンドラーを動かさず、フレームワークのコマンドか、`package.json` で宣言した Cloudflare のビルドツールを実行する。ビルドツールは Cloudflare Vite plugin 2.0 beta（`@cloudflare/vite-plugin@beta`）で、Wrangler に依存しない。Vite plugin を宣言していないときだけ Wrangler でビルドする（Cloudflare「Develop, build, and deploy」の「How `cf` runs your project」）。また、`wrangler.jsonc`、`wrangler.json`、`wrangler.toml` のあるプロジェクトでは `cf deploy` を実行してはいけない（Cloudflare「Deploy your first Worker」の「Start from an existing project」）。
- そのため、2 つの Worker はどちらも `@cloudflare/vite-plugin@beta` を宣言し、wrangler を依存に宣言せず、`wrangler.*` の設定ファイルを置かない。`cf migrate` の Wrangler bundler も使わない。
- `cf` にドキュメント化されたコマンドがない操作は、Cloudflare API かダッシュボードで行い、wrangler で補わない。`cf` で足りるかどうかを実装の前に確かめる項目は[未決事項](open-questions.md)にまとめる。
- `cf` はベータで、コマンドが安定版の前に変わりうる（Cloudflare「Cloudflare CLI」）。
- CI では `cf` が `CLOUDFLARE_API_TOKEN` と `CLOUDFLARE_ACCOUNT_ID` を読む（Cloudflare「Use cf in CI」の「Provide credentials」）。

**Terraform とスクリプトの分担**

基盤はできるだけコードで持つ（IaC）。宣言できるものは Terraform に、手続きでしか表せないものは `cf` を使うシェルスクリプトに置き、手作業の手順を残さない。例外は、ダッシュボードでしかできない操作と認証情報を作る操作だけで、[ブートストラップ](../deployment/bootstrap.md)の前提に列挙する。望む状態を宣言し、実際の状態をそれに合わせ続ける形にするため（[宣言とリコンシリエーション](../philosophy/system-design/declarative-and-reconciliation.md)）。

- Terraform（Cloudflare provider）が持つもの：DNS（Worker のカスタムドメインが作るレコードを除く）、WAF のカスタムルール（mTLS）、レート制限ルール、管理用のホスト名への mTLS の割り当て、CSR から発行するクライアント証明書、fail closed の設定。
- Worker のカスタムドメインは、それぞれの Worker の `cloudflare.config.ts`（`worker.domains`）が持ち、`cf deploy` が Worker と一緒に付ける（Cloudflare「Cloudflare config」）。`workers.dev` とプレビューの URL の無効化（`workersDev`、`previewUrls`）も同じファイルで宣言する。Terraform と `cf` の両方がカスタムドメインを持つと、片方の変更をもう片方が戻しうる。また、Terraform に持たせると、最初の apply がまだない Worker にドメインを付けることになる。カスタムドメインは、Cloudflare が DNS のレコードと証明書を作るので、Terraform はそのホスト名の DNS のレコードを持たない。ホスト名の値はデプロイの設定ファイルから渡し、`cloudflare.config.ts` に書かない。
- `cf` のシェルスクリプトが持つもの：D1 のデータベースの作成、D1 のマイグレーション、Worker のデプロイ、Worker Secret の登録、D1 が production バックエンドにあることの確認、鍵の生成、Terraform の state を置く R2 のバケットの作成。
- D1 のデータベースを Terraform に置かないのは、plan の認証情報に D1 の権限を一切持たせないため（下の PR の `terraform plan` の認証情報を参照）。provider の `cloudflare_d1_database` は `D1 Read` か `D1 Write` の権限を要し（Terraform Cloudflare provider「cloudflare_d1_database」の Accepted Permissions）、`terraform plan` は既定で既存のリソースの現状を読む（HashiCorp「terraform plan」の Introduction）。Terraform に D1 のデータベースがあると、plan のトークンに D1 の権限が要る。D1 のデータベースは作った後に変えるものがほとんどなく、宣言で持つ利点も小さい。
- Terraform には秘密を渡さない。state は入力の値を保存するため。証明書と CSR は秘密ではないので Terraform に渡してよい。
- Terraform のバージョンは mise で固定し、provider のバージョンは `.terraform.lock.hcl` で固定する。
- state は、デプロイ先のアカウントの R2 に、S3 互換の backend で置く（Cloudflare「Remote R2 backend」）。state のバケットは Terraform より先に必要なので、`cf` のスクリプトで最初に作る。R2 の認証情報は 1Password Environments で CI に渡す（[1Password Environments と GitHub Actions](../deployment/secret.md)参照）。
- state はデプロイごとに分け、アカウントをまたいで共有しない。backend のブロックには変数を使えないので、バケットの名前と endpoint（アカウント ID から組み立てる）は、`terraform init` の `-backend-config` で、デプロイの入力から渡す。backend のブロックに値を書かない。
- Terraform のコードは、上の「デプロイごとの入力」を変数として受け取り、アカウント ID、ゾーン ID、ホスト名を `.tf` のファイルに書かない。ゾーン ID は data source でゾーンの名前から引く。
- provider がどのリソースに対応しているか（mTLS のホスト名の割り当て、fail closed の設定など）は、実装の前に確かめる（[未決事項](open-questions.md)参照）。対応していないものは、`cf` か Cloudflare API のスクリプトにし、wrangler では補わない。

**シェルスクリプトの規則**

- スクリプトは `#!/usr/bin/env bash` と `set -euxo pipefail` で始める。
- 例外として、秘密を扱うスクリプト（鍵の生成、Worker Secret の登録、break-glass の操作）は `set -euo pipefail` にし、`-x` を付けない。xtrace は展開した後の秘密の値をそのまま表示するため。この例外と理由は、そのスクリプトの先頭のコメントに書く。[AGENT.md](../../AGENT.md) には書かない（スクリプトごとの例外なので、例外を持つスクリプトの中に置く）。

**鍵と秘密の生成スクリプト**

鍵と秘密（署名鍵、管理者の mTLS の秘密鍵）は、必ずリポジトリのレビュー済みの生成スクリプトで生成する。手で生成すると、手順のずれが鍵ごとに積み重なり、それが最も危険なため。

- スクリプトを通せば、人が実行してもエージェント（AI）が実行しても結果は変わらない。そのため、実行する主体は限らない。
- 秘密を AI のコンテキストに入れてはいけない、という規則は変わらない。スクリプトは秘密を標準出力に出さない。
- 生成スクリプトは `op` を必須にし、生成した鍵を 1Password のアイテムと Worker Secret に直接パイプで渡す。平文をディスクに書かない。
- `kid`（RFC 7638）はスクリプトが自分で計算する。
- 出力するのは秘密でない値（`kid`、公開鍵、証明書のフィンガープリント、CSR）だけにする。

**デプロイのパイプライン**

- PR：lint、テスト、`terraform plan` を流し、plan の出力を PR に載せる。apply はしない。
- main へのマージ：その 1 つのコミットから、`terraform apply`、`cf` のスクリプトによる D1 のマイグレーション、IdP の Worker の `cf deploy`、管理用の Worker の `cf deploy` の順に流し、最初の失敗で止める。
- 手動の承認は置かない。apply とデプロイは main へのマージで自動で走る。デプロイは管理者のフィンガープリントの許可リストも変えるので、main のブランチのルールセット（PR のレビューとマージの権限）が、管理者の権限と基盤の変更の唯一の関門になる（[操作とリスク](operations-and-risks.md)参照）。
- 2 つの Worker は別々に切り替わるので、マイグレーションは expand / contract にする。新しいマイグレーションは、古いコードと新しいコードの両方で動く形にし、古い形を消すのは、両方の Worker が新しいコードになった後の別のマイグレーションで行う。
- ロールバック：Worker は前のバージョンに戻す。Cloudflare のドキュメントは、ロールバックをダッシュボードと Wrangler の `wrangler rollback` でしか説明していない（Cloudflare「Rollbacks」）。`cf` か Cloudflare API でできるかは実装の前に確かめる（[未決事項](open-questions.md)参照）。ロールバックはバインディング先の D1 を変えない（同じページの「Bindings」）。D1 は Time Travel で戻す。
- 依存の取得は、Takumi Guard の下で、バージョンを固定した pnpm のセットアップの Action と `pnpm install --frozen-lockfile` で行う。Takumi Guard が pnpm に対応していることは利用者が確認済みで、セットアップの Action の実装で改めて確かめる。
- `examples/github-actions/deploy.yml` は、今は npm の雛形のままで、pnpm、`cf`、Terraform の上の流れに作り直すのは実装の作業にする。

**PR の `terraform plan` の認証情報（例外）**

[1Password Environments と GitHub Actions](../deployment/secret.md) は、PR の検証の job に OIDC の権限も 1Password の認証情報も渡さないとしている。`terraform plan` は state と Cloudflare の現状を読むので、認証情報なしでは動かない。

- 例外として、plan の job にだけ、読み取り専用の Environment（plan 用の読み取り専用の API トークンと、state のバケットの読み取り専用の R2 の認証情報）を渡す。デプロイ用の Environment とは分ける。
- plan 用のトークンは、Terraform が持つもの（DNS、WAF、SSL と証明書、mTLS の割り当て、fail closed の設定など）の読み取りだけにし、D1 の権限は読み取りも含めて一切持たせない。Cloudflare API の D1 のクエリ（「Query D1 Database」と「Raw D1 Database Query」）は `D1 Read` の権限でも受け付けると書かれていて（それぞれの Accepted Permissions）、`D1 Read` があればユーザーのデータを読める可能性があるため（どこまでできるかは[未決事項](open-questions.md)で確かめる）。
- destination は、plan の workflow と、同じリポジトリのブランチからの `pull_request` のイベントに限り、GitHub Environment `production` は使わない。fork からの PR には渡さない。
- 理由：plan を PR に載せることで、基盤の変更をマージの前にレビューでき、手動の承認を置かない流れでの唯一の関門（PR のレビュー）を意味のあるものにするため。
- 残るリスク：読み取り専用なので、トークンが漏れても変更はできない。残るのは、そのトークンの範囲で読めるものの機密性。workflow の path を固定しても、そのトークンで何が動くかは限れない。同じリポジトリの PR は、plan の workflow も Terraform のコードも書き換えられ、Terraform は plan の時点でもコード（provider や data source）を動かすので、トークンを持ち出せる。そのため、範囲を読まれても困らないもの（基盤の設定）に絞り、D1 を外す。
- 1Password の destination で PR のイベントに限れるかは、実装の前に確かめる（[未決事項](open-questions.md)参照）。限れなければ、plan を PR に載せるのをやめ、main での apply の前の plan だけにする。

**API トークン**

- 役割ごとに分ける。どれもデプロイ先のアカウントに限り、アカウントごとに別のトークンを作る。
  - Terraform 用：DNS、WAF、SSL と証明書、fail closed の設定に要る Workers のルート。D1 の権限は持たせない。
  - デプロイ用：Workers の編集、Worker のカスタムドメインを付けるためのゾーンの Workers のルートの編集と DNS の編集、マイグレーションのための D1 の編集。必要な権限の正確な名前は、実装で `cf deploy` が成功する最小の組み合わせを確かめて記録する。
  - plan 用（上の例外）：Terraform 用と同じ範囲の読み取りだけ。D1 の権限は読み取りも持たせない。
- D1 のデータベースの作成は、最初の構築のときだけ、運用者の手元の `cf` のセッションで行う（[ブートストラップ](../deployment/bootstrap.md)の段階 1）。CI のトークンには D1 の作成の権限を持たせない。
- どれも 1Password Environments と GitHub OIDC で、実行時に CI に渡す。
- break-glass 用の D1 のトークン（下記）は、範囲（IdP の D1 の編集）と短い有効期限を定めておくが、前もって作らない。

**ホスト名を変えるときの影響**

ホスト名はデプロイごとに決める値で、設定を変えれば別のホスト名で動かせる。ただし、運用を始めた後に変えると、次のことが仕様上避けられない。

- パスキーは RP ID（ホスト名）に紐付くので、全員がパスキーを登録し直す必要がある。
- `iss` が変わるので、RP からは別の IdP に見える。RP 側の設定と利用者の紐付けを移行する必要がある。ledger などの結合キー（`iss` + `sub`）も変わる。

そのため、本番のホスト名は最初のデプロイの前に決め、以後は変えない前提で運用する。

別のアカウントに作り直すときも、issuer のホスト名が変わるので、同じことが起きる。検証用のアカウントで登録したパスキー、RP の設定、`iss` + `sub` の紐付けは、本番のアカウントに引き継がない（上の「アカウントの移植性」を参照）。

**Cloudflare アカウント**

- IdP の Worker と D1 は、IdP 専用の Cloudflare アカウントに置く。D1 の API トークンの権限は特定のデータベースに絞れず、アカウント内のすべての D1 に効くため。アカウントを分ければ、IdP のトークンが漏れても影響は IdP に限られ、他のサービスのトークンで IdP のデータを書き換えられることもない。
- クライアント証明書はアカウント単位の CA で検証され、同じアカウントのどのゾーンで発行した証明書も、mTLS を有効にしたホストで通る（Cloudflare「Enable mTLS」の「CAs in use」）。アカウントを分ければ、管理用の Worker の mTLS を通る証明書を IdP のアカウントで発行したものに限れる。
- ホスト名には、そのアカウントに置いたゾーンのドメインを使う。
- 最初のデプロイを置く検証用のアカウントは、この条件を満たすとは限らない。検証用のアカウントには本物の利用者のデータを置かず、この条件は本番のアカウントで満たす（上の「アカウントの移植性」を参照）。
- D1 は作成時に APAC リージョンを指定する。

**管理用の Worker**

- IdP の Worker とは別のホスト名に、同じゾーンで置く。IdP の Worker と同じ D1 をバインドする。
- 管理用のホスト名に mTLS を有効にし、WAF のカスタムルールで、有効でない証明書と失効した証明書を遮断する。`workers.dev` とプレビューの URL は無効にする（[管理 CLI と管理用の Worker](idpctl.md)参照）。
- 管理者の証明書のフィンガープリントの許可リストは、デプロイの設定ファイル（上の「デプロイごとの入力」）に置き、管理用の Worker の設定として CI のデプロイでだけ変える。D1 には置かない。証明書はアカウント単位の CA で発行するので、許可リストはデプロイごとに別のものになる。
- クライアント証明書の発行と失効には「SSL and Certificates Write」の権限が要る（Cloudflare API「Create Client Certificate」）。この権限は基盤の権限として扱い、日常の管理には使わない。

**D1 の API トークン（break-glass）**

- 日常の管理には使わない。管理操作はすべて管理用の Worker の管理 API で行う。
- 前もって作らない。どこ（キーチェーン、1Password、CI）にも常設しない。管理用の Worker が使えないときの break-glass に限って、その時点で、権限を IdP の D1 の編集だけに絞り、短い有効期限を付けて作り、`cf d1 query` で使う。作業が終わったら失効させる。
- このトークンは IdP の全データを書き換えられる基盤の権限で、共有コアの規則も監査ログも通らない（[管理 CLI と管理用の Worker](idpctl.md)の break-glass を参照）。

**署名鍵**

- Worker Secret は書き込み専用で、登録した値を読み出せない。署名鍵の正本とバックアップは 1Password の Vault のアイテムに置き、Worker Secret にはそこから登録する。鍵は上の生成スクリプトで生成し、平文のままディスクに書かない（[トークン設計](tokens.md)参照）。
- Worker Secret は、Ed25519 の鍵の current を常に置き、最初のローテーションの後は previous も置く。RS256 を有効にするときだけ、RSA の鍵（4096 bit）の current（とローテーションの後の previous）を足す。既定のデプロイは RSA の鍵を持たない（[トークン設計](tokens.md)参照）。
- RS256 を有効にするのも無効にするのも、RSA の Secret をスクリプトで登録するか外してデプロイすることで行う。無効にするのは、`RS256` を登録した client がないことを `idpctl clients_list` で確かめ、最後の client を `Ed25519` に変えてから ID トークンの有効期限（5 分）が過ぎた後にする（[トークン設計](tokens.md)参照）。
- 管理用の Worker は署名鍵をバインドしない。RS256 が有効かどうかは、IdP の Worker への Service Binding で discovery を読んで判断する。
- 同じデプロイの Worker を作り直すときは、1Password のアイテムから登録し直す。
- 別のアカウントに作り直すときは、鍵を引き継がず、生成スクリプトで新しい鍵を作る。issuer が変わるので、古い鍵で署名したトークンを新しいデプロイで受け入れる理由がないため。1Password のアイテムも、デプロイごとに別の名前にする（上の「デプロイごとの入力」）。

**ログ**

- 状態の変化は D1 の `audit_log` に記録する。Workers Logs は消えていく短期の記録で、障害の調査にだけ使い、外部に送らない。
- Workers Logs の無料枠は、今は 1 日 200,000 イベントで 3 日間残る（Cloudflare「Workers Logs」の「Pricing」）。2026 年 12 月 1 日からは Cloudflare Observability の料金に移り、Free は 1 日 0.5 GB の取り込みで 7 日間残る。1 日の上限に達すると、UTC 0 時のリセットまで新しいデータを取り込まない（Cloudflare「Pricing」（Observability）の「Plans」）。
- 形式は、リクエストごとに構造化した 1 行とし、ルート、結果、エラーの種類、`client_id`、`sub`、管理者の名前（管理用の Worker）を持たせる。管理用の Worker が拒否したリクエストは、証明書のフィンガープリントと拒否の理由だけを書く。
- 書かないもの：トークン、認可コード、Cookie、IdP が発行する秘密、登録トークン、チャレンジ、`Authorization` ヘッダー、要求の本文。
- IdP は IP アドレスを書かない（設計原則 7）。悪用の調査には WAF の分析を使う。
- **受け入れるリスク**：無料枠では、すべてのリクエストのログを残すことはできない。大量のリクエストでその日の取り込みを止められることもある。それでも、状態の変化は `audit_log` にすべて残る。これより厳密な記録が必要なら、有料のプランにするか、この IdP を使わない。

**D1 のバックアップ**

- 家族規模の運用なので、無料の範囲でできるベストエフォートにとどめる。D1 の Time Travel だけを使い、定期的な export は取らない。
- Time Travel は常に有効で、履歴の保持と復元に追加の費用はかからない。保持期間は Workers Free で 7 日（Workers Paid では 30 日）。データベースが D1 の production バックエンドにあることが前提になる（[未決事項](open-questions.md)で確認する）。

Time Travel だけに任せることで、次のリスクを受け入れる。

- 7 日より後に気付いた破損や誤操作は、復元できない。
- Cloudflare アカウントを失うと、データベースと履歴をまとめて失う。Time Travel はこれを守らない。
- データベースを削除した後も履歴が残るかはドキュメントに書かれていないので、削除したデータベースは復元できないものとして扱う。
