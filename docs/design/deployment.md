# デプロイと設定

ホスト名などのデプロイ先に依存する値は、コードにも設計書にも書かず、デプロイごとの設定として与える。同じ実装をどのドメイン・どのアカウントにも置けるようにする。

**設定値**

- issuer の URL を 1 つの設定値（Worker の環境変数）として持つ。形式は `https://<ホスト名>` で、パス、クエリ、フラグメント、末尾のスラッシュは付けない。
- RP ID、WebAuthn の origin、discovery に載せる各エンドポイントの URL、アクセストークンの `aud` は、すべて issuer から導く。別々の設定値として持たない（値の食い違いを構造的に起こさないため）。
- 管理用の Worker も同じ issuer を設定として持ち、登録リンク（`/enroll#<token>`）の組み立てに使う。管理用のホスト名は、issuer とは別の設定値として持つ。
- リクエストの `Host` ヘッダーから issuer や origin を作らない。`Host` は送信側が自由に書き換えられるため。
- issuer が未設定、または形式が不正（`https` でない、パスが付いている、ホストが IP アドレスなど）なら、リクエストを処理せずエラーを返す（fail-closed）。

**デプロイの道具**

- 最初の構築の順番は[ブートストラップ](../deployment/bootstrap.md)にまとめる。
- Worker のデプロイ、D1 のマイグレーション、break-glass の D1 の操作は、すべて Cloudflare の `cf` CLI で行う。wrangler はどこにも使わない。`cf` は Worker のデプロイ（`cf deploy`。Cloudflare「Deploy your first Worker」）と D1 のマイグレーション（`cf d1 migrations apply`。Cloudflare「Wrangler to cf reference」）を挙げている。
- `cf` は自分でバンドラーを動かさず、フレームワークのコマンドか、`package.json` で宣言した Cloudflare のビルドツールを実行する。ビルドツールは Cloudflare Vite plugin 2.0 beta（`@cloudflare/vite-plugin@beta`）で、Wrangler に依存しない。Vite plugin を宣言していないときだけ Wrangler でビルドする（Cloudflare「Develop, build, and deploy」の「How `cf` runs your project」）。また、`wrangler.jsonc`、`wrangler.json`、`wrangler.toml` のあるプロジェクトでは `cf deploy` を実行してはいけない（Cloudflare「Deploy your first Worker」の「Start from an existing project」）。
- そのため、2 つの Worker はどちらも `@cloudflare/vite-plugin@beta` を宣言し、wrangler を依存に宣言せず、`wrangler.*` の設定ファイルを置かない。`cf migrate` の Wrangler bundler も使わない。
- `cf` にドキュメント化されたコマンドがない操作は、Cloudflare API かダッシュボードで行い、wrangler で補わない。`cf` で足りるかどうかを実装の前に確かめる項目は[未決事項](open-questions.md)にまとめる。
- `cf` はベータで、コマンドが安定版の前に変わりうる（Cloudflare「Cloudflare CLI」）。
- CI では `cf` が `CLOUDFLARE_API_TOKEN` と `CLOUDFLARE_ACCOUNT_ID` を読む（Cloudflare「Use cf in CI」の「Provide credentials」）。

**Terraform とスクリプトの分担**

基盤はできるだけコードで持つ（IaC）。宣言できるものは Terraform に、手続きでしか表せないものは `cf` を使うシェルスクリプトに置き、手作業の手順を残さない。望む状態を宣言し、実際の状態をそれに合わせ続ける形にするため（[宣言とリコンシリエーション](../philosophy/system-design/declarative-and-reconciliation.md)）。

- Terraform（Cloudflare provider）が持つもの：D1 のデータベース、DNS、Worker のカスタムドメイン、WAF のカスタムルール（mTLS）、レート制限ルール、管理用のホスト名への mTLS の割り当て、CSR から発行するクライアント証明書、fail closed の設定。
- `cf` のシェルスクリプトが持つもの：D1 のマイグレーション、Worker のデプロイ、Worker Secret の登録、D1 が production バックエンドにあることの確認、鍵の生成、Terraform の state を置く R2 のバケットの作成。
- Terraform には秘密を渡さない。state は入力の値を保存するため。証明書と CSR は秘密ではないので Terraform に渡してよい。
- Terraform のバージョンは mise で固定し、provider のバージョンは `.terraform.lock.hcl` で固定する。
- state は、IdP 専用の Cloudflare アカウントの R2 に、S3 互換の backend で置く（Cloudflare「Remote R2 backend」）。state のバケットは Terraform より先に必要なので、`cf` のスクリプトで最初に作る。R2 の認証情報は 1Password Environments で CI に渡す（[1Password Environments と GitHub Actions](../deployment/secret.md)参照）。
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

- 例外として、plan の job にだけ、読み取り専用の Environment（Terraform の読み取り専用の API トークンと、state のバケットの読み取り専用の R2 の認証情報）を渡す。デプロイ用の Environment とは分ける。
- destination は、plan の workflow と、同じリポジトリからの PR に限る。fork からの PR には渡さない。
- 理由：plan を PR に載せることで、基盤の変更をマージの前にレビューでき、手動の承認を置かない流れでの唯一の関門（PR のレビュー）を意味のあるものにするため。読み取り専用の認証情報が漏れても、変更はできない。
- 1Password の destination で PR のイベントに限れるかは、実装の前に確かめる（[未決事項](open-questions.md)参照）。限れなければ、plan を PR に載せるのをやめ、main での apply の前の plan だけにする。

**API トークン**

- 役割ごとに分ける。どれも IdP 専用のアカウントに限る。
  - Terraform 用：DNS、WAF、SSL と証明書、D1 の作成、Worker のカスタムドメイン。
  - デプロイ用：Workers の編集と、マイグレーションのための D1 の編集。
  - plan 用（上の例外）：Terraform 用と同じ範囲の読み取りだけ。
- どれも 1Password Environments と GitHub OIDC で、実行時に CI に渡す。
- break-glass 用の D1 のトークン（下記）は、範囲（IdP の D1 の編集）と短い有効期限を定めておくが、前もって作らない。

**ホスト名を変えるときの影響**

ホスト名はデプロイごとに決める値で、設定を変えれば別のホスト名で動かせる。ただし、運用を始めた後に変えると、次のことが仕様上避けられない。

- パスキーは RP ID（ホスト名）に紐付くので、全員がパスキーを登録し直す必要がある。
- `iss` が変わるので、RP からは別の IdP に見える。RP 側の設定と利用者の紐付けを移行する必要がある。ledger などの結合キー（`iss` + `sub`）も変わる。

そのため、本番のホスト名は最初のデプロイの前に決め、以後は変えない前提で運用する。

**Cloudflare アカウント**

- IdP の Worker と D1 は、IdP 専用の Cloudflare アカウントに置く。D1 の API トークンの権限は特定のデータベースに絞れず、アカウント内のすべての D1 に効くため。アカウントを分ければ、IdP のトークンが漏れても影響は IdP に限られ、他のサービスのトークンで IdP のデータを書き換えられることもない。
- クライアント証明書はアカウント単位の CA で検証され、同じアカウントのどのゾーンで発行した証明書も、mTLS を有効にしたホストで通る（Cloudflare「Enable mTLS」の「CAs in use」）。アカウントを分ければ、管理用の Worker の mTLS を通る証明書を IdP のアカウントで発行したものに限れる。
- ホスト名には、そのアカウントに置いたゾーンのドメインを使う。
- D1 は作成時に APAC リージョンを指定する。

**管理用の Worker**

- IdP の Worker とは別のホスト名に、同じゾーンで置く。IdP の Worker と同じ D1 をバインドする。
- 管理用のホスト名に mTLS を有効にし、WAF のカスタムルールで、有効でない証明書と失効した証明書を遮断する。`workers.dev` とプレビューの URL は無効にする（[管理 CLI と管理用の Worker](idpctl.md)参照）。
- 管理者の証明書のフィンガープリントの許可リストは、管理用の Worker の設定としてリポジトリに置き、CI のデプロイでだけ変える。D1 には置かない。
- クライアント証明書の発行と失効には「SSL and Certificates Write」の権限が要る（Cloudflare API「Create Client Certificate」）。この権限は基盤の権限として扱い、日常の管理には使わない。

**D1 の API トークン（break-glass）**

- 日常の管理には使わない。管理操作はすべて管理用の Worker の管理 API で行う。
- 前もって作らない。どこ（キーチェーン、1Password、CI）にも常設しない。管理用の Worker が使えないときの break-glass に限って、その時点で、権限を IdP の D1 の編集だけに絞り、短い有効期限を付けて作り、`cf d1 query` で使う。作業が終わったら失効させる。
- このトークンは IdP の全データを書き換えられる基盤の権限で、共有コアの規則も監査ログも通らない（[管理 CLI と管理用の Worker](idpctl.md)の break-glass を参照）。

**署名鍵**

- Worker Secret は書き込み専用で、登録した値を読み出せない。署名鍵の正本とバックアップは 1Password の Vault のアイテムに置き、Worker Secret にはそこから登録する。鍵は上の生成スクリプトで生成し、平文のままディスクに書かない（[トークン設計](tokens.md)参照）。
- Worker Secret は、Ed25519 の鍵の current と previous の 2 つを常に置く。RS256 を有効にするときだけ、RSA の鍵（4096 bit）の current と previous を足して 4 つにする。既定のデプロイは RSA の鍵を持たない（[トークン設計](tokens.md)参照）。
- RS256 を有効にするのも無効にするのも、RSA の Secret をスクリプトで登録するか外してデプロイすることで行う。無効にするのは、`RS256` を登録した client がないことを `idpctl clients_list` で確かめ、最後の client を `Ed25519` に変えてから ID トークンの有効期限（5 分）が過ぎた後にする（[トークン設計](tokens.md)参照）。
- 管理用の Worker は署名鍵をバインドしない。RS256 が有効かどうかは、IdP の Worker への Service Binding で discovery を読んで判断する。
- 再設定や別アカウントへの移行のときは、1Password のアイテムから登録し直す。

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
