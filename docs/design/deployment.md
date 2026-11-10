# デプロイと設定

ホスト名などのデプロイ先に依存する値は、コードにも設計書にも書かず、デプロイごとの設定として与える。同じ実装をどのドメイン・どのアカウントにも置けるようにする。

**アカウントの移植性**

移植性は、fork して自分のアカウントとドメインの情報を入れればデプロイできること（fork できること）を指す。稼働中の IdP をアカウントの間で移すことではない。最初のデプロイは、検証用のアカウントに置く。これは最終的なアカウントではない。本番は、下の「Cloudflare アカウント」の条件を満たすアカウントに、同じ構成を作り直して置く。そのため、構成の全体を、下の「デプロイごとの入力」を変えるだけで、別のアカウントに同じ形で再現できるようにする。

- 検証用のアカウントの名前と、どのアカウントの ID も、リポジトリに書かない。リポジトリは公開しているため。ドキュメントでは「検証用のアカウント」とだけ呼ぶ。
- 移植性は「同じ構成」を意味し、「同じデータ」を意味しない。新しいアカウントには、新しい D1 と新しい署名鍵を作る。issuer と RP ID が変わるので、利用者はパスキーを登録し直す（下の「ホスト名を変えるときの影響」を参照）。アカウントの間でデータ（D1 の行、署名鍵）を移すことは、この設計の範囲外とする。
- ドメインを持たない人も fork できるように、ホスティングのモードを 2 つ持つ。カスタムドメインのモード（`custom_domain`）は同じアカウントのゾーンに置き、`workers.dev` のモード（`workers_dev`）はゾーンを持たずにアカウントの `workers.dev` のサブドメインに置く（[ホスティングのモード](hosting-modes.md)）。
- **`workers.dev` のモードの固定の警告**：`workers_dev` の issuer と RP ID は、アカウントの `workers.dev` のサブドメインと IdP の Worker の名前で決まる。後からカスタムドメインに移すと、issuer が変わり、全員のパスキーの登録し直しとすべての RP の設定の移行が要る（下の「ホスト名を変えるときの影響」）。長く使うつもりなら、最初からカスタムドメインのモードを選ぶ。Cloudflare も `workers.dev` を本番向けとしていない（[ホスティングのモード](hosting-modes.md)の 2.4）。
- 検証用のアカウントで行うのは検証だけで、本物の利用者のデータを置かない。
- 移植できることは、本番の前に、入力だけを使って 2 つ目のアカウントにブートストラップを最後まで通して確かめる（[未決事項](open-questions.md)参照）。

**デプロイごとの入力**

デプロイごとに変えてよいのは、次の入力だけとする。これ以外の値（リソースの構成、権限の範囲、手順、コード）は、すべてのデプロイで同じにする。入力が増えるときは、この表を先に更新する。

| 入力 | 置き場所 | 使うもの |
| --- | --- | --- |
| Cloudflare のアカウント ID | 1Password（CI は Environment の `CLOUDFLARE_ACCOUNT_ID`、手元は Vault のアイテム）。リポジトリには置かない | Terraform、`cf` のスクリプト、CI、R2 の backend の endpoint |
| ホスティングのモード（`hosting_mode`、新設。`custom_domain` か `workers_dev`。既定値なし） | デプロイの設定ファイル | Terraform、`cf` のスクリプト、CI、2 つの Worker の `cloudflare.config.ts` と環境変数 `HOSTING_MODE`。ほかの入力の必須と禁止を決める（[ホスティングのモード](hosting-modes.md)の 1.1） |
| ゾーン（ドメイン）。`custom_domain` だけ | デプロイの設定ファイル | Terraform（ゾーン ID はここから引く） |
| issuer のホスト名。`custom_domain` だけ | デプロイの設定ファイル | IdP の Worker の `cloudflare.config.ts`（カスタムドメイン）、IdP の Worker と管理用の Worker の環境変数 |
| 管理用のホスト名。`custom_domain` だけ | デプロイの設定ファイル | 管理用の Worker の `cloudflare.config.ts`（カスタムドメイン）、管理用の Worker の環境変数 |
| アカウントの `workers.dev` のサブドメイン（`workers_dev_subdomain`、新設）。`workers_dev` だけ | デプロイの設定ファイル | issuer と管理用のホスト名を導く（`scripts/lib.sh`）。運用者の確認のスクリプト（`scripts/check-workers-dev-subdomain.sh`、`scripts/terraform.sh`）が Cloudflare API で実際の値と照らし合わせる。Terraform は形と、モードとの組み合わせだけを確かめる |
| D1 のデータベースの名前 | デプロイの設定ファイル | `cf` のスクリプト（ID は名前から引く） |
| IdP の Worker の Rate Limiting の名前空間の ID（`rate_limit_namespace_id`） | デプロイの設定ファイル | IdP の Worker の `cloudflare.config.ts`（Rate Limiting のバインディング）。アカウントの中で一意なので、同じアカウントのほかの Worker が使っていない値を選ぶ |
| 管理用の Worker の Rate Limiting の名前空間の ID（`admin_rate_limit_namespace_id`、新設） | デプロイの設定ファイル | 管理用の Worker の `cloudflare.config.ts`（Rate Limiting のバインディング）。IdP の Worker の値とも、同じアカウントのほかの Worker の値とも違う値を選ぶ（[ホスティングのモード](hosting-modes.md)の 6.2） |
| Terraform の state を置く R2 のバケットの名前 | デプロイの設定ファイル | `cf` のスクリプト（作成）、`terraform init` の backend の設定 |
| 1Password の Environment と Vault のアイテムの名前 | デプロイの設定ファイル | 生成スクリプト、Secret の登録スクリプト、手元の Terraform、1Password の連携のスクリプト |
| GitHub Environment の名前（デプロイ用と plan 用） | デプロイの設定ファイル | CI の workflow、1Password の destination の条件 |
| 管理者の署名鍵の許可リスト（`admin_signing_keys`、新設） | デプロイの設定ファイル（管理者の生成スクリプトが行を書く） | 管理用の Worker の設定 `ADMIN_SIGNING_KEYS` |

- 前の設計の入力の、管理者の証明書のフィンガープリントの許可リスト（`admin_allowlist`）とクライアント証明書の CSR（`admin_client_certificates`）は、管理者の認証を署名だけにする決定で廃止し、mTLS の撤去（[ホスティングのモード](hosting-modes.md)の実装の順番の 7）で外した。設定ファイルにキーが残っていれば、値によらず（空や `null` でも）、すべてのスクリプトが通る `scripts/lib.sh` の `deployment_config_path`（`reject_removed_inputs`）が処理を始める前に止める。キーがあるかどうかの判断はこちらが正とする。Terraform の変数（null だけを受け付ける廃止の印の変数）は、null でない値（空のリストや空のマップを含む）を拒否する。Terraform は明示した `null` とキーがないことを区別できないので、`null` の値は Terraform を通り、スクリプトが止める。古い設定ファイルを、まだ mTLS を使うデプロイとしてレビューで読み違えないため（fail-closed。[ホスティングのモード](hosting-modes.md)の 1.1 の「廃止」と 1.4）。`zone_singletons_owner` は ③ で外れた。
- 新設の入力のうち、`admin_signing_keys` と `admin_rate_limit_namespace_id` は、[ホスティングのモード](hosting-modes.md)の実装の順番の 5 で、Terraform の変数（設定ファイルの検証）と生成スクリプトに足した。実装の順番の 6 で、管理用の Worker の `cloudflare.config.ts` が、デプロイのスクリプトの環境変数 `IDP_ADMIN_SIGNING_KEYS`（`admin_signing_keys` の JSON）と `IDP_ADMIN_RATE_LIMIT_NAMESPACE_ID` から `ADMIN_SIGNING_KEYS` と `RATE_LIMITER` を組み立てるようにした。ほかに、`IDP_HOSTING_MODE`、`IDP_ISSUER`、`IDP_ADMIN_HOST`、`IDP_D1_DATABASE_ID` を受け取り、どれかが欠けているか形が違えば設定の評価が失敗する。`hosting_mode` と `workers_dev_subdomain` は実装の順番の 8 で足した。IdP の Worker の `cloudflare.config.ts` も `IDP_HOSTING_MODE` を受け取り、`IDP_ISSUER` は `workers_dev` では `https://idp.<workers_dev_subdomain>.workers.dev` になる（`scripts/lib.sh` の `deployment_issuer_host` と `deployment_admin_host` が導く）。
- `custom_domain` で動いている既存のデプロイは、設定ファイルに `"hosting_mode": "custom_domain"` を足すだけでよい。ほかの入力、issuer、Worker の公開の仕方、Terraform の plan は変わらない（ゾーンの data source のアドレスが `data.cloudflare_zone.this[0]` になるが、data source は plan のたびに読み直すもので、作ったり変えたりする資源ではないので、plan に変更は出ない）。`hosting_mode` がないままの設定ファイルは、すべてのスクリプトと Terraform が止める。
- モードの必須と禁止（[ホスティングのモード](hosting-modes.md)の 1.1 の表）は、`scripts/lib.sh` の `check_hosting_inputs`（`deployment_config_path` を通るすべてのスクリプト）と Terraform の変数の両方で確かめる。禁止の入力は、値が空や `null` でもキーがあれば `scripts/lib.sh` が止める。Terraform は明示した `null` とキーがないことを区別できないので、キーの有無はスクリプトを正とする（上の廃止した入力と同じ）。2 つの Worker の `cloudflare.config.ts` と Worker の実行時も、共有コアの同じ規則でモードとホスト名の組み合わせを確かめる（1.4 の 3 か所）。
- Terraform は `admin_signing_keys` の形（3 つのメンバー、`keyid` の形、管理者の名前、P-384 の SPKI の base64 の形、`keyid` の重複）だけを確かめる。Terraform はバイト列の SHA-256 を計算できないので、`keyid` と `public_key` の一致と、公開鍵が曲線の上の点であることは、生成スクリプト（書くたびに設定ファイルのリスト全体を確かめる）と管理用の Worker が確かめる。空のリストは、[ホスティングのモード](hosting-modes.md)の 1.1 と 1.4 の必須に合わせ、Terraform の変数、デプロイの前の検証（`scripts/lib.sh` の `check_admin_signing_keys`）、管理用の Worker の `cloudflare.config.ts`、管理用の Worker 自身のすべてで拒否する（実装の順番の 6 で、実装の順番の 5 の一時的な例外を終えた）。例外は生成スクリプトだけで、新しいデプロイの空のリストに最初の行を足すために、書く前の確認では空を受け付け、書いた後のリストは空を拒否する確認に通す。

- デプロイの設定ファイルは、デプロイごとに 1 つ、`deployments/<デプロイの名前>.tfvars.json` に置く。秘密を含まない値だけを書く。Terraform は `-var-file` で読み、`cf` のスクリプトと CI も同じファイルを読む。同じ値を 2 か所に持たないため。
- アカウント ID だけは設定ファイルに書かず、1Password から実行時に環境変数で受け取る。公開リポジトリにアカウント ID を残さないため。ゾーン、ホスト名、`workers.dev` のサブドメインは DNS と discovery で外から見える値で、許可リストの公開鍵と `keyid` は秘密ではないので、設定ファイルに書いてよい。
- CI が使うデプロイは、GitHub のリポジトリの変数 `IDP_DEPLOYMENT`（デプロイの名前。空白か改行で区切って複数を並べてよい）で選ぶ。workflow の最初の job が設定ファイルを読み、デプロイごとに GitHub Environment の名前を後の job に渡す。変数が空なら、workflow はどの job も動かさない（fork と、一度だけの準備の前の状態）。
- 入力から導ける値は入力にしない。ゾーン ID は Terraform がゾーンの名前から引く。D1 の ID は、ブートストラップとデプロイのスクリプトが名前から引き、Worker のバインディングに渡す。R2 の backend の endpoint はアカウント ID から組み立てる。1Password の Workload ID と Environment ID は、1Password の連携のスクリプトが GitHub の変数に登録する。どれも人が手で書き写さない。
- 設定ファイルが入力のどれかを欠いていたら、Terraform、スクリプト、CI は処理を始めずに止まる（fail-closed）。既定値で補わない。モードで禁止した入力が書かれているときも止まる（片方のモードの値が残っていると、どちらのモードで動いているかをレビューで読み違えるため。[ホスティングのモード](hosting-modes.md)の 1.4）。

**直書きの禁止**

- アカウント ID、ゾーン ID、D1 のデータベースの ID、ホスト名、`workers.dev` のサブドメイン、管理者の公開鍵と `keyid` を、Terraform、スクリプト、CI の workflow、Worker のコード、ドキュメントに直接書かない。値はすべて上の入力から受け取るか、入力から引く。ドキュメントでは `<ホスト名>` のような置き換えの印で書く。
- スクリプトの `cf` の呼び出しは、すべて対象のアカウントを明示する。運用者の `cf auth login` のセッションは、複数のアカウントにまたがりうるため。`cf` 1.0.0-beta.21 のグローバルフラグには、アカウントを指定するものがない（`cf --help` の Global flags にあるのは `--zone` や `--profile` など）。そのため、スクリプトは呼び出しごとに入力のアカウント ID を `CLOUDFLARE_ACCOUNT_ID` に設定し、変更を加える前に、対象のアカウントが入力のものであることを確かめる。手元の `cf` のセッションがこの環境変数に従うかは、実装の前に確かめる（[未決事項](open-questions.md)参照）。従わなければ、アカウントごとの `--profile` か Cloudflare API のスクリプトにする。

**設定値**

- issuer の URL を 1 つの設定値（Worker の環境変数）として持つ。形式は `https://<ホスト名>` で、パス、クエリ、フラグメント、末尾のスラッシュは付けない。
- ホスト名はモードで決まる。`custom_domain` では issuer のホスト名と管理用のホスト名を入力として持ち、どちらも `workers.dev` の下に置けない。`workers_dev` では issuer のホスト名を `idp.<workers_dev_subdomain>.workers.dev`、管理用のホスト名を `<管理用の Worker の名前>.<workers_dev_subdomain>.workers.dev` として入力から導き、別の入力にしない（[ホスティングのモード](hosting-modes.md)の 1.3）。Worker の名前はコードの定数で、`workers_dev` では変えると issuer が変わる。
- 2 つの Worker は、モードを環境変数 `HOSTING_MODE` で受け取り、モードと issuer（管理用の Worker では管理用のホスト名も）の形が合わなければ、すべての要求を拒否する。実行時の処理はモードで分けず、モードの値は設定の食い違いを検出するためだけに使う（[ホスティングのモード](hosting-modes.md)の 1.4）。
- RP ID、WebAuthn の origin、discovery に載せる各エンドポイントの URL、アクセストークンの `aud` は、すべて issuer から導く。別々の設定値として持たない（値の食い違いを構造的に起こさないため）。
- 管理用の Worker も同じ issuer を設定として持ち、登録リンク（`/enroll#<token>`）の組み立てに使う。管理用のホスト名は、issuer とは別の設定値として持つ。
- リクエストの `Host` ヘッダーから issuer や origin を作らない。`Host` は送信側が自由に書き換えられるため。
- IdP の Worker は、静的なページを含むすべてのリクエストで先に動き（`run_worker_first` を真にする）、issuer のホスト名以外へのリクエストを、スキームによらず処理せずに 404 で拒否する。
- issuer のホスト名への平文の HTTP のリクエストは、`GET` か `HEAD` で `Authorization` と、名前が `__Host-` で始まる Cookie を持たないものだけを、設定した issuer の同じパスとクエリへ 308 でリダイレクトする。ほかの平文のリクエストは、処理せずに 404 で拒否する。平文の HTTP で送られたクライアントシークレット、認可コード、アクセストークンは、届いた時点ですでに経路上に漏れているので、応答して再送を促さない。ゾーン全体に効く「Always Use HTTPS」もシングルリダイレクトのルールも使わない。IdP はゾーンのルールセットと設定を持たないため（[ドメインの置き場所](domain-placement.md)の決定 ③ と共存の設計の 3）。管理用の Worker は平文のリクエストをリダイレクトせず、`forbidden` で拒否する。
- IdP の Worker と管理用の Worker は、`request.cf.tlsVersion` が `TLSv1.2` か `TLSv1.3` でないリクエストを、処理せずに拒否する（IdP の Worker は 404、管理用の Worker は `forbidden`）。値がない、知らない値も拒否する。ゾーンの TLS の最小バージョンはゾーン全体の設定で、IdP は持たないため（RFC 8996 の例外。[ドメインの置き場所](domain-placement.md)の共存の設計の 3）。
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

- Terraform（Cloudflare provider）が持つもの：DNS（Worker のカスタムドメインが作るレコードを除く）と fail closed の設定。ゾーンのルールセット（WAF のカスタムルール、レート制限ルール、シングルリダイレクト）は持たない（[ドメインの置き場所](domain-placement.md)の決定 ③）。管理用のホスト名への mTLS の割り当てと、CSR から発行するクライアント証明書は、管理者の認証を署名だけにする決定で外した（[ホスティングのモード](hosting-modes.md)の実装の順番の 7）。今の `infra/` は、ゾーンを引く data source と設定ファイルの検証だけを持ち、ゾーンに資源を置かない。`workers_dev` のモードでは、Terraform はゾーンの data source を使わない。
- Worker のカスタムドメインは、それぞれの Worker の `cloudflare.config.ts`（`worker.domains`）が持ち、`cf deploy` が Worker と一緒に付ける（Cloudflare「Cloudflare config」）。`workers.dev` とプレビューの URL の有効と無効（`workersDev`、`previewUrls`）も同じファイルで宣言し、値はモードから導く（`custom_domain` は `domains` が 1 つで `workersDev` が偽、`workers_dev` は `domains` がなく `workersDev` が真。プレビューの URL はどちらも無効。[ホスティングのモード](hosting-modes.md)の 1.2）。Terraform と `cf` の両方がカスタムドメインを持つと、片方の変更をもう片方が戻しうる。また、Terraform に持たせると、最初の apply がまだない Worker にドメインを付けることになる。カスタムドメインは、Cloudflare が DNS のレコードと証明書を作るので、Terraform はそのホスト名の DNS のレコードを持たない。ホスト名の値はデプロイの設定ファイルから渡し、`cloudflare.config.ts` に書かない。
- `cf` のシェルスクリプトが持つもの：D1 のデータベースの作成、D1 のマイグレーション、Worker のデプロイ、Worker Secret の登録、D1 が production バックエンドにあることの確認、鍵の生成、Terraform の state を置く R2 のバケットの作成。
- D1 のデータベースを Terraform に置かないのは、plan の認証情報に D1 の権限を一切持たせないため（下の PR の `terraform plan` の認証情報を参照）。provider の `cloudflare_d1_database` は `D1 Read` か `D1 Write` の権限を要し（Terraform Cloudflare provider「cloudflare_d1_database」の Accepted Permissions）、`terraform plan` は既定で既存のリソースの現状を読む（HashiCorp「terraform plan」の Introduction）。Terraform に D1 のデータベースがあると、plan のトークンに D1 の権限が要る。D1 のデータベースは作った後に変えるものがほとんどなく、宣言で持つ利点も小さい。
- Terraform には秘密を渡さない。state は入力の値を保存するため。管理者の公開鍵は秘密ではないので Terraform の変数で検証してよい。
- Terraform のバージョンは mise で固定し、provider のバージョンは `.terraform.lock.hcl` で固定する。
- state は、デプロイ先のアカウントの R2 に、S3 互換の backend で置く（Cloudflare「Remote R2 backend」）。state のバケットは Terraform より先に必要なので、`cf` のスクリプトで最初に作る。R2 の認証情報は 1Password Environments で CI に渡す（[1Password Environments と GitHub Actions](../deployment/secret.md)参照）。
- state はデプロイごとに分け、アカウントをまたいで共有しない。backend のブロックには変数を使えないので、バケットの名前と endpoint（アカウント ID から組み立てる）は、`terraform init` の `-backend-config` で、デプロイの入力から渡す。backend のブロックに値を書かない。
- Terraform のコードは、上の「デプロイごとの入力」を変数として受け取り、アカウント ID、ゾーン ID、ホスト名を `.tf` のファイルに書かない。ゾーン ID は data source でゾーンの名前から引く。
- provider がどのリソースに対応しているか（fail closed の設定など）は、実装の前に確かめる（[未決事項](open-questions.md)参照）。対応していないものは、`cf` か Cloudflare API のスクリプトにし、wrangler では補わない。
- 実装（`infra/`、provider 5.28.1）で確かめた結果：mTLS のホスト名の割り当て（`cloudflare_certificate_authorities_hostname_associations`）と CSR からのクライアント証明書（`cloudflare_client_certificate`）は provider で持てた（実装の順番の 7 で撤去した。どのデプロイでも適用されなかったので、state にも Cloudflare にも残っておらず、Terraform の `removed` のブロックは置かずにそのまま消した）。ゾーンのルールセット（`cloudflare_ruleset`）も持てるが、エントリポイントのルールセットのルールの一覧を丸ごと持つ資源で、一部のルールだけを持つことはできないので、使わない。fail closed の設定は、provider の Workers のルート（`cloudflare_workers_route`）に属性がなく、2 つの Worker はルートではなくカスタムドメインを使うので、Terraform には置かない。カスタムドメインで設定できるかは[未決事項](open-questions.md)の項目のまま残す。
- ゾーン全体に効く設定（Always Use HTTPS と TLS の最小バージョン。`cloudflare_zone_setting`）は持たない。ゾーンの持ち主が決めるもので、IdP のデプロイがサービスのほかのホスト名の動きを変えないため。代わりに、Worker の中のリダイレクトと TLS のバージョンの確認を置く（上の設定値）。ゾーンの TLS の最小バージョンが 1.2 以上であることは、ブートストラップの前提でゾーンの持ち主に確かめる（[ドメインの置き場所](domain-placement.md)の共存の設計の 3）。
- 管理用のホスト名は、設定ファイルで小文字のホスト名だけを受け付ける。管理用の Worker は、要求の URL のホスト名（常に小文字に正規化される）と完全に一致することで確かめるため。
- 今の構成では、Terraform が持つ DNS のレコードはない。IdP の Worker と管理用の Worker のホスト名のレコードは、どちらもカスタムドメインが作るため。カスタムドメイン以外のレコードが要るようになったら、Terraform に足す。
- IdP はゾーンに単一資源（ゾーンに 1 つしかなく、ゾーンの持ち主と取り合うもの）を何も置かない。置くのは Worker のカスタムドメインだけである（[ドメインの置き場所](domain-placement.md)の共存の設計の 2）。最後の単一資源だった管理用のホスト名の mTLS の割り当て（ゾーンの managed CA に割り当てたホスト名の一覧を丸ごと持つ資源）は、mTLS の撤去で外した。
- IdP の Worker の Rate Limiting のバインディングのしきい値（10 秒あたりの件数）は、実測の前の仮の値として 10 にする。静的なページは数えないので、正規のサインイン 1 回でバインディングに数えられるリクエストは 4〜5 件の見込みで、10 秒の間に 1 回やり直せる数にした。実測したら置き換える（[無料枠](free-tier.md)と[未決事項](open-questions.md)参照）。
- 管理用の Worker の Rate Limiting のバインディングのしきい値も、仮の値で 10 秒あたり 10 件にする。名前空間は IdP の Worker と分ける（[ホスティングのモード](hosting-modes.md)の 6.2）。
- IdP の Worker の名前と、Ed25519 の current の署名鍵の Worker Secret の名前は、デプロイごとの入力ではなくコードの定数で、スクリプト（`scripts/lib.sh`）と IdP の Worker の設定で同じ値を使う。

**シェルスクリプトの規則**

- スクリプトは `#!/usr/bin/env bash` と `set -euxo pipefail` で始める。
- 例外として、秘密を扱うスクリプト（鍵の生成、Worker Secret の登録、break-glass の操作）は `set -euo pipefail` にし、`-x` を付けない。xtrace は展開した後の秘密の値をそのまま表示するため。この例外と理由は、そのスクリプトの先頭のコメントに書く。[AGENT.md](../../AGENT.md) には書かない（スクリプトごとの例外なので、例外を持つスクリプトの中に置く）。

**鍵と秘密の生成スクリプト**

鍵と秘密（署名鍵、管理者の秘密鍵（署名鍵））は、必ずリポジトリのレビュー済みの生成スクリプトで生成する。手で生成すると、手順のずれが鍵ごとに積み重なり、それが最も危険なため。

- スクリプトを通せば、人が実行してもエージェント（AI）が実行しても結果は変わらない。そのため、実行する主体は限らない。
- 秘密を AI のコンテキストに入れてはいけない、という規則は変わらない。スクリプトは秘密を標準出力に出さない。
- 生成スクリプトは `op` を必須にし、生成した鍵を 1Password のアイテムと Worker Secret に直接パイプで渡す。平文をディスクに書かない。
- `kid`（RFC 7638）と管理者の鍵の `keyid`（SPKI の DER の SHA-256）はスクリプトが自分で計算する。
- 出力するのは秘密でない値（`kid`、`keyid`、公開鍵）だけにする。管理者の鍵の生成スクリプトは、デプロイの設定ファイルの `admin_signing_keys` に、`keyid`、`name`、`public_key` の行を書く。CSR は作らない（[ホスティングのモード](hosting-modes.md)の 3.10。実装の順番の 7 で外した）。既存のアイテムの鍵には、アイテムの `public_key` と `public_key_sha256` だけを読んで行を書くモード（`--from-existing`）を使い、秘密鍵のフィールドは読まない。

**デプロイのパイプライン**

- PR：lint、テスト、`terraform plan` を流し、plan の出力を PR に載せる。apply はしない。
- main へのマージ：その 1 つのコミットから、`terraform apply`、`cf` のスクリプトによる D1 のマイグレーション、IdP の Worker の `cf deploy`、管理用の Worker の `cf deploy` の順に流し、最初の失敗で止める。
- 手動の承認は置かない。apply とデプロイは main へのマージで自動で走る。デプロイは管理者の署名鍵の許可リストも変えるので、main のブランチのルールセット（PR のレビューとマージの権限）が、管理者の権限と基盤の変更の唯一の関門になる（[操作とリスク](operations-and-risks.md)参照）。
- 2 つの Worker は別々に切り替わるので、マイグレーションは expand / contract にする。新しいマイグレーションは、古いコードと新しいコードの両方で動く形にし、古い形を消すのは、両方の Worker が新しいコードになった後の別のマイグレーションで行う。
- 例外：`0004`（監査ログの `admin_credential`）は、署名だけにする決定に合わせ、`admin_credential` のない `admin` の行を拒否するので、署名の前の管理用の Worker とは両立しない（IdP の Worker の挿入は列を名指ししないので影響しない）。そのため `0004` は、署名に切り替えた管理用の Worker（[ホスティングのモード](hosting-modes.md)の実装の順番の 6）と同じデプロイで適用し、それより前のデプロイで先に適用しない。上の流れでは同じデプロイの中でマイグレーションが管理用の Worker の `cf deploy` より先に走るので、その間だけ古い管理用の Worker と `0004` が並ぶが、その間に管理操作の書き込みは走らない（管理操作は `idpctl` から運用者が送るものだけで、デプロイの間には送らない）ので害はない。最初のデプロイがすでにこの管理用の Worker を含むので、署名の前の管理用の Worker が動いたデプロイは実際にはない。
- 管理者が締め出されたときは、Worker を前のバージョンに戻さず、許可リストの行か鍵を PR で直してデプロイし直す。`0004` の後に署名の前の管理用の Worker へ戻すと、管理操作の書き込みがすべて `0004` のトリガーで失敗する。`0004` より前からあるデプロイで戻すことがどうしても避けられないときは、先に break-glass で `0004` のトリガーを外す。
- ロールバック：Worker は前のバージョンに戻す。Cloudflare のドキュメントは、ロールバックをダッシュボードと Wrangler の `wrangler rollback` でしか説明していない（Cloudflare「Rollbacks」）。`cf` か Cloudflare API でできるかは実装の前に確かめる（[未決事項](open-questions.md)参照）。ロールバックはバインディング先の D1 を変えない（同じページの「Bindings」）。D1 は Time Travel で戻す。
- 依存の取得は、Takumi Guard の下で、バージョンを固定した pnpm のセットアップの Action と `pnpm install --frozen-lockfile` で行う。Takumi Guard が pnpm に対応していることは利用者が確認済みで、セットアップの Action の実装で改めて確かめる。

実装（`.github/workflows/deploy.yml`、`scripts/terraform.sh --ci`、`scripts/deploy.sh --ci`）は次のとおり。npm の雛形だった `examples/github-actions/deploy.yml` は、この実装で外した。

- 起動：main への push と、手動の起動（`workflow_dispatch`。main だけ）。手動の起動は、`IDP_DEPLOYMENT` にあるデプロイを 1 つだけ選び、最初のデプロイ（[ブートストラップ](../deployment/bootstrap.md)の段階 5）のための「署名鍵の前」の指定を付けられる。
- 最初の job は、認証情報を持たず、`IDP_DEPLOYMENT` のすべてのデプロイの設定ファイルを `scripts/lib.sh` の検証に通し（廃止した入力、モードの必須と禁止）、デプロイごとの GitHub Environment の名前を確かめて（英数字、`_`、`-` だけ）、次の job の matrix にする。どれか 1 つでも不正なら、どの job も認証情報を受け取る前に止まる。
- 次の job は、デプロイごとに、その GitHub Environment の中で動く。OIDC の権限（`id-token: write`）と 1Password の認証情報は、この job だけが受け取る。依存を取得した後で 1Password Environment を読み込み、アカウント ID を記録から隠してから、次の順に流し、最初の失敗で止まる。デプロイの間は互いに止め合わない（アカウントが別で、それぞれが自分の最初の失敗で止まる）。
  1. 取り出したコミットが今の main の先頭であることの確認（下の「順番」）。
  2. Terraform：`scripts/terraform.sh --ci` の `init` と `apply`。CI の Terraform はこのスクリプトだけを通り、`terraform` を直接呼ばない。`workers_dev` では、apply の前にアカウントの `workers.dev` のサブドメインを確かめる。apply は承認を求めない（上の「手動の承認は置かない」）。
  3. 入力の検証：`scripts/deploy.sh --ci` が、設定ファイルのすべての入力（`admin_signing_keys` の行の `keyid` と公開鍵の一致を含む）を、何かを変える前に確かめる。issuer と管理用のホスト名は、`scripts/lib.sh` の `deployment_issuer_host` と `deployment_admin_host` だけから導く。`workers_dev` では、`cf deploy` の前に、デプロイ用のトークンでアカウントの `workers.dev` のサブドメインを確かめ、違えば何も変えずに止まる。
  4. ビルド：前のビルドの成果物を消してから、2 つの Worker を `cf build` でビルドする。2 つの `cloudflare.config.ts` は、環境変数 `IDP_HOSTING_MODE`、`IDP_ISSUER`、`IDP_ADMIN_HOST`、`IDP_D1_DATABASE_ID`、`IDP_RATE_LIMIT_NAMESPACE_ID`、`IDP_ADMIN_RATE_LIMIT_NAMESPACE_ID`、`IDP_ADMIN_SIGNING_KEYS` を読み、それぞれが自分の分を確かめる。D1 の ID は名前から引く。ビルドを変更の前に置くのは、入力の誤りとビルドの失敗で、何もデプロイされないうちに止まるため。
  5. D1 のマイグレーション（`0004` を含む）、IdP の Worker の `cf deploy`、管理用の Worker の `cf deploy` の順。管理用の Worker の `IDP` の Service Binding は、IdP の Worker の名前付きのエントリーポイント `IdpInternal` を指すので、IdP の Worker を先にデプロイする。
  6. 外からの確認。discovery と JWKS が https で issuer を名乗ること（署名鍵の前の最初のデプロイでは、IdP の Worker の設定の誤りの 500）。issuer のホスト名への平文の HTTP で、資格情報のない `GET` が IdP の Worker 自身の 308 で同じパスとクエリの https に移ること、`Authorization` か `__Host-` の Cookie を持つ `GET` が 404 で拒否されること（署名鍵の前は、すべてが 500 なので次のデプロイで確かめる）。`workers_dev` では、`workers.dev` が平文の要求を Worker より先に https へリダイレクトすることもあり（[ホスティングのモード](hosting-modes.md)の 7.2 の表。未確認）、そのときは同じ URL の https へのリダイレクトを受け付け、どちらが答えたかを記録に残す。`custom_domain` では、IdP の Worker の 308 だけを受け付け、301 はゾーンのルール（Always Use HTTPS など）が先に答えたものとして失敗にする。署名のない要求に、管理用の Worker が理由を含まない `forbidden`（403）を返すこと。`workers.dev` がモードのとおり（`workers_dev` だけ有効）で、プレビューの URL が両方の Worker で無効であること。確認の要求は、`workers.dev` のボット対策がライブラリの既定の `User-Agent` を拒否するので、自分の `User-Agent` を名乗る。mTLS、WAF、ゾーンのルールセットは確かめない（どれも IdP は持たない）。
- 1Password Environment の変数（デプロイごとに 1 つの Environment）：`CLOUDFLARE_ACCOUNT_ID`、`DEPLOY_CLOUDFLARE_API_TOKEN`（デプロイ用のトークン）、`TERRAFORM_CLOUDFLARE_API_TOKEN`（Terraform 用のトークン）、`R2_ACCESS_KEY_ID` と `R2_SECRET_ACCESS_KEY`（state のバケット）。トークンは役割の名前で置く。1Password の読み込みの step は、Environment のすべての変数をその step の出力にだけ置き（`export-env` を使わず、`GITHUB_ENV` に書かない）、後の step は、自分の `env` で名指しした出力だけを、道具が読む名前（`CLOUDFLARE_API_TOKEN`、`AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY`）で受け取る。Terraform の step は Terraform 用のトークンと R2 の認証情報だけを、デプロイの step はデプロイ用のトークンだけを受け取る。1Password の Workload Identity は、読み込む変数を選べず、Environment のすべてを読み込むので、Environment にはこの job が使う変数だけを置く。
- 順番：GitHub の `concurrency` は、workflow の全体で 1 つの実行だけを動かし、待っている古い実行を新しい実行で置き換えるが、実行の順番は保証しない。古い実行の再実行もできる。そのため、デプロイの job は、認証情報を読み込む前に、取り出したコミットが今の main の先頭（リモートから直接読む）であることを確かめ、違えば止まる。`scripts/deploy.sh --ci` も、何かを変える前に同じことを確かめる。古いマージが新しいマージの後にデプロイして、前に進むだけのマイグレーションの後で古いコードに戻すことを防ぐため。
- 依存の取得は `pnpm install --frozen-lockfile --ignore-scripts` で行う。ビルドは依存のスクリプトを必要としない（`pnpm-workspace.yaml` もどのスクリプトも許していない）。
- 残るリスク：`id-token: write` は job の全体に付き、依存の取得を含むすべての step が、この job の GitHub の OIDC トークンを要求できる（Takumi Guard と 1Password の認証の両方が同じ job で要るので、分けられない）。1Password の交換には、読み込みの step にだけ渡す秘密の連携の鍵（`OP_INTEGRATION_KEY`）も要るので、OIDC トークンだけでは 1Password Environment を読めない。残るのは、依存の取得のときの悪意のある依存が、この job の OIDC トークンを、同じ条件を信頼するほかのサービスに使うことと、デプロイの step の中で `cf build` が動かす Vite のビルド（依存のコード）がデプロイ用のトークンを見られること。どちらも、ロックファイルの固定と Takumi Guard で依存を絞ることで抑える。
- 前のビルドの成果物（`apps/*/.cloudflare`）は Git が無視するので、作業ツリーの確認では見えない。`scripts/deploy.sh` はビルドの前にこれを消し、デプロイするものが必ずその実行でビルドしたものになるようにする。
- 1Password の Workload ID、Environment ID、連携の鍵（`OP_WORKLOAD_ID`、`OP_ENVIRONMENT_ID`、`OP_INTEGRATION_KEY`）は、同じ名前の GitHub Environment の変数と secret がリポジトリのものより優先される。デプロイが 2 つ以上あるときは、デプロイごとの GitHub Environment に置き、それぞれのデプロイが自分の 1Password Environment だけを読むようにする。
- 手元からのデプロイ（`scripts/deploy.sh` を `--ci` なしで動かす）は、作業ツリーに変更がなく、HEAD がその場で取得した `origin/main` と同じときだけ動く。デプロイのメッセージに HEAD を記録するので、レビューされていないコミットや、ビルドしたものと違うコミットの名前を残さないため。比べる main は、明示した refspec で取得し直したもので、リモートの取得の設定が狭められていても古い値と比べない。手元の実行の表示には、xtrace でアカウント ID が出る（隠すのは CI の記録だけ）。

**PR の `terraform plan` の認証情報（例外）**

[1Password Environments と GitHub Actions](../deployment/secret.md) は、PR の検証の job に OIDC の権限も 1Password の認証情報も渡さないとしている。`terraform plan` は state と Cloudflare の現状を読むので、認証情報なしでは動かない。

- 例外として、plan の job にだけ、読み取り専用の Environment（plan 用の読み取り専用の API トークンと、state のバケットの読み取り専用の R2 の認証情報）を渡す。デプロイ用の Environment とは分ける。
- plan 用のトークンは、Terraform が持つもの（ゾーン、DNS、fail closed の設定など）の読み取りだけにし、D1 の権限は読み取りも含めて一切持たせない。Cloudflare API の D1 のクエリ（「Query D1 Database」と「Raw D1 Database Query」）は `D1 Read` の権限でも受け付けると書かれていて（それぞれの Accepted Permissions）、`D1 Read` があればユーザーのデータを読める可能性があるため（どこまでできるかは[未決事項](open-questions.md)で確かめる）。
- destination は、plan の workflow と、同じリポジトリのブランチからの `pull_request` のイベントに限り、GitHub Environment `production` は使わない。fork からの PR には渡さない。
- 理由：plan を PR に載せることで、基盤の変更をマージの前にレビューでき、手動の承認を置かない流れでの唯一の関門（PR のレビュー）を意味のあるものにするため。
- 残るリスク：読み取り専用なので、トークンが漏れても変更はできない。残るのは、そのトークンの範囲で読めるものの機密性。workflow の path を固定しても、そのトークンで何が動くかは限れない。同じリポジトリの PR は、plan の workflow も Terraform のコードも書き換えられ、Terraform は plan の時点でもコード（provider や data source）を動かすので、トークンを持ち出せる。そのため、範囲を読まれても困らないもの（基盤の設定）に絞り、D1 を外す。
- 1Password の destination で PR のイベントに限れるかは、実装の前に確かめる（[未決事項](open-questions.md)参照）。限れなければ、plan を PR に載せるのをやめ、main での apply の前の plan だけにする。

**API トークン**

- 役割ごとに分ける。どれもデプロイ先のアカウントに限り、アカウントごとに別のトークンを作る。アカウントを IdP が仕えるサービスと共有するときも、サービスのトークンを IdP に使わず、IdP の役割ごとに IdP のためだけのトークンを作る。
- ゾーンの権限は、すべて IdP のホスト名を持つゾーン 1 つに絞る（Cloudflare「Create API token」）。ホスト名には絞れない。`workers_dev` のモードでは、どのトークンにもゾーンの権限を持たせない（ゾーンがない）。D1 と Workers のスクリプトの権限はアカウント単位で、特定のデータベースや Worker に絞れない（Cloudflare「API token permissions」。[ドメインの置き場所](domain-placement.md)の共存の設計の 6）。
  - Terraform 用：`custom_domain` ではゾーンの読み取り（data source でゾーン ID を引く）。`workers_dev` ではゾーンの権限を持たせず、代わりにアカウントの `Workers Scripts Read` を持たせる。運用者の確認のスクリプトが、このトークンでアカウントの `workers.dev` のサブドメインを読むため（[ホスティングのモード](hosting-modes.md)の 1.1）。SSL と証明書の権限は持たせない（`infra/` はクライアント証明書も mTLS の割り当ても持たない。[ホスティングのモード](hosting-modes.md)の実装の順番の 7 で外した）。WAF とシングルリダイレクトの権限は持たせない（IdP はゾーンのルールセットを持たない）。fail closed の設定に要る Workers のルートの権限と DNS の権限は、Terraform がそれらを持つようになったときに足す。D1 の権限は持たせない。
  - デプロイ用：Workers の編集、マイグレーションのための D1 の編集。`custom_domain` では、Worker のカスタムドメインを付けるためのゾーンの Workers のルートの編集と DNS の編集も要る。`workers_dev` では、ゾーンの権限は要らない。アカウントの `workers.dev` のサブドメインは、CI のデプロイが `cf deploy` の前にこのトークンで確かめる（Cloudflare API「Get a Workers Subdomain」。`Workers Scripts` の読み取りが要る。編集の権限で足りるかは未確認）。手元では、運用者のスクリプトが Terraform 用のトークンで確かめる（[ホスティングのモード](hosting-modes.md)の 1.1）。必要な権限の正確な名前は、実装で `cf deploy` が成功する最小の組み合わせを確かめて記録する。ゾーンの DNS の編集はホスト名に絞れないので、ゾーンをサービスと共有すると、サービスのほかのレコードも変えられる（受け入れるリスク）。
  - plan 用（上の例外）：Terraform 用と同じ範囲の読み取りだけ。D1 の権限は読み取りも持たせない。
- D1 のデータベースの作成は、最初の構築のときだけ、運用者の手元の `cf` のセッションで行う（[ブートストラップ](../deployment/bootstrap.md)の段階 1）。CI のトークンには D1 の作成の権限を持たせない。
- どれも 1Password Environments と GitHub OIDC で、実行時に CI に渡す。
- break-glass 用の D1 のトークン（下記）は、範囲（IdP の D1 の編集）と短い有効期限を定めておくが、前もって作らない。

**ホスト名を変えるときの影響**

ホスト名はデプロイごとに決める値で、設定を変えれば別のホスト名で動かせる。ただし、運用を始めた後に変えると、次のことが仕様上避けられない。

- パスキーは RP ID（ホスト名）に紐付くので、全員がパスキーを登録し直す必要がある。
- `iss` が変わるので、RP からは別の IdP に見える。RP 側の設定と利用者の紐付けを移行する必要がある。ledger などの結合キー（`iss` + `sub`）も変わる。

そのため、本番のホスト名は最初のデプロイの前に決め、以後は変えない前提で運用する。

次の操作も issuer のホスト名を変えるので、同じことが起きる（[ホスティングのモード](hosting-modes.md)の 1.5、2.3）。

- ホスティングのモードの変更（`workers_dev` からカスタムドメインへの移行を含む）。稼働中のデプロイの切り替えではなく、新しいデプロイとして作り直す。
- `workers_dev` のモードでの、アカウントの `workers.dev` のサブドメインの変更（ダッシュボードで変えられる）。手放した古いサブドメインを別のアカウントが取れるかは未確認で、取れるなら古い issuer を信じている RP がなりすまされる。変えるなら、先にすべての RP の設定から古い issuer を外す。
- `workers_dev` のモードでの、IdP の Worker の名前の変更。名前はコードの定数で、変える PR は issuer の変更として扱う。

別のアカウントに作り直すときも、issuer のホスト名が変わるので、同じことが起きる。検証用のアカウントで登録したパスキー、RP の設定、`iss` + `sub` の紐付けは、本番のアカウントに引き継がない（上の「アカウントの移植性」を参照）。

**Cloudflare アカウント**

- カスタムドメインのモードでは、IdP の 2 つの Worker と D1 は、IdP のホスト名（issuer と管理用のホスト名）を持つゾーンと同じ Cloudflare アカウントに置く。Worker のカスタムドメインは自分のアカウントのゾーンにしか作れないため（[ドメインの置き場所](domain-placement.md)）。`workers.dev` のモードでは、ゾーンを持たず、アカウントの `workers.dev` のサブドメインに置く。
- 典型的には、そのアカウントは IdP が専属で仕えるサービス 1 つのアカウントで、IdP はサービスごとに 1 つ置く。ゾーンにはサービスのほかのホスト名も載ってよく、その共存の設計は[ドメインの置き場所](domain-placement.md)にまとめた。IdP 専用のアカウントは求めない（2026-11-09 の決定で、この制約を外した）。
- 1 つのアカウントに複数の IdP を置かない。D1 の API トークンの権限と Workers のスクリプトの権限は特定のデータベースや Worker に絞れずアカウント内のすべてに効くので、1 つの IdP の基盤の権限がほかの IdP の全利用者に及ぶため。`workers.dev` のモードでは、同じアカウントの Worker は互いに same-site にもなる（[ホスティングのモード](hosting-modes.md)の 2.2）。
- サービスとアカウントを共有すると、サービスの D1 と Workers の権限を持つ人とトークンは、IdP の D1 を読み書きでき、IdP の Worker を差し替えられる。1 日のリクエスト上限と D1 の上限もサービスと共有する。そのため、サービスの運用者が IdP の管理者と同じでないときは、IdP 専用のアカウントを持つ形（[ドメインの置き場所](domain-placement.md)の B か A1）を選ぶ。
- D1 は作成時に APAC リージョンを指定する。

**管理用の Worker**

- IdP の Worker とは別のホスト名に置く（カスタムドメインのモードでは同じゾーン、`workers.dev` のモードでは同じアカウントのサブドメイン）。IdP の Worker と同じ D1 をバインドする。
- 管理者は、要求ごとの RFC 9421 の署名を、許可リストの公開鍵で検証して確かめる。両方のモードで同じ（[管理 CLI と管理用の Worker](idpctl.md)、[ホスティングのモード](hosting-modes.md)の 3）。エッジでは何も止めず、管理用の Worker のゲートが拒否する。プレビューの URL は無効にし、カスタムドメインのモードでは `workers.dev` も無効にする。
- 管理者の署名鍵の許可リスト（`admin_signing_keys`）は、デプロイの設定ファイル（上の「デプロイごとの入力」）に置き、管理用の Worker の設定 `ADMIN_SIGNING_KEYS` として CI のデプロイでだけ変える。D1 には置かない。
- 管理用の Worker も、接続元の IP ごとの Rate Limiting バインディングを持つ。名前空間の ID は `admin_rate_limit_namespace_id` で、IdP の Worker と分ける。
- 経緯：管理用の Worker は[ホスティングのモード](hosting-modes.md)の実装の順番の 6 で署名だけで管理者を確かめるようになり、実装の順番の 7 で Terraform の mTLS の割り当てとクライアント証明書を外した。そのため、「SSL and Certificates Write」の権限はどのトークンにも要らない。

**D1 の API トークン（break-glass）**

- 日常の管理には使わない。管理操作はすべて管理用の Worker の管理 API で行う。
- 前もって作らない。どこ（キーチェーン、1Password、CI）にも常設しない。管理用の Worker が使えないときの break-glass に限って、その時点で、権限を IdP の D1 の編集だけに絞り、短い有効期限を付けて作り、`cf d1 query` で使う。作業が終わったら失効させる。
- このトークンは IdP の全データを書き換えられる基盤の権限で、共有コアの規則も監査ログも通らない（[管理 CLI と管理用の Worker](idpctl.md)の break-glass を参照）。

**署名鍵**

- Worker Secret は書き込み専用で、登録した値を読み出せない。署名鍵の正本とバックアップは 1Password の Vault のアイテムに置き、Worker Secret にはそこから登録する。鍵は上の生成スクリプトで生成し、平文のままディスクに書かない（[トークン設計](tokens.md)参照）。
- Worker Secret は、Ed25519 の鍵の current を常に置き、最初のローテーションの後は previous も置く。RS256 を有効にするときだけ、RSA の鍵（4096 bit）の current（とローテーションの後の previous）を足す。既定のデプロイは RSA の鍵を持たない（[トークン設計](tokens.md)参照）。
- Secret の名前は `SIGNING_KEY_ED25519_CURRENT`、`SIGNING_KEY_ED25519_PREVIOUS`、`SIGNING_KEY_RSA_CURRENT`、`SIGNING_KEY_RSA_PREVIOUS` に固定する。IdP の Worker の `cloudflare.config.ts` は Secret を宣言しない。最初のデプロイ（[ブートストラップ](../deployment/bootstrap.md)の段階 5）は鍵の登録（段階 5b）より前に走るので、宣言した Secret がないことでデプロイが止まる余地を残さないため。鍵がない間は、Worker 自身がすべてのリクエストを拒否する。
- IdP の Worker の `cloudflare.config.ts` は、issuer を環境変数 `IDP_ISSUER`、D1 の ID を `IDP_D1_DATABASE_ID`、Rate Limiting の名前空間の ID を `IDP_RATE_LIMIT_NAMESPACE_ID` で受け取る。デプロイのスクリプトが、issuer は `scripts/lib.sh` の `deployment_issuer_host` がモードから導いたホスト名（`issuer_host`、または `workers_dev_subdomain` から導いたもの）から、名前空間の ID はデプロイの設定ファイルの `rate_limit_namespace_id` から、D1 の ID は名前から引いて渡す。名前空間の ID がないか正の整数でなければ、issuer と同じく設定の評価が失敗する。どちらかが欠けているか形式が不正なら、設定の評価が失敗してデプロイは始まらない（fail-closed）。カスタムドメインのホスト名は issuer から導き、別の値として持たない。
- IdP の Worker も、管理用の Worker と同じく、Worker のバージョンのメタデータのバインディングを `CF_VERSION_METADATA` として持つ。本人によるパスキーの操作（登録リンクによる登録、追加、失効）で書く監査ログの `writer_version` は `idp@<バージョンの ID>` にする。バインディングがないか ID が空なら、署名鍵がないときと同じく、すべてのリクエストを拒否する。どの版のコードが書いたかを残せない監査ログの行を書かないため。
- RS256 を有効にするのも無効にするのも、RSA の Secret をスクリプトで登録するか外してデプロイすることで行う。無効にするのは、`RS256` を登録した client がないことを `idpctl clients_list` で確かめ、最後の client を `Ed25519` に変えてから ID トークンの有効期限（5 分）が過ぎた後にする（[トークン設計](tokens.md)参照）。
- 管理用の Worker は署名鍵をバインドしない。RS256 が有効かどうかは、IdP の Worker の内部のエントリポイント `IdpInternal` への Service Binding で discovery を読んで判断する（公開の `fetch` は使わない。[管理 CLI と管理用の Worker](idpctl.md)参照）。
- 同じデプロイの Worker を作り直すときは、1Password のアイテムから登録し直す。
- 別のアカウントに作り直すときは、鍵を引き継がず、生成スクリプトで新しい鍵を作る。issuer が変わるので、古い鍵で署名したトークンを新しいデプロイで受け入れる理由がないため。1Password のアイテムも、デプロイごとに別の名前にする（上の「デプロイごとの入力」）。

**ログ**

- 状態の変化は D1 の `audit_log` に記録する。Workers Logs は消えていく短期の記録で、障害の調査にだけ使い、外部に送らない。
- Workers Logs の無料枠は、今は 1 日 200,000 イベントで 3 日間残る（Cloudflare「Workers Logs」の「Pricing」）。2026 年 12 月 1 日からは Cloudflare Observability の料金に移り、Free は 1 日 0.5 GB の取り込みで 7 日間残る。1 日の上限に達すると、UTC 0 時のリセットまで新しいデータを取り込まない（Cloudflare「Pricing」（Observability）の「Plans」）。
- 形式は、リクエストごとに構造化した 1 行とし、ルート、結果、エラーの種類、`client_id`、`sub`、管理者の名前（管理用の Worker）を持たせる。管理用の Worker が拒否したリクエストは、要求が名乗った `keyid`（形が正しいときだけ）と拒否の理由だけを書く。署名の値、`nonce`、要求の本文は書かない。
- 書かないもの：トークン、認可コード、Cookie、IdP が発行する秘密、登録トークン、チャレンジ、`Authorization` ヘッダー、要求の本文。
- IdP は IP アドレスを書かない（設計原則 7）。悪用の調査には、ゾーンの分析（Security Analytics などのトラフィックの分析）を使う。IdP はゾーンのルールを持たないが、ゾーンへの要求の分析はルールがなくても見られる。
- **受け入れるリスク**：無料枠では、すべてのリクエストのログを残すことはできない。大量のリクエストでその日の取り込みを止められることもある。それでも、状態の変化は `audit_log` にすべて残る。これより厳密な記録が必要なら、有料のプランにするか、この IdP を使わない。

**D1 のバックアップ**

- 家族規模の運用なので、無料の範囲でできるベストエフォートにとどめる。D1 の Time Travel だけを使い、定期的な export は取らない。
- Time Travel は常に有効で、履歴の保持と復元に追加の費用はかからない。保持期間は Workers Free で 7 日（Workers Paid では 30 日）。データベースが D1 の production バックエンドにあることが前提になる（[未決事項](open-questions.md)で確認する）。

Time Travel だけに任せることで、次のリスクを受け入れる。

- 7 日より後に気付いた破損や誤操作は、復元できない。
- Cloudflare アカウントを失うと、データベースと履歴をまとめて失う。Time Travel はこれを守らない。
- データベースを削除した後も履歴が残るかはドキュメントに書かれていないので、削除したデータベースは復元できないものとして扱う。
