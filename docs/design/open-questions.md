# 未決事項・要検証

実装に入る前に決めること（有効・無効の持ち方と削除しない方針、管理 API の形、ブートストラップ、トークンのクレーム、デプロイのパイプライン、ログ、画面と多言語化を含む）は、すべて各トピックのドキュメントに記録した。決めていないことが見つかったら、ここではなく、そのトピックのドキュメントに決定として書く。ここに残すのは、実装の前に確かめる前提と、作りながら実測で確かめるものだけ。

**実装の前に必ず確かめること**

データモデル（[データモデル](data-model.md)参照）は、次が成り立つことを前提にしている。

- [ ] D1 が、マイグレーションで `CREATE TRIGGER … BEGIN SELECT RAISE(ABORT, …); END` を受け付け、実行時に、出来事の表の UPDATE と DELETE、`principals`、`users`、`clients`、`groups` の DELETE を拒否すること。D1 のドキュメント（Cloudflare「SQL statements」）はトリガーの可否を書いていない。設計の SQL は `sqlite3` と、ローカルの D1（`cf` が同梱する miniflare の workerd。`contract/test/schema.test.ts`）では確かめた。残るのは本物の D1 での確認。成り立たなければ、追記だけと削除しないことを共有コアの規則だけで守る形に見直し、break-glass での削除を防げないことを受け入れるリスクとして記録し直す
- [ ] D1 のバッチの中で、トリガーの `RAISE(ABORT, …)` がバッチ全体をロールバックすること（下の「D1 バインディングのバッチ」の確認と一緒に行う）

管理 API（[管理 CLI と管理用の Worker](idpctl.md)参照）は、次を前提にしている。

- [ ] `Idempotency-Key` の draft（draft-ietf-httpapi-idempotency-key-header）の状態を、実装の直前にもう一度確かめる。2026-11-08 の時点では -08（2026-10-22）で、RFC になっていない。RFC になって §2.7 のステータスコードや、キーの形が変わっていれば、管理 API をそれに合わせる

デプロイのパイプライン（[デプロイと設定](deployment.md)参照）は、次を前提にしている。どれかが成り立たなければ、wrangler に戻さず、Cloudflare API かダッシュボードで行う形に設計を見直す。

- [ ] `cf`（`cf workers deployments` など）か Cloudflare API で、Worker を前のバージョンにロールバックできるか。Cloudflare「Rollbacks」はダッシュボードと `wrangler rollback` しか説明していない。できなければ、ロールバックはダッシュボードで行う手順にする
- [ ] Terraform の Cloudflare provider が、WAF のカスタムルールとレート制限ルール、CSR からのクライアント証明書、管理用のホスト名への mTLS の割り当て、fail closed の設定を扱えるか。扱えないものは `cf` か Cloudflare API のスクリプトにする
- [ ] `cf` で R2 のバケットを作れるか（Terraform の state のバケットは Terraform より先に要る）
- [ ] `cf` で D1 のデータベースを APAC のリージョンを指定して作れるか（plan のトークンから D1 の権限を外すため、D1 のデータベースは Terraform に置かない）。作れなければ、Cloudflare API の「Create D1 Database」のスクリプトにする
- [ ] 1Password Environments の GitHub Actions の destination を、plan の workflow の、同じリポジトリのブランチからの `pull_request` のイベントに限れるか。限れなければ、PR の `terraform plan` をやめる（[デプロイと設定](deployment.md)の例外を参照）
- [ ] `D1 Read` の権限だけのトークンで、Cloudflare API の D1 のクエリ（「Query D1 Database」と「Raw D1 Database Query」）を実行できるか、できるなら読み取りだけか書き込みもできるか。ドキュメントは両方の Accepted Permissions に `D1 Read` を挙げるが、実行できる文の範囲は書いていない。結果によらず、plan のトークンには D1 の権限を持たせない（[デプロイと設定](deployment.md)の例外を参照）。デプロイ用のトークンの範囲を見直すときの根拠にもする
- [ ] 移植性のテスト：本番の前に、[デプロイと設定](deployment.md)の「デプロイごとの入力」だけを新しく用意し、検証用のアカウントとは別の 2 つ目のアカウントに、[ブートストラップ](../deployment/bootstrap.md)の段階 0 から 7 までが、Terraform、スクリプト、CI の workflow、Worker のコードを変えずに最後まで通ること。あわせて、リポジトリにアカウント ID、ゾーン ID、D1 の ID が残っていないことを確かめる。通らなければ、直すのは入力の一覧か直書きの箇所で、手順に手作業を足さない
- [ ] 運用者の `cf auth login` のセッション（複数のアカウントにまたがりうる）の下で、`CLOUDFLARE_ACCOUNT_ID` を設定すると、`cf` がそのアカウントだけを対象にするか。`cf` 1.0.0-beta.21 のグローバルフラグにはアカウントを指定するものがない。従わなければ、アカウントごとの `--profile` か Cloudflare API のスクリプトにする（[デプロイと設定](deployment.md)の直書きの禁止を参照）
- [ ] `cf` で、D1 のデータベースの ID をリポジトリのファイルに書かずに、Worker の D1 のバインディングに渡せるか（デプロイのスクリプトが名前から引いた ID を渡す）。渡せなければ、スクリプトがデプロイのたびにバインディングの設定を生成し、コミットしない形にする
- [ ] Takumi Guard の下で、固定した pnpm のセットアップの Action と `pnpm install --frozen-lockfile` が動くこと（利用者は pnpm への対応を確認済み。実装で軽く確かめる）

管理用の Worker（[管理 CLI と管理用の Worker](idpctl.md)参照）は、次が成り立つことを前提にしている。どれかが成り立たなければ、実装に入る前に設計を見直す。

- [ ] Free プランの WAF のカスタムルールで、`cf.tls_client_auth.*` のフィールドを使えるか。ドキュメントは、クライアント証明書のフィールドが WAF のカスタムルールなどで使えるとは書いているが、プランごとの可否を書いていない。Workers の 1 日のリクエスト上限はアカウント全体で数えるので、管理用のホスト名へのリクエストが WAF で止まらず Worker に届くと、攻撃者は証明書なしで IdP のリクエスト上限を使い切れる（[無料枠](free-tier.md)参照）。Worker 側の再確認は不正なリクエストを拒否できるが、上限の消費は防げない
- [ ] Cloudflare の managed CA が、ECDSA P-384 の鍵の CSR を受け付けるか。ドキュメントには RSA 2048 の例しかない。受け付けなければ P-256 にする（RSA にはしない）
- [ ] `cf` CLI にクライアント証明書を扱うコマンドがあるか（`cf cli search "client certificate"` で確認する）。なければ、証明書の発行と失効はダッシュボードか API で行う

デプロイの道具を `cf` に揃えること（[デプロイと設定](deployment.md)参照）は、次が成り立つことを前提にしている。どれかが成り立たなければ、wrangler に戻さず、Cloudflare API かダッシュボードで行う形に設計を見直す。

- [ ] 2 つの Worker が、どちらも Vite plugin の経路（`@cloudflare/vite-plugin@beta`）でビルドとデプロイ（`cf build`、`cf deploy`）をできるか。`cf` は Vite plugin を宣言していないプロジェクトを Wrangler でビルドする（Cloudflare「Develop, build, and deploy」の「How `cf` runs your project」）
- [ ] `cf d1 migrations apply` で D1 のマイグレーションを適用できるか。ドキュメントはコマンド名と `--dir`、`--pattern`、`--table` を挙げるだけで、動作を説明していない（Cloudflare「Wrangler to cf reference」の「Configuration fields」）
- [ ] Worker Secret（署名鍵）を、平文をディスクに書かずに登録できるか（[ブートストラップ](../deployment/bootstrap.md)の段階 5b と、鍵のローテーションの登録の方法がこれで決まる）。`cf` は 1 つずつの Secret の登録にまだ対応しておらず、代わりに `cf deploy --secrets-file <PATH>` か `cf workers versions create` の `--secrets-file` で、新しいバージョンと一緒に Secret を上げられる（Cloudflare「Wrangler to cf reference」の「Commands not yet supported」）。入力は JSON か `.env` 形式のファイルで（Cloudflare「Develop, build, and deploy」の「Deploy」）、ファイルに書くと「平文のままディスクに書かない」規則に反する。標準入力やパイプ（`/dev/stdin` など）を受け付けるかはドキュメントにないので、これを確かめる。受け付けなければ、Cloudflare API かダッシュボードで登録する
- [ ] 段階 5b で登録した Worker Secret が、その後の CI の `cf deploy`（`--secrets-file` を付けない）で新しいバージョンに引き継がれるか（[ブートストラップ](../deployment/bootstrap.md)参照）。ドキュメントに書かれていない。引き継がれなければ、デプロイのたびに署名鍵を CI に渡すことになり、署名鍵を CI に持たせない方針と衝突するので、実装の前に設計を見直す
- [ ] Time Travel の復元を `cf` か Cloudflare API でできるか。Time Travel のドキュメントは Wrangler のコマンドでしか説明していない（Cloudflare「Time Travel and backups」）

RS256 を任意の機能として持つこと（[トークン設計](tokens.md)参照）は、次が成り立つことを前提にしている。

- [ ] 4096 bit の RSA 鍵による RS256 の署名が、無料枠の CPU 10 ms に収まるか。RSA の署名の計算量は、モジュラスの長さのおよそ 3 乗で増える。収まらなければ、実装の前に鍵の長さと RS256 の扱いを見直す。Ed25519 はすべての client の既定なので、RSA の署名の分の CPU 時間がかかるのは `RS256` を登録した client の ID トークンだけ

**実測・確認すること**

- [ ] 無料枠の CPU 10 ms に、WebAuthn 検証と、トークンの Ed25519 の署名が収まるか
- [ ] Workers の WebCrypto（標準の `Ed25519`）で、JWK の Ed25519 の秘密鍵をインポートし、`alg: Ed25519` の JWS を CPU の予算内で署名・検証できるか（Cloudflare の Web Crypto の対応表は Ed25519 の sign と verify、importKey を対応としている）
- [ ] つなぐ予定の各 RP の OIDC ライブラリが、`alg` が `Ed25519` の ID トークンを検証できるか。できない RP には `RS256` を登録し、RS256 を有効にする
- [ ] Ed25519（-8）のパスキーを、Workers の WebCrypto（標準の Ed25519）で検証できるか
- [ ] OpenID Foundation の Basic OP と Config OP のテストプランを全項目合格するか。特に、テストスイートが confidential client の認可リクエストに `code_challenge` を付けるか（付けなければ、PKCE を全 client で必須にする方針と衝突するので、テストスイートの設定で付けられるかを確かめる）と、パスキーのサインインを手動の操作で通して流せるか
- [ ] D1 バインディングのバッチが、途中で失敗したときに全体をロールバックするか（わざと 2 文目を失敗させて、D1 アダプタの適合テストで確認する。ローカルの D1 では `contract/test/schema.test.ts` で確認済みで、残るのは本物の D1 での確認）
- [ ] D1 REST API のバッチが、途中で失敗したときに全体をロールバックするか。日常の管理では使わず、break-glass の `cf d1 query` で複数の文を流すときだけ関係する（[管理 CLI と管理用の Worker](idpctl.md)参照）
- [ ] Worker のバンドルサイズと起動時間が無料枠（圧縮前 64 MiB、起動 1 秒）に十分収まるか
- [ ] 正規のサインイン 1 回で Worker に届くリクエスト数（WAF のしきい値の根拠）
- [ ] WAF のレート制限で遮断したリクエストが、Workers のリクエスト数に数えられないこと（ドキュメントには「Worker に届いたリクエストだけが数えられる」としか書かれていない。ダッシュボードの分析で確認する）
- [ ] カスタムドメインに割り当てた Worker でも fail closed を設定できるか（ドキュメントではルートの設定として説明されている）
- [ ] つなぐ予定の RP（Grafana など）が、`email` クレームなしでサインインとユーザーの作成をできるか（[トークン設計](tokens.md)参照）。できない RP は、RP 側の設定で本人に入力させられるかを確認する
- [ ] D1 のデータベースが production バックエンドにあり、Time Travel の対象になっていること（Cloudflare API の「Get D1 Database」（`GET /accounts/{account_id}/d1/database/{database_id}`、`D1 Read` の権限）の応答の `version` が `production` であることを確かめる。Time Travel のドキュメントは `version: production` のデータベースが Time Travel に対応するとしている（Cloudflare「Time Travel and backups」の「Support for Time Travel」）。`cf` で同じ情報を出すコマンドはドキュメントにないので、API で確かめる。[デプロイと設定](deployment.md)参照）
- [ ] 対象のブラウザで、条件付きメディエーション（パスキーの自動入力）と、WebAuthn Level 3 の `parseCreationOptionsFromJSON()`、`parseRequestOptionsFromJSON()`、`toJSON()` が使えるか（[認証フロー](authentication.md)の画面と言語を参照）
- [ ] サインインページの読み込みごとのチャレンジの書き込みを含めて、D1 の 1 日の書き込みが見込みに収まること（[無料枠](free-tier.md)参照）
- [ ] 正規の利用での Workers Logs の 1 日の取り込み量が、2026 年 12 月 1 日からの Free の上限（0.5 GB / 日）に十分収まること（[デプロイと設定](deployment.md)のログを参照）
- [ ] Cloudflare のクライアント証明書の失効を API で要求してから、`pending_revocation` が `revoked` になり WAF で遮断されるまでの時間（ドキュメントに書かれていない。それまでは許可リストから消すことで締め出す）
