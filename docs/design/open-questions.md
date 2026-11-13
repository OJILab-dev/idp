# 未決事項・要検証

実装に入る前に決めること（有効・無効の持ち方と削除しない方針、管理 API の形、ブートストラップ、トークンのクレーム、デプロイのパイプライン、ログ、画面と多言語化を含む）は、すべて各トピックのドキュメントに記録した。決めていないことが見つかったら、ここではなく、そのトピックのドキュメントに決定として書く。ここに残すのは、実装の前に確かめる前提と、作りながら実測で確かめるものだけ。

**ホスティングのモードと署名による管理者の認証（[ホスティングのモード](hosting-modes.md)）**

設計は運用者が 2026-11-10 に承認した。管理者の認証は両方のモードで RFC 9421 の署名だけにする。次は、公式の資料で確かめられなかったので、実装とデプロイで確かめる。

- [ ] Workers の Web Crypto で ECDSA の P-384 と SHA-384 の署名を検証できるか（Cloudflare の対応表は曲線を挙げていない）。署名の値の形が r と s を 48 バイトずつ連結した 96 バイトであること。ローカルの workerd（`cf` が同梱する miniflare）では、実装の順番の 2 のテストベクタで確かめた（96 バイトの署名を検証でき、改ざんと DER の形を拒否する。[ホスティングのモード](hosting-modes.md)の 3.3）。残るのは本物の Workers での確認で、実装の順番の 6 のデプロイの後、ブートストラップの段階 6 で確かめる。できなければ Ed25519 に切り替えて管理者の鍵を作り直す（運用者の決定の 4）
- [ ] P-384 の署名の検証の CPU 時間が、無料枠の 10 ms の中で、管理操作のほかの処理と合わせて収まるか
- [ ] Workers の実行環境が、要求の URL のパスとクエリのパーセントエンコードを正規化するか（`@target-uri` の組み立てに効く。食い違うと正しい要求が `forbidden` になる、安全側の失敗）。ローカルの workerd では、実装の順番の 3 で、パーセントエンコードを含むパスとクエリの `request.url` がベクタの URL のまま届くことを確かめた（[ホスティングのモード](hosting-modes.md)の 3.12）。残るのは本物の Workers での確認で、実装の順番の 6 のデプロイの後に確かめる
- [ ] 管理用の Worker の Rate Limiting バインディングのしきい値（仮の値で 10 秒あたり 10 件）が、`idpctl` の正規の連続した操作を止めないこと
- [ ] D1 が、主キーへの書き込みを索引の行として別に数えるか（`admin_request_nonces` の書き込みの見込みに効く）
- [ ] D1 が `ALTER TABLE … ADD COLUMN` と、追加した列を確かめる挿入のトリガーを、ローカルと同じに扱うか（`0004` のマイグレーション）
- [ ] `workers.dev` で、`request.cf.tlsVersion` がカスタムドメインと同じ値（`TLSv1.2`、`TLSv1.3`）をとるか。`workers.dev` のエッジの TLS の最小バージョン
- [ ] `workers.dev` が平文の HTTP の要求を Worker に届けるか、エッジでリダイレクトするか
- [ ] `workers.dev` のバージョンの URL とデプロイメントの URL を、設定で無効にできるか（プレビューの URL は `previewUrls` で無効にできる）
- [ ] `workers.dev` で 1 日の要求の上限を超えたときに返るもの（ルートの fail closed の設定がない）
- [ ] Browser Integrity Check（BIC）で拒否された要求が、1 日の要求の上限に数えられるか
- [ ] Go の HTTP クライアントの既定の `User-Agent` が BIC で拒否されるか（`idpctl` は常に明示するので、結果によらず設計は変わらない）
- [ ] アカウントの `workers.dev` のサブドメインを変えた後、古いサブドメインを別のアカウントが取れるか（取れるなら issuer のなりすましになる。抑え方はサブドメインを変えないこと）
- [ ] 運用者のスクリプトが `curl` で読む Cloudflare API の「Get a Workers Subdomain」の応答が、`result.subdomain` にサブドメインのラベルだけを持つこと（固定した `cf` 1.0.0-beta.21 には同じ情報を出すコマンドがないので API で読む。[ホスティングのモード](hosting-modes.md)の 1.1）。`workers.dev` のモードの Terraform 用のトークンに、`Workers Scripts Read` を足せば足りること
- [ ] `workers.dev` のモードで `cf deploy` が、アカウントにサブドメインがないときに自分で作ろうとするか（`cf` の内部に、`workers.dev` のサブドメインを登録する処理がある）。運用者のスクリプトは、サブドメインがなければデプロイの前に止まる
- [ ] ブラウザとパスワードマネージャーが、Public Suffix List の私的な領域のホスト名（`workers.dev` の下）のパスキーを、カスタムドメインと同じに扱うか（e2e と、つなぐ予定の端末で確かめる）。e2e では、Chromium の仮想オーセンティケータが `idp.<サブドメイン>.workers.dev` を RP ID とするパスキーを作り、それでサインインできることを確かめた（e2e の `workers_dev` の実行）。残るのは、つなぐ予定の端末の実際のパスキーのプロバイダでの確認

**移植性のテストの `workers_dev` 版（[ホスティングのモード](hosting-modes.md)の実装の順番の 9）**

運用者が、ドメインを持たない 2 つ目の Cloudflare アカウントに、[ブートストラップ](../deployment/bootstrap.md)の段階 0 から 7 までを `workers.dev` のモードで通す。変えてよいのは、デプロイの設定ファイル（`deployments/<デプロイの名前>.tfvars.json`）の入力と、1Password とダッシュボードの前提の作業だけ。Terraform、スクリプト、CI の workflow、Worker のコード、手順の文書を変える必要が出たら、そこで止め、移植性の欠陥として先に直す（手順に手作業を足さない）。結果は未記入で、運用者が実行して埋める。

- [ ] 前提：アカウントにゾーンがなく、ドメインを 1 つも持たないこと。`workers.dev` のサブドメインをダッシュボードで作り、[ブートストラップ](../deployment/bootstrap.md)の警告を読んでから選んだこと。R2 の有効化、2 つの Rate Limiting の名前空間の ID の選択、役割ごとの API トークン（Terraform 用はゾーンの権限なし、`Workers Scripts Read` あり）、R2 の S3 互換の認証情報、1Password の Vault と Environment、GitHub Environment が、ブートストラップの前提のとおりそろっていること
- [ ] 段階 0：`deployments/workers-dev.tfvars.json.example` を写した設定ファイルが、`hosting_mode` を `workers_dev` にし、`workers_dev_subdomain` を持ち、`zone`、`issuer_host`、`admin_host`、廃止した入力を持たないこと。リポジトリにアカウント ID がないこと。すべてのスクリプトの入力の検証を通ること
- [ ] 段階 1 と 2：state のバケットと APAC の D1 が 2 つ目のアカウントにだけでき、マイグレーションのトリガーが更新と削除を拒否すること
- [ ] 段階 3 と 4：署名鍵と管理者の鍵の生成スクリプトが、秘密でない値だけを出力すること。サブドメインの確認のスクリプトが、正しいサブドメインで通り、`workers_dev_subdomain` をわざと違う値にしたときに何も変えずに止まること（確かめた後に戻す）。Terraform の plan がゾーンを引かず、資源を何も作らず変えないこと
- [ ] 段階 5 と 5b：CI のデプロイが、2 つの Worker を `idp.<サブドメイン>.workers.dev` と `idp-admin.<サブドメイン>.workers.dev` に公開し、カスタムドメインとプレビューの URL を作らないこと。`cf deploy` が、サブドメインを作ろうとしたり変えたりしないこと。署名鍵の登録の後に、IdP の Worker が鍵を読めること
- [ ] 段階 6：ブートストラップの段階 6 の共通の確認と、`workers.dev` のモードの確認（Browser Integrity Check と `User-Agent`、discovery の `issuer`、RP ID、`__Host-` の Cookie、同じアカウントのほかの Worker のホスト名での拒否）がすべて通ること。上の「ホスティングのモードと署名による管理者の認証」の `workers.dev` の項目（TLS のバージョン、平文の HTTP、バージョンの URL、1 日の上限、BIC と上限の数え方）の結果を、この実行で埋めること
- [ ] 段階 7：導いた管理用のホスト名に向けた `idpctl` で、自分のユーザー、登録リンク、パスキー、グループ、最初の RP、grant を作り、`access_check` で自分がその RP を使えること。つないだ RP が、導いた issuer で discovery、`/token`、`/userinfo` を呼べること
- [ ] 後片付けの確認：リポジトリにアカウント ID と D1 の ID が残っていないこと（`workers_dev_subdomain` は設定ファイルの入力なので残る）。最初のアカウントのデプロイ（カスタムドメインのモード）の plan が、この作業の前と変わらないこと
- [ ] 結果：（未記入。運用者が実行した日、通ったかどうか、止まった段階と直した入力か欠陥を書く）

**ゾーンをサービスと共有する構成（[ドメインの置き場所](domain-placement.md)の A2）**

決定と共存の設計は[ドメインの置き場所](domain-placement.md)に記録した。次は、ドキュメントで確かめられなかったので、最初のデプロイで確かめる。

- [ ] Workers の Rate Limiting バインディングを Workers Free で使えるか、料金がかかるか。ドキュメント（Workers の「Rate Limiting」、料金、上限のページ）に書かれていない。使えなければ最初の `cf deploy` が失敗する。IdP は WAF のレート制限ルールを持たない（[ドメインの置き場所](domain-placement.md)の決定 ③）ので、そのときは、IdP の Worker から D1 の書き込みの保護がなくなることを受け入れるリスクとして[無料枠](free-tier.md)に記録し直すか、別の数え方（Durable Objects など）を検討する
- [ ] `run_worker_first` を真にしたカスタムドメインの IdP の Worker に、平文の HTTP の要求が `http:` の URL のまま届き、Worker の 308 のリダイレクトが返ること（ゾーンの Always Use HTTPS が無効のとき。有効なら、エッジがその前にリダイレクトする）。ページ（`/signin`）も Worker を通ることを、平文の要求と TLS 1.2 の要求で確かめる。ローカルの workerd では e2e で確かめた
- [ ] `request.cf.tlsVersion` が、TLS 1.2 と 1.3 の接続でそれぞれ `TLSv1.2` と `TLSv1.3` になること（Cloudflare「Block on TLS」の例の綴り）。違えば、2 つの Worker がすべての要求を拒否するので、最初のデプロイの段階 6 で気付く
- [ ] API トークンの最小の権限の組み合わせ（Terraform 用はゾーンの読み取りだけで足り、ゾーンを 1 つに絞れること。デプロイ用は `cf deploy` が成功する最小の組み合わせ）。権限の一覧のページは 2 つの表で名前が食い違う
- [ ] ゾーンの持ち主がゾーンの TLS の最小バージョンを 1.2 以上にしているか（ブートストラップの前提。低ければ RFC 8996 の例外が実際に起きる）

**実装の前に必ず確かめること**

データモデル（[データモデル](data-model.md)参照）は、次が成り立つことを前提にしている。

- [ ] D1 が、マイグレーションで `CREATE TRIGGER … BEGIN SELECT RAISE(ABORT, …); END` を受け付け、実行時に、出来事の表の UPDATE と DELETE、`principals`、`users`、`clients`、`groups` の DELETE を拒否すること。D1 のドキュメント（Cloudflare「SQL statements」）はトリガーの可否を書いていない。設計の SQL は `sqlite3` と、ローカルの D1（`cf` が同梱する miniflare の workerd。`contract/test/schema.test.ts`）では確かめた。残るのは本物の D1 での確認。成り立たなければ、追記だけと削除しないことを共有コアの規則だけで守る形に見直し、break-glass での削除を防げないことを受け入れるリスクとして記録し直す
- [ ] D1 のバッチの中で、トリガーの `RAISE(ABORT, …)` がバッチ全体をロールバックすること（下の「D1 バインディングのバッチ」の確認と一緒に行う）。ローカルの D1 では、D1 アダプタの適合テスト（`packages/cloudflare/test/d1/conformance.test.ts`）で、アダプタを通しても成り立ち、ポートのエラーとして返ることを確認済み。残るのは本物の D1 での確認

管理 API（[管理 CLI と管理用の Worker](idpctl.md)参照）は、次を前提にしている。

- [ ] `Idempotency-Key` の draft（draft-ietf-httpapi-idempotency-key-header）の状態を、実装の直前にもう一度確かめる。2026-11-08 の時点では -08（2026-10-22）で、RFC になっていない。RFC になって §2.7 のステータスコードや、キーの形が変わっていれば、管理 API をそれに合わせる

デプロイのパイプライン（[デプロイと設定](deployment.md)参照）は、次を前提にしている。どれかが成り立たなければ、wrangler に戻さず、Cloudflare API かダッシュボードで行う形に設計を見直す。

- [ ] `cf`（`cf workers deployments` など）か Cloudflare API で、Worker を前のバージョンにロールバックできるか。Cloudflare「Rollbacks」はダッシュボードと `wrangler rollback` しか説明していない。できなければ、ロールバックはダッシュボードで行う手順にする
- [ ] Terraform の Cloudflare provider が、fail closed の設定を扱えるか。扱えないものは `cf` か Cloudflare API のスクリプトにする（[デプロイと設定](deployment.md)）
- [ ] `cf` で R2 のバケットを作れるか（Terraform の state のバケットは Terraform より先に要る）
- [ ] `cf` で D1 のデータベースを APAC のリージョンを指定して作れるか（plan のトークンから D1 の権限を外すため、D1 のデータベースは Terraform に置かない）。作れなければ、Cloudflare API の「Create D1 Database」のスクリプトにする
- [ ] 1Password Environments の GitHub Actions の destination を、plan の workflow の、同じリポジトリのブランチからの `pull_request` のイベントに限れるか。限れなければ、PR の `terraform plan` をやめる（[デプロイと設定](deployment.md)の例外を参照）
- [ ] `D1 Read` の権限だけのトークンで、Cloudflare API の D1 のクエリ（「Query D1 Database」と「Raw D1 Database Query」）を実行できるか、できるなら読み取りだけか書き込みもできるか。ドキュメントは両方の Accepted Permissions に `D1 Read` を挙げるが、実行できる文の範囲は書いていない。結果によらず、plan のトークンには D1 の権限を持たせない（[デプロイと設定](deployment.md)の例外を参照）。デプロイ用のトークンの範囲を見直すときの根拠にもする
- [ ] 移植性のテスト：本番の前に、[デプロイと設定](deployment.md)の「デプロイごとの入力」だけを新しく用意し、検証用のアカウントとは別の 2 つ目のアカウントに、[ブートストラップ](../deployment/bootstrap.md)の段階 0 から 7 までが、Terraform、スクリプト、CI の workflow、Worker のコードを変えずに最後まで通ること。あわせて、リポジトリにアカウント ID、ゾーン ID、D1 の ID が残っていないことを確かめる。通らなければ、直すのは入力の一覧か直書きの箇所で、手順に手作業を足さない
- [ ] 運用者の `cf auth login` のセッション（複数のアカウントにまたがりうる）の下で、`CLOUDFLARE_ACCOUNT_ID` を設定すると、`cf` がそのアカウントだけを対象にするか。`cf` 1.0.0-beta.21 のグローバルフラグにはアカウントを指定するものがない。従わなければ、アカウントごとの `--profile` か Cloudflare API のスクリプトにする（[デプロイと設定](deployment.md)の直書きの禁止を参照）
- [ ] `cf` で、D1 のデータベースの ID をリポジトリのファイルに書かずに、Worker の D1 のバインディングに渡せるか（デプロイのスクリプトが名前から引いた ID を渡す）。渡せなければ、スクリプトがデプロイのたびにバインディングの設定を生成し、コミットしない形にする
- [ ] Takumi Guard の下で、固定した pnpm のセットアップの Action と `pnpm install --frozen-lockfile` が動くこと（利用者は pnpm への対応を確認済み。実装で軽く確かめる）

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
- [ ] D1 バインディングのバッチが、途中で失敗したときに全体をロールバックするか（わざと 2 文目を失敗させて、D1 アダプタの適合テストで確認する。ローカルの D1 では `contract/test/schema.test.ts` と、D1 アダプタの適合テスト（`packages/cloudflare/test/d1/conformance.test.ts`）で確認済みで、残るのは本物の D1 での確認）
- [ ] D1 REST API のバッチが、途中で失敗したときに全体をロールバックするか。日常の管理では使わず、break-glass の `cf d1 query` で複数の文を流すときだけ関係する（[管理 CLI と管理用の Worker](idpctl.md)参照）
- [ ] Worker のバンドルサイズと起動時間が無料枠（圧縮前 64 MiB、起動 1 秒）に十分収まるか
- [ ] 正規のサインイン 1 回で、IdP の Worker の Rate Limiting バインディングに数えられるリクエスト数（しきい値の根拠）と、静的なページを含めて Worker に届くリクエスト数（1 日のリクエスト上限の見込みの根拠。[無料枠](free-tier.md)）
- [ ] カスタムドメインに割り当てた Worker でも fail closed を設定できるか（ドキュメントではルートの設定として説明されている）
- [ ] つなぐ予定の RP（Grafana など）が、`email` クレームなしでサインインとユーザーの作成をできるか（[トークン設計](tokens.md)参照）。できない RP は、RP 側の設定で本人に入力させられるかを確認する
- [ ] D1 のデータベースが production バックエンドにあり、Time Travel の対象になっていること（Cloudflare API の「Get D1 Database」（`GET /accounts/{account_id}/d1/database/{database_id}`、`D1 Read` の権限）の応答の `version` が `production` であることを確かめる。Time Travel のドキュメントは `version: production` のデータベースが Time Travel に対応するとしている（Cloudflare「Time Travel and backups」の「Support for Time Travel」）。`cf` で同じ情報を出すコマンドはドキュメントにないので、API で確かめる。[デプロイと設定](deployment.md)参照）
- [ ] 対象のブラウザで、条件付きメディエーション（パスキーの自動入力）と、WebAuthn Level 3 の `parseCreationOptionsFromJSON()`、`parseRequestOptionsFromJSON()`、`toJSON()` が使えるか（[認証フロー](authentication.md)の画面と言語を参照）
- [ ] サインインページの読み込みごとのチャレンジの書き込みを含めて、D1 の 1 日の書き込みが見込みに収まること（[無料枠](free-tier.md)参照）
- [ ] 正規の利用での Workers Logs の 1 日の取り込み量が、2026 年 12 月 1 日からの Free の上限（0.5 GB / 日）に十分収まること（[デプロイと設定](deployment.md)のログを参照）