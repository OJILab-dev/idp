# 未決事項・要検証

実装に入る前に決めることは、すべて各トピックのドキュメントに記録した。残っているのは、実装の前に確かめる前提と、作りながら実測で確かめるものだけ。

**実装の前に必ず確かめること**

管理用の Worker（[管理 CLI と管理用の Worker](idpctl.md)参照）は、次が成り立つことを前提にしている。どれかが成り立たなければ、実装に入る前に設計を見直す。

- [ ] Free プランの WAF のカスタムルールで、`cf.tls_client_auth.*` のフィールドを使えるか。ドキュメントは、クライアント証明書のフィールドが WAF のカスタムルールなどで使えるとは書いているが、プランごとの可否を書いていない。Workers の 1 日のリクエスト上限はアカウント全体で数えるので、管理用のホスト名へのリクエストが WAF で止まらず Worker に届くと、攻撃者は証明書なしで IdP のリクエスト上限を使い切れる（[無料枠](free-tier.md)参照）。Worker 側の再確認は不正なリクエストを拒否できるが、上限の消費は防げない
- [ ] Cloudflare の managed CA が、ECDSA P-384 の鍵の CSR を受け付けるか。ドキュメントには RSA 2048 の例しかない。受け付けなければ P-256 にする（RSA にはしない）
- [ ] `cf` CLI にクライアント証明書を扱うコマンドがあるか（`cf cli search "client certificate"` で確認する）。なければ、証明書の発行と失効はダッシュボードか API で行う
- [ ] 無料プランで 1 つだけ作れるレート制限ルールに、管理用のホスト名も含められるか。含められなければ、管理用のホスト名は mTLS の WAF のルールだけで守る

デプロイの道具を `cf` に揃えること（[デプロイと設定](deployment.md)参照）は、次が成り立つことを前提にしている。どれかが成り立たなければ、wrangler に戻さず、Cloudflare API かダッシュボードで行う形に設計を見直す。

- [ ] 2 つの Worker が、どちらも Vite plugin の経路（`@cloudflare/vite-plugin@beta`）でビルドとデプロイ（`cf build`、`cf deploy`）をできるか。`cf` は Vite plugin を宣言していないプロジェクトを Wrangler でビルドする（Cloudflare「Develop, build, and deploy」の「How `cf` runs your project」）
- [ ] `cf d1 migrations apply` で D1 のマイグレーションを適用できるか。ドキュメントはコマンド名と `--dir`、`--pattern`、`--table` を挙げるだけで、動作を説明していない（Cloudflare「Wrangler to cf reference」の「Configuration fields」）
- [ ] Worker Secret（署名鍵）を、平文をディスクに書かずに登録できるか。`cf` は 1 つずつの Secret の登録にまだ対応しておらず、代わりに `cf deploy --secrets-file <PATH>` か `cf workers versions create` の `--secrets-file` で、新しいバージョンと一緒に Secret を上げられる（Cloudflare「Wrangler to cf reference」の「Commands not yet supported」）。入力は JSON か `.env` 形式のファイルで（Cloudflare「Develop, build, and deploy」の「Deploy」）、ファイルに書くと「平文のままディスクに書かない」規則に反する。標準入力やパイプ（`/dev/stdin` など）を受け付けるかはドキュメントにないので、これを確かめる。受け付けなければ、Cloudflare API かダッシュボードで登録する
- [ ] Time Travel の復元を `cf` か Cloudflare API でできるか。Time Travel のドキュメントは Wrangler のコマンドでしか説明していない（Cloudflare「Time Travel and backups」）

RS256 を任意の機能として持つこと（[トークン設計](tokens.md)参照）は、次が成り立つことを前提にしている。

- [ ] 4096 bit の RSA 鍵による RS256 の署名が、無料枠の CPU 10 ms に収まるか。RSA の署名の計算量は、モジュラスの長さのおよそ 3 乗で増える。収まらなければ、実装の前に鍵の長さと RS256 の扱いを見直す。Ed25519 はすべての client の既定なので、RSA の署名の分の CPU 時間がかかるのは `RS256` を登録した client の ID トークンだけ

**実測・確認すること**

- [ ] 無料枠の CPU 10 ms に、WebAuthn 検証と、トークンの Ed25519 の署名が収まるか
- [ ] Workers の WebCrypto（標準の `Ed25519`）で、JWK の Ed25519 の秘密鍵をインポートし、`alg: Ed25519` の JWS を CPU の予算内で署名・検証できるか（Cloudflare の Web Crypto の対応表は Ed25519 の sign と verify、importKey を対応としている）
- [ ] つなぐ予定の各 RP の OIDC ライブラリが、`alg` が `Ed25519` の ID トークンを検証できるか。できない RP には `RS256` を登録し、RS256 を有効にする
- [ ] Ed25519（-8）のパスキーを、Workers の WebCrypto（標準の Ed25519）で検証できるか
- [ ] OpenID Foundation の Basic OP と Config OP のテストプランを全項目合格するか
- [ ] D1 バインディングのバッチが、途中で失敗したときに全体をロールバックするか（わざと 2 文目を失敗させて、D1 アダプタの適合テストで確認する）
- [ ] D1 REST API のバッチが、途中で失敗したときに全体をロールバックするか。日常の管理では使わず、break-glass の `cf d1 query` で複数の文を流すときだけ関係する（[管理 CLI と管理用の Worker](idpctl.md)参照）
- [ ] Worker のバンドルサイズが 3 MB（圧縮後）に十分収まるか
- [ ] 正規のサインイン 1 回で Worker に届くリクエスト数（WAF のしきい値の根拠）
- [ ] WAF のレート制限で遮断したリクエストが、Workers のリクエスト数に数えられないこと（ドキュメントには「Worker に届いたリクエストだけが数えられる」としか書かれていない。ダッシュボードの分析で確認する）
- [ ] カスタムドメインに割り当てた Worker でも fail closed を設定できるか（ドキュメントではルートの設定として説明されている）
- [ ] つなぐ予定の RP（Grafana など）が、`email` クレームなしでサインインとユーザーの作成をできるか（[トークン設計](tokens.md)参照）。できない RP は、RP 側の設定で本人に入力させられるかを確認する
- [ ] D1 のデータベースが production バックエンドにあり、Time Travel の対象になっていること（Cloudflare API の「Get D1 Database」（`GET /accounts/{account_id}/d1/database/{database_id}`、`D1 Read` の権限）の応答の `version` が `production` であることを確かめる。Time Travel のドキュメントは `version: production` のデータベースが Time Travel に対応するとしている（Cloudflare「Time Travel and backups」の「Support for Time Travel」）。`cf` で同じ情報を出すコマンドはドキュメントにないので、API で確かめる。[デプロイと設定](deployment.md)参照）
- [ ] Cloudflare のクライアント証明書の失効を API で要求してから、`pending_revocation` が `revoked` になり WAF で遮断されるまでの時間（ドキュメントに書かれていない。それまでは許可リストから消すことで締め出す）
