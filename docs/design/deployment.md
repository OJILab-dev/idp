# デプロイと設定

ホスト名などのデプロイ先に依存する値は、コードにも設計書にも書かず、デプロイごとの設定として与える。同じ実装をどのドメイン・どのアカウントにも置けるようにする。

**設定値**

- issuer の URL を 1 つの設定値（Worker の環境変数）として持つ。形式は `https://<ホスト名>` で、パス、クエリ、フラグメント、末尾のスラッシュは付けない。
- RP ID、WebAuthn の origin、discovery に載せる各エンドポイントの URL、アクセストークンの `aud` は、すべて issuer から導く。別々の設定値として持たない（値の食い違いを構造的に起こさないため）。
- 管理用の Worker も同じ issuer を設定として持ち、登録リンク（`/enroll#<token>`）の組み立てに使う。管理用のホスト名は、issuer とは別の設定値として持つ。
- リクエストの `Host` ヘッダーから issuer や origin を作らない。`Host` は送信側が自由に書き換えられるため。
- issuer が未設定、または形式が不正（`https` でない、パスが付いている、ホストが IP アドレスなど）なら、リクエストを処理せずエラーを返す（fail-closed）。

**デプロイの道具**

- Worker のデプロイ、D1 のマイグレーション、break-glass の D1 の操作は、すべて Cloudflare の `cf` CLI で行う。wrangler はどこにも使わない。`cf` は Worker のデプロイ（`cf deploy`。Cloudflare「Deploy your first Worker」）と D1 のマイグレーション（`cf d1 migrations apply`。Cloudflare「Wrangler to cf reference」）を挙げている。
- `cf` にドキュメント化されたコマンドがない操作は、Cloudflare API かダッシュボードで行い、wrangler で補わない。`cf` で足りるかどうかを実装の前に確かめる項目は[未決事項](open-questions.md)にまとめる。
- `cf` はベータで、コマンドが安定版の前に変わりうる（Cloudflare「Cloudflare CLI」）。
- CI では `cf` が `CLOUDFLARE_API_TOKEN` と `CLOUDFLARE_ACCOUNT_ID` を読む（Cloudflare「Use cf in CI」の「Provide credentials」）。

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
- 管理用の Worker が使えないときの break-glass に限って、権限を D1 の編集だけに絞り、短い有効期限を付けて発行し、`cf d1 query` で使う。作業が終わったら失効させ、常設しない。
- このトークンは IdP の全データを書き換えられる基盤の権限で、共有コアの規則も監査ログも通らない（[管理 CLI と管理用の Worker](idpctl.md)の break-glass を参照）。

**署名鍵**

- Worker Secret は書き込み専用で、登録した値を読み出せない。署名鍵の正本とバックアップは 1Password の Vault のアイテムに置き、Worker Secret にはそこから登録する。鍵は運用者が AI のセッションの外で生成し、秘密鍵は標準入力で渡して平文のままディスクに書かない（[トークン設計](tokens.md)参照）。
- Worker Secret は、Ed25519 の鍵の current と previous の 2 つを常に置く。RS256 を有効にするときだけ、RSA の鍵（4096 bit）の current と previous を足して 4 つにする。既定のデプロイは RSA の鍵を持たない（[トークン設計](tokens.md)参照）。
- RS256 を有効にするのも無効にするのも、運用者が RSA の Secret を登録するか外してデプロイすることで行う。無効にするのは、`RS256` を登録した client がないことを `idpctl clients_list` で確かめてからにする。
- 管理用の Worker は署名鍵をバインドしない。RS256 が有効かどうかは、IdP の Worker への Service Binding で discovery を読んで判断する。
- 再設定や別アカウントへの移行のときは、1Password のアイテムから登録し直す。

**D1 のバックアップ**

- 家族規模の運用なので、無料の範囲でできるベストエフォートにとどめる。D1 の Time Travel だけを使い、定期的な export は取らない。
- Time Travel は常に有効で、履歴の保持と復元に追加の費用はかからない。保持期間は Workers Free で 7 日（Workers Paid では 30 日）。データベースが D1 の production バックエンドにあることが前提になる（[未決事項](open-questions.md)で確認する）。

Time Travel だけに任せることで、次のリスクを受け入れる。

- 7 日より後に気付いた破損や誤操作は、復元できない。
- Cloudflare アカウントを失うと、データベースと履歴をまとめて失う。Time Travel はこれを守らない。
- データベースを削除した後も履歴が残るかはドキュメントに書かれていないので、削除したデータベースは復元できないものとして扱う。
