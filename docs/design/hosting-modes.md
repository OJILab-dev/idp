# ホスティングのモード（運用者の決定 C の設計）

IdP の 2 つの Worker を、どこで公開するかをデプロイごとに選べるようにする設計。モードは 2 つある。

- **カスタムドメインのモード**（今の設計）：2 つの Worker を、同じ Cloudflare アカウントにあるゾーンのカスタムドメインに置く。
- **`workers.dev` のモード**：ゾーンを持たない。2 つの Worker を `<Worker の名前>.<アカウントのサブドメイン>.workers.dev` で公開する。ドメインを持たない人が fork してデプロイできるようにするためのモード（[デプロイと設定](deployment.md)の「アカウントの移植性」）。

`workers.dev` ではエッジの mTLS を使えないので、管理 API の管理者は HTTP Message Signatures（RFC 9421）で確かめる。この文書は、モードの切り替え、`workers.dev` での issuer と RP ID、RFC 9421 による管理者の認証、カスタムドメインのモードでも署名を使うか、`idpctl`、無料枠、リスク、実装の順番を決める。

前提は、運用者が選んだ ③（IdP はゾーンのルールセットを使わず、HTTPS へのリダイレクト、TLS 1.2 以上の確認、Rate Limiting バインディング、管理用の Worker の fail-closed の確認をすべて Worker に置く）である。③ は main に入った（#52）。既存の文書は、下の「追従する変更」のとおりこの文書に合わせた（実装の順番の 1）。

調べた日：2026-11-09。出典は末尾の表にまとめ、本文では記号（[R1] など）で示す。公式の資料で確かめられなかったことは「未確認」と書き、末尾の「未確認の事項」に集める。

## 運用者の決定（2026-11-10）

運用者は、下の「運用者に決めてもらうこと」の 4 つを次のとおり決めた。本文は、決定の後の形で書く。

1. **この設計を承認する**：モードの入力、`workers.dev` の issuer の形、RFC 9421 の形を、この文書のとおりにする。
2. **管理者の認証は、両方のモードで RFC 9421 の署名だけにする（4 の C）**：mTLS はすべて外す。外すものは、managed CA の利用、管理者のクライアント証明書、管理用のホスト名の mTLS のホスト名の割り当て、証明書のフィンガープリントの許可リスト（`ADMIN_ALLOWLIST`、`admin_allowlist`、`admin_client_certificates`）、`gate.ts` の `tlsClientAuth` の確認。撤去は実装の順番の 7 で行い、文書の追従（実装の順番の 1）では文書だけを変える。4 の A（mTLS だけ）と B（両方）は採らず、経緯として残す。
3. **管理用の Worker にも Workers の Rate Limiting バインディングを置く**：名前空間の ID は、デプロイごとの新しい入力 `admin_rate_limit_namespace_id` にする（6.2）。実装は実装の順番の 6 で行う。
4. **P-384 が workerd で検証できなければ Ed25519 に切り替え、管理者の鍵を作り直す**：確かめるのは実装の順番の 2（契約のテストベクタ）で、ベクタをローカルの workerd（`cf` が同梱する miniflare）で検証して決める。結果は 3.3 に書く。→ 2026-11-10 に、ローカルの workerd で P-384 の署名を検証できたので、ECDSA P-384 のままにする（3.3）。

移行の間の注意：実装の順番の 6 が main に入るまで、今のコードの管理用の Worker は mTLS と証明書のフィンガープリントの許可リストで管理者を確かめる。文書は決定の後の姿を書くので、それまでの運用（ブートストラップの段階 4 など）は[実行手順](../deployment/runbook.md)の「移行の間の手順」に従う。

## 決定の要約

1. モードはデプロイの設定ファイルの 1 つの値 `hosting_mode`（`custom_domain` か `workers_dev`）で選ぶ。既定値を持たない。ほかの設定は、すべてこの値から導くか、この値に合うことを確かめる。混ぜた設定は、デプロイの前、Worker の設定の組み立て、Worker の実行時の 3 か所で拒否する（fail-closed）。
2. `workers_dev` の issuer は `https://idp.<アカウントのサブドメイン>.workers.dev` で、RP ID はそのホスト名そのものにする。issuer はアカウントのサブドメインと Worker の名前に結び付き、後からカスタムドメインに移すと、全員のパスキーが使えなくなり、issuer が変わる。fork する人にはこれを最初に警告する。
3. 管理用の Worker は、管理者の秘密鍵による RFC 9421 の署名を、許可リストの公開鍵で検証して管理者を確定する。アルゴリズムは ECDSA P-384 と SHA-384（RFC 9421 §3.3.5）。リプレイは、`created` の時間窓と、D1 に保存する `nonce` の一意性で防ぐ。
4. **決定（運用者の決定の 2）**：カスタムドメインのモードでも、管理者の認証を署名だけにし、mTLS を外す。③ では WAF のカスタムルールを置かないので、mTLS は証明書のない要求を Worker の前で止めなくなり、mTLS に残る利点が小さい。2 つの認証の経路を持つより、1 つの経路を両方のモードで同じに保つ方が、検証する面が小さい。
5. 管理用の Worker にも、接続元の IP ごとの Rate Limiting バインディングを置き、名前空間の ID をデプロイごとの入力 `admin_rate_limit_namespace_id` にする（運用者の決定の 3。6.2）。
6. 実装は、文書の追従、契約、共有コア、`idpctl`、生成スクリプト、管理用の Worker の切り替え、mTLS の撤去、モードの入力の順に、積み重ねない PR で進める（最後の節）。

## 1. モードの切り替え

### 1.1 入力

デプロイの設定ファイル（`deployments/<デプロイの名前>.tfvars.json`）に `hosting_mode` を足す。値は `custom_domain` か `workers_dev` のどちらかで、既定値を持たない。書き忘れたデプロイは、Terraform、スクリプト、CI が処理を始める前に止まる（[デプロイと設定](deployment.md)のデプロイごとの入力と同じ規則）。

モードごとに、ほかの入力の扱いは次のとおり。「禁止」は、値が書かれていたらデプロイを止めることを指す。片方のモードの値が残っていると、どちらのモードで動いているかをレビューで読み違えるため。

| 入力 | `custom_domain` | `workers_dev` |
| --- | --- | --- |
| ゾーン（`zone`） | 必須 | 禁止 |
| issuer のホスト名（`issuer_host`） | 必須 | 禁止（下の 1.3 で導く） |
| 管理用のホスト名（`admin_host`） | 必須 | 禁止（下の 1.3 で導く） |
| アカウントのサブドメイン（`workers_dev_subdomain`、新設） | 禁止 | 必須 |
| 管理者の署名鍵の許可リスト（`admin_signing_keys`、新設） | 必須 | 必須 |
| 管理用の Worker の Rate Limiting の名前空間の ID（`admin_rate_limit_namespace_id`、新設） | 必須 | 必須 |
| 管理者の証明書の許可リストと CSR（今の `admin_allowlist`、`admin_client_certificates`） | 廃止（実装の順番の 7 で外す。それまでは今のまま） | 禁止 |
| ゾーンの単一資源の持ち主（`zone_singletons_owner`） | ③（#52）で廃止済み | 禁止 |
| D1、IdP の Worker の Rate Limiting の名前空間、R2、1Password、GitHub Environment の入力 | 必須 | 必須（同じ意味） |

`workers_dev_subdomain` は、アカウントの `workers.dev` のサブドメインのラベル（`<アカウントのサブドメイン>.workers.dev` の左の 1 ラベル）で、DNS のラベルの規則（英小文字、数字、ハイフンの 1〜63 文字、先頭と末尾はハイフンでない）に従う。アカウントの設定から引ける値だが、issuer を決める値なので、設定ファイルに明示してレビューを通す。デプロイのスクリプトは、Cloudflare API の「Get a Workers Subdomain」（`GET /accounts/{account_id}/workers/subdomain`。権限は `Workers Scripts Read` か `Workers Scripts Write`）[C4] で実際のサブドメインを読み、入力と違えば何も変えずに止まる。サブドメインがダッシュボードで変えられたとき、気付かずに別の issuer でデプロイしないため。`cf` に同じ情報を出すコマンドがあるかは未確認で、なければ API で読む。

### 1.2 モードが決めるもの

| 項目 | `custom_domain` | `workers_dev` |
| --- | --- | --- |
| IdP の Worker の公開 | カスタムドメイン（issuer のホスト名）だけ | `workers.dev` のルートだけ |
| 管理用の Worker の公開 | カスタムドメイン（管理用のホスト名）だけ | `workers.dev` のルートだけ |
| `cloudflare.config.ts` の `domains` | そのホスト名の 1 つ | なし |
| `cloudflare.config.ts` の `workersDev` | `false` | `true` |
| `cloudflare.config.ts` の `previewUrls` | `false` | `false` |
| mTLS のホスト名の割り当てとクライアント証明書（Terraform） | 置かない（実装の順番の 7 で外す） | 置かない（ゾーンがない） |
| 管理者の許可リストの種類 | 署名鍵 | 署名鍵 |
| Terraform のゾーンの data source | 使う | 使わない |
| HTTPS へのリダイレクト、TLS のバージョンの確認、Rate Limiting バインディング | Worker（③） | Worker（③。同じコード） |

- プレビューの URL は両方のモードで無効にする。`workers.dev` を有効にしても、プレビューとバージョンの URL は別のホスト名になり、issuer の確認でどうせ拒否されるので、出さない方が攻撃面が小さい。`workers.dev` を無効にしてもバージョン、プレビュー、デプロイメントの URL は無効にならない [W1]。プレビューの URL は `previewUrls` で消せるが、バージョンとデプロイメントの URL を設定で消せるかは未確認。どちらにしても、2 つの Worker はホスト名が設定と完全に一致しない要求を処理しない（今の確認のまま）。
- `workers.dev` のモードでは Worker の名前がホスト名のラベルになるので、63 文字以下、英数字とハイフン、先頭と末尾はハイフンでない、という制約を満たす必要がある [W1]。IdP の Worker の名前は `idp` で、管理用の Worker の名前もコードで固定する。デプロイごとの入力にはしない（ホスト名を決める値を増やさないため）。
- Worker の名前を変えると、`workers.dev` のモードでは issuer が変わる。名前はコードで固定し、変える PR は issuer の変更として扱う（下の 2.3）。

### 1.3 `workers_dev` のホスト名の導き方

- issuer のホスト名は `idp.<workers_dev_subdomain>.workers.dev`、管理用のホスト名は `<管理用の Worker の名前>.<workers_dev_subdomain>.workers.dev` にする。どちらも入力から導き、別の入力として持たない。issuer、RP ID、origin を 1 つの値から導く今の規則（[デプロイと設定](deployment.md)の設定値）を、モードにも広げる。
- 導いた値は、カスタムドメインのモードと同じ形で Worker に渡す（IdP の Worker と管理用の Worker の `ISSUER`、管理用の Worker の `ADMIN_HOST`）。Worker の中で issuer を扱うコードは、モードによって分けない。

### 1.4 fail-closed の検証

モードを混ぜた設定は、次の 3 か所で拒否する。どこか 1 か所が漏れても、残りが止める。

1. **デプロイの前**（デプロイのスクリプト、CI の最初の job、Terraform の変数の `validation`）：`hosting_mode` がない、知らない値、上の 1.1 の表で必須の入力がない、禁止の入力がある、のどれかで止まる。`workers_dev` では、API で読んだサブドメインが入力と違えば止まる。
2. **Worker の設定の組み立て**（2 つの Worker の `cloudflare.config.ts`）：同じ規則で、モードから `domains`、`workersDev`、`previewUrls` を導き、合わなければ例外で止まる（今の `workerConfig` が issuer の形を確かめて止まるのと同じ）。`custom_domain` で issuer のホスト名が `workers.dev` の下にあるもの、`workers_dev` で issuer のホスト名が `idp.<1 ラベル>.workers.dev` の形でないものも拒否する。
3. **Worker の実行時**：2 つの Worker に `HOSTING_MODE` を環境変数で渡す。Worker は設定の検証で、`HOSTING_MODE` と issuer（管理用の Worker では管理用のホスト名も）の形が上の規則に合うことを確かめ、合わなければすべての要求を拒否する（IdP の Worker は 500、管理用の Worker は `internal`。今の設定の誤りと同じ）。実行時の処理はモードで分岐しない。モードの値は、設定の食い違いを検出するためだけに使う。

### 1.5 モードを変えること

モードの変更は、稼働中のデプロイの切り替えではなく、issuer のホスト名の変更である。[デプロイと設定](deployment.md)の「ホスト名を変えるときの影響」がそのまま起きる（全員のパスキーの登録し直し、`iss` の変化、RP の設定と `iss` + `sub` の紐付けの移行）。そのため、モードは最初のデプロイの前に決め、変えるときは新しいデプロイとして作り直す。

## 2. `workers.dev` のモードの issuer と RP ID

### 2.1 ホスト名

- issuer は `https://idp.<アカウントのサブドメイン>.workers.dev` で、パス、ポート、末尾のスラッシュを付けない（今の issuer の形の規則のまま）。
- RP ID は issuer のホスト名そのもの（`idp.<アカウントのサブドメイン>.workers.dev`）にする。WebAuthn の origin は issuer と同じ。今の「RP ID と origin は issuer から導き、1 つに固定する」規則を変えない。
- `workers.dev` のサブドメインはアカウントに 1 つで、ダッシュボードで変えられる。Worker のホスト名は `<Worker の名前>.<アカウントのサブドメイン>.workers.dev` の形になる [W1]。

### 2.2 Public Suffix List と、RP ID と Cookie への影響

`workers.dev` は Public Suffix List の私的な領域（PRIVATE DOMAINS）に、Cloudflare の登録として載っている [P1]。そのため、`<アカウントのサブドメイン>.workers.dev` が登録可能なドメイン（サイト）になり、アカウントの中の Worker は互いに同じサイト（same-site）、別のアカウントの Worker とは別のサイトになる。これは次のように効く。

- **RP ID の範囲**：WebAuthn では、呼び出し元が指定できる RP ID は、呼び出し元の origin の有効なドメインと等しいか、その登録可能なドメインの接尾辞でなければならない [WA1 §4 の RP ID、§5.1.3、§5.1.4]。RP ID を issuer のホスト名そのものにするので、同じアカウントのほかの Worker（`<別の名前>.<アカウントのサブドメイン>.workers.dev`）は、このパスキーを使う WebAuthn の呼び出しをできない（issuer のホスト名は、ほかの Worker のホスト名の接尾辞ではない）。逆に RP ID を `<アカウントのサブドメイン>.workers.dev` に広げると、同じアカウントのすべての Worker がこの RP ID でパスキーを作り、使えるようになるので、広げない。`workers.dev` そのものは公開接尾辞なので RP ID にできない。
- **関連する origin の要求**：WebAuthn Level 3 は、RP ID のホストの `/.well-known/webauthn` に載せた別の origin からも、その RP ID を使えるようにする仕組みを持つ [WA1 §5.11]。IdP はこの文書を出さない。IdP の Worker は `/.well-known/webauthn` に応答しない（今のルートの表にないので 404）ことを、チェックリストの項目として確かめる（下の 3.11）。出すと、そこに載せた origin がこの RP ID のパスキーを使えるようになるため。
- **Cookie**：IdP の Cookie はすべて `__Host-` の接頭辞を持つ。`__Host-` の Cookie は `Secure` を持ち、`Domain` 属性を持たず、`Path=/` でなければ設定できない [CK1 §4.1.3.2]。そのため、同じアカウントのほかの Worker が `Domain=<アカウントのサブドメイン>.workers.dev` の Cookie で IdP の Cookie を上書きしたり、同じ名前の Cookie を送り込んだりすることはできない（Cookie tossing を防ぐ）。ほかの Worker は接頭辞のない Cookie を `Domain` 付きで設定できるが、IdP はそれを読まない。仕様は RFC 6265 の改訂の Internet-Draft（draft-ietf-httpbis-rfc6265bis-22）で、まだ RFC ではない。
- **same-site の隣人**：同じアカウントのほかの Worker からの要求は same-site なので、`SameSite=Lax` の Cookie が付く。IdP の状態を変える POST は `Sec-Fetch-Site` が `same-origin` であることを求め、same-site を通さない（[認証フロー](authentication.md)と[セキュリティ要件チェックリスト](security-checklist.md)のセッションと通信）。そのため、ほかの Worker からの CSRF は今の確認で止まる。カスタムドメインのモードでも、ゾーンのほかのホスト名（A2 ではサービスのホスト名）は same-site で、同じ確認で止めている。モードによる違いは、隣人がゾーンのホスト名かアカウントの Worker かだけである。
- 別のアカウントの `workers.dev` の Worker は、PSL により別のサイトなので、上のどれにも当たらない。

### 2.3 固定される値と、後から移すときの影響

`workers.dev` のモードの issuer は、次の 3 つのどれが変わっても変わる。

- アカウントの `workers.dev` のサブドメイン（ダッシュボードで変えられる [W1]）
- IdP の Worker の名前（コードで固定）
- モード（カスタムドメインへの移行）

issuer が変わると、[デプロイと設定](deployment.md)の「ホスト名を変えるときの影響」がすべて起きる。

- パスキーは RP ID に紐付くので、全員がパスキーを登録し直す。
- `iss` が変わるので、RP からは別の IdP に見える。RP の設定、RP の利用者の紐付け、ledger などの `iss` + `sub` の結合キーを移す必要がある。

これを和らげる仕組みとして、WebAuthn の関連する origin の要求 [WA1 §5.11] で、新しい origin から古い RP ID のパスキーを使い続ける形を検討したが、採らない。古いホスト名の Worker を残し続ける必要がある、`iss` の変化は避けられない、ブラウザが対応しているかを確かめていない（未確認）、上の 2.2 で出さないと決めた文書を出すことになる、の 4 つの理由による。

アカウントのサブドメインを変えた後、手放した古いサブドメインを別のアカウントが取れるかは、ドキュメントに書かれていない（未確認）。取れるなら、古い issuer を信じている RP は、別のアカウントが置いた Worker の discovery と JWKS を信じることになる（issuer のなりすまし）。カスタムドメインのモードでのドメインの期限切れと同じ種類のリスクで、抑え方は「サブドメインを変えない」ことと、変えるときは先にすべての RP の設定から古い issuer を外すことである。

### 2.4 fork する人への警告

`workers_dev` を選ぶ人には、[ブートストラップ](../deployment/bootstrap.md)と README の `workers.dev` のモードの説明の最初に、次を警告として書く。

- issuer と RP ID は、アカウントの `workers.dev` のサブドメインと Worker の名前で決まる。後からカスタムドメインに移ると、全員のパスキーの登録し直しと、すべての RP の設定の移行が要る。長く使うつもりなら、最初からカスタムドメインのモードを選ぶ。
- アカウントの `workers.dev` のサブドメインを変えない。Worker の名前を変えない。どちらも issuer を変える。サブドメインを手放すと、別のアカウントに取られるかもしれない（未確認）。
- Cloudflare は、本番の Worker を `workers.dev` ではなくルートかカスタムドメインで動かすことを勧めており、`workers.dev` を業務上重要でない個人や趣味のプロジェクト向けとしている [W1]。
- `workers.dev` へのすべての要求は Browser Integrity Check（BIC）を受け、無効にできない。ライブラリの既定の `User-Agent` を送る自動のクライアントは、Worker に届く前に Error 1010 で拒否される [W1]。RP のサーバーが discovery、JWKS、`/token`、`/userinfo` を既定の `User-Agent` で呼ぶと失敗しうるので、つなぐ RP ごとに確かめ、必要なら RP 側で `User-Agent` を設定する。
- 同じアカウントのほかの Worker は、IdP と same-site になる（上の 2.2）。IdP の確認で止まるが、アカウントにほかの Worker を置くなら、その Worker の権限を持つ人が IdP の Worker も差し替えられることに変わりはない（[ドメインの置き場所](domain-placement.md)の残るリスク）。

## 3. RFC 9421 による管理者の認証

この節は、管理用の Worker が要求ごとに管理者を確定する手順を決める。両方のモードで同じ手順を使う（運用者の決定の 2）。

### 3.1 なぜ RFC 9421 か

- `workers.dev` にはゾーンがないので、エッジの mTLS（managed CA とホスト名の割り当て）も WAF も使えない。Cloudflare Access の mTLS は Free にない（[管理 CLI と管理用の Worker](idpctl.md)）。Access のサービストークンは持参人の秘密で、盗まれた値がそのまま使えるので採らない（[ドメインの置き場所](domain-placement.md)の C）。
- RFC 9421 の非対称の署名は、秘密鍵を管理者の手元から出さずに要求ごとの証明を作れる。検証する側は公開鍵だけを持つ [R1 §7.3.3]。今の mTLS と同じく、管理者の秘密鍵は IdP にも Cloudflare にも渡らない。
- 署名は要求の中身（メソッド、URI、本文のダイジェスト、`Idempotency-Key`）に結び付くので、TLS を終端する中継が要求を書き換えても検出できる。

### 3.2 署名の形

署名は `Signature-Input` と `Signature` の 2 つのヘッダーで運ぶ [R1 §4.1、§4.2]。どちらも構造化フィールドの Dictionary で、管理用の Worker は次の形だけを受け付ける。

- **署名は 1 つだけ**：2 つのヘッダーはどちらもちょうど 1 つのメンバーを持ち、ラベルが一致する。ラベルの名前は解釈しない [R1 §7.2.5]。2 つ以上の署名を持つ要求は拒否する。複数の署名の扱いを決める必要をなくすため [R1 §7.2.6]。ヘッダーが繰り返されたもの、トレイラーで送られたものも拒否する（RFC 9421 は `Signature-Input` をヘッダーで送ることを勧めている [R1 §4.1]）。
- **対象のコンポーネント**：順序を含めて、次の並びと完全に一致するものだけを受け付ける。足りないものも、余計なものも拒否する。対象を固定すると、署名の対象の不足 [R1 §7.2.1] と、署名の対象の選び方による解釈の違いが起きない。
  - `"@method"`（[R1 §2.2.1]）
  - `"@target-uri"`（スキーム、ホスト、パス、クエリを含む要求の URI。[R1 §2.2.2]）
  - `"@authority"`（[R1 §2.2.3]。小文字にし、既定のポートを省く。`Host` ヘッダーではなく、この派生コンポーネントを使う [R1 §7.2.4、§7.5.4]）
  - `"content-digest"`（下の 3.4）
  - 本文が空でない要求だけ `"content-type"`。メソッドでは決めない。`POST` と `PUT` にも本文のない操作（登録リンクの発行、シークレットの再発行、所属と grant の追加）があり、`idpctl` はそれらに `Content-Type` を付けないため。本文が空なのに対象にあるもの、本文があるのに対象にないものは拒否する（RFC 9530 §6.3 は、ダイジェストを署名しても表現のメタデータを署名しないと改ざんの余地が残るとしている [R2 §6.3]）
  - `Idempotency-Key` ヘッダーを持つ要求だけ `"idempotency-key"`。ヘッダーがあるのに対象にないもの、対象にあるのにヘッダーがないものは拒否する。`Idempotency-Key` を求める操作でヘッダーがないことは、今のとおり共有コアの検証が `validation-failed`（400）にする（[管理 CLI と管理用の Worker](idpctl.md)）
- **パラメーター**：`created`、`nonce`、`keyid`、`tag` の 4 つをちょうど持つ [R1 §2.3]。
  - `created`：整数の UNIX 秒（下の 3.5）。
  - `nonce`：32 バイトの乱数を base64url（パディングなし）にした文字列。`Idempotency-Key` とトークンの形と同じで、[実装に依存しない契約](cross-language-contract.md)の厳格な base64url の規則で検証する。
  - `keyid`：署名に使った公開鍵の識別子（下の 3.7）。
  - `tag`：固定の文字列 `idp-admin`。ほかの用途の署名を管理 API の署名として受け付けないための、アプリケーション固有の値 [R1 §2.3、§7.2.7]。
  - `alg` と `expires` は持たせず、持つ要求は拒否する。アルゴリズムは許可リストの鍵から決め、要求の申告を受け付けない（RFC 9421 §3.2.1 は、鍵から決まるときに `alg` を禁じることをアプリケーションの要件の例として挙げる [R1 §3.2.1]。§3.2 の手順 6 は、複数の場所で指定されたアルゴリズムが食い違えば失敗させる [R1 §3.2]）。有効期限は検証する側の時間窓で決める（下の 3.5）。
  - 知らないパラメーターを持つ要求も拒否する。
- アプリケーションが定めた要件は、検証の手順の中で強制し、満たさない署名は失敗させなければならない [R1 §3.2.1]。上の規則は、どれも署名の検証の失敗として扱う。

### 3.3 アルゴリズム

ECDSA の P-384 と SHA-384（`ecdsa-p384-sha384`）にする [R1 §3.3.5]。

- 今の管理者の鍵は ECDSA P-384 で、生成スクリプト（`scripts/generate-admin-key.sh`）、1Password のアイテム、`idpctl` の鍵の読み込み（P-384 の確認を含む）をそのまま使える。NIST SP 800-57 Part 1 Rev. 5 の強度の議論（P-384 は 192 bit）も今の文書のまま保てる（[管理 CLI と管理用の Worker](idpctl.md)の管理者の秘密鍵）。
- 署名の値は、r と s をそれぞれ 48 バイトのビッグエンディアンにして連結した 96 バイトにする [R1 §3.3.5]。96 バイトでない値は拒否する。Web Crypto API の ECDSA の署名と検証も、この r と s を連結した形を使う（未確認：Workers の実装で確かめる。下の 3.12）。
- ECDSA の署名は確定的ではないので、検証は検証の関数で行い、署名し直して比べない [R1 §7.3.5]。
- ECDSA の署名には、同じ要求に対する別の有効な署名（s を n − s にしたもの）がある。リプレイの判定は署名の値ではなく、署名された `nonce` で行う（下の 3.6）ので、この性質は影響しない。
- **Workers での検証**：Cloudflare の Web Crypto の対応表は、ECDSA の `sign()` と `verify()`、`importKey()` を対応としている [W2]。ただし表は曲線を挙げていない。実装の順番の 2 で、ローカルの workerd（`cf` が同梱する miniflare 5.20261019.2-beta）で、契約のテストベクタを検証して確かめた（`packages/core/test/admin-signature-vectors.test.ts`）。workerd の Web Crypto は、P-384 の SPKI を `importKey()` で読み込み、r と s を連結した 96 バイトの署名を `verify()`（ECDSA、SHA-384）で検証できた。対象は、Node の Web Crypto で作って秘密鍵を捨てた固定の署名と、テストの実行時に作った鍵による正しい検証のケースすべての署名。1 バイト変えた基底、1 バイト変えた署名、95 バイトと 97 バイトの署名、ASN.1 DER の署名、許可リストにない鍵の署名は、どれも検証に失敗した。そのため、アルゴリズムは ECDSA P-384 のままにし、Ed25519 には切り替えない（運用者の決定の 4）。RFC 9421 の付録 B.2.6 の Ed25519 の例も同じ workerd で検証できたので、代わりの Ed25519 も使える状態にある。本物の Workers での検証は、実装の順番の 6 のデプロイで確かめる（[未決事項](open-questions.md)）。
- **`idpctl`（Go）での署名**：Go の標準ライブラリ `crypto/ecdsa` で P-384 の署名を作れる。`crypto/ecdsa` の署名は ASN.1 の形か r と s の整数で返るので、`idpctl` が 48 バイトずつに 0 で詰めて連結する [G1]。Ed25519 に切り替える場合も `crypto/ed25519` で署名できる [G2]。外部のライブラリは足さない。
- アルゴリズムは 1 つに固定する。許可リストの鍵が P-384 の SPKI でなければ、設定の誤りとしてすべての要求を拒否する。鍵とアルゴリズムの組を検証する側が決めることで、鍵の取り違えと格下げを防ぐ [R1 §7.3.4、§7.3.6]。

### 3.4 本文のダイジェスト（`Content-Digest`）

- すべての要求に `Content-Digest` を付け、署名の対象にする [R1 §7.2.8、R2 §2]。本文のない要求（`GET` と `DELETE`）は、空のバイト列のダイジェストを付ける。署名した空のダイジェストで、本文が足されたことを検出できる [R2 §6.3]。
- アルゴリズムは `sha-256` だけにし、Dictionary のメンバーがちょうど `sha-256` の 1 つで、値が 32 バイトのバイト列であるものだけを受け付ける。`sha-256` と `sha-512` は IANA の登録で Active で [R2 §5、§7.2]、Workers の Web Crypto は SHA-256 の `digest()` に対応している [W2]。ほかのアルゴリズムやメンバーを持つものは拒否する（受け取る側は任意のダイジェストを無視してよい [R2 §2] が、この IdP では 1 つの形に限る）。
- 管理用の Worker は、受け取った本文のバイト列（JSON として解釈する前、今の本文の大きさの上限の中）の SHA-256 を計算し、ヘッダーの値と定数時間で比べる。

### 3.5 時刻のずれの窓

- `created` が、管理用の Worker の今の時刻の 60 秒前から 60 秒後までの範囲にあるものだけを受け付ける。範囲の外は拒否する。最大の経過時間を決めることは、RFC 9421 がアプリケーションの要件の例として挙げている [R1 §3.2.1]。
- 60 秒の根拠：`idpctl` は要求を送る直前に署名し、再試行のたびに署名し直す（下の 5.2）ので、正規の要求の `created` は送信の時刻とほぼ同じになる。手元の時計が NTP で合っていれば、ずれは 1 秒より十分小さい。窓を広げると、保存する `nonce` の期間が延び、盗まれた要求を使える時間も延びる。
- 時計がずれた管理者の要求は `forbidden` になる。理由は返さない（下の 3.8）ので、`idpctl` は `forbidden` のときに、確かめることの一覧（時計、許可リスト、ホスト名）を標準エラー出力に出す。

### 3.6 リプレイの防止（`nonce` の保存）

- 管理用の Worker は、署名の検証と本文のダイジェストの確認がすべて通った後で、`nonce` を D1 の新しい表 `admin_request_nonces` に一意制約付きで挿入する。挿入が一意制約で失敗した要求は、リプレイとして拒否する。RFC 9421 は、`nonce` の一意性の強制をアプリケーションの要件の例として挙げ [R1 §3.2.1]、`nonce` と作成の時刻でリプレイを検出できるとしている [R1 §7.2.2]。
- 表は `nonce`（主キー）と `expires_at`（`created` に 60 秒を足した UNIX 秒）の 2 つの列だけを持ち、`expires_at` に索引を付ける。スキーマの SQL は、追従する変更で[データモデル](data-model.md)に書き、`0003` のマイグレーションに写す。管理者の名前は持たない（`nonce` はすべての管理者で一意であればよい）。
- 有効期限を過ぎた行は、`nonce` の挿入と同じバッチで消す。cron は置かない。登録トークンの発行が同じバッチで期限切れの行を消すのと同じ形（[管理 CLI と管理用の Worker](idpctl.md)）。`expires_at` を過ぎた `nonce` を持つ要求は、`created` の窓で必ず拒否されるので、行を消してもリプレイを通さない。
- 挿入は、管理操作の書き込みより前の別の文で行う。操作が後で失敗しても、`nonce` は使用済みのまま残る（同じ署名を使い直させない）。
- D1 への挿入が一意制約以外の理由で失敗したら、操作を行わず `internal`（500）を返す。リプレイかどうかを確かめられない要求を通さない（fail-closed）。
- **認証されない要求は D1 に書かない**：`nonce` の挿入は、署名の検証が通った後だけに行う。署名のない要求、許可リストにない鍵の要求、署名が通らない要求は、D1 に 1 行も書かない。

### 3.7 `keyid` と管理者の名前の対応（許可リスト）

- `keyid` は、管理者の公開鍵の SubjectPublicKeyInfo（SPKI）の DER の SHA-256 を、小文字の 16 進 64 文字で書いた値にする。生成スクリプトが今 1Password に保存している `public_key_sha256` と同じ値で、今の許可リストのフィンガープリントと同じ書き方にそろう。
- 許可リストは、デプロイの設定ファイルの新しい入力 `admin_signing_keys` に置き、管理用の Worker に `ADMIN_SIGNING_KEYS` として渡す。今の `ADMIN_ALLOWLIST` と同じく、D1 にも管理 API にも置かず、CI のデプロイでだけ変える（管理 API から自分を足せない）。
- 形は、`keyid`、`name`、`public_key` の 3 つのメンバーだけを持つオブジェクトの JSON 配列にする。`public_key` は SPKI の DER を base64（パディングあり）で 1 行に書く。`name` は今の管理者の名前の規則（英小文字、数字、ハイフンの 1〜64 文字）に従う。
- 管理用の Worker は設定の検証で、空の配列、JSON でない値、ほかのメンバー、`keyid` の形の誤り、P-384 の公開鍵として読み込めない `public_key`、`keyid` と `public_key` の SHA-256 の食い違い、`keyid` の重複を、すべての要求を拒否する設定の誤りにする。`keyid` を `public_key` から計算できるのに書かせるのは、レビューする人が 1Password の `public_key_sha256` と監査ログの値に照らし合わせられるようにするため。食い違いを拒否するので、書いた値と鍵がずれることはない。
- 1 人の管理者が、鍵の移行の間に複数の行を持ってよい。鍵を許可リストから消せば、そのデプロイの後は使えない。mTLS と違い、Cloudflare での証明書の失効の手順がなくなる。
- 要求の `keyid` は、許可リストを引く鍵としてだけ使う。許可リストにない `keyid` は拒否する [R1 §3.2 の手順 5]。検証には許可リストの公開鍵を使い、要求が名乗る鍵を信じない。

### 3.8 検証の順番とエラーの振る舞い

管理用の Worker は、安い確認から順に行い、D1 への書き込みを最後に置く。

1. ホスト名、スキーム、TLS のバージョン（今の確認のまま）
2. 接続元の IP ごとの Rate Limiting バインディング（新設。下の 6.2）
3. 本文の大きさの上限（今の確認のまま）
4. `Signature-Input`、`Signature`、`Content-Digest` の構造化フィールドとしての厳格な解析
5. 対象のコンポーネントとパラメーターが 3.2 の形であること
6. `keyid` が許可リストにあること
7. `created` が 3.5 の窓にあること
8. 署名の基底の組み立て [R1 §2.5] と、許可リストの公開鍵による ECDSA P-384 の検証
9. 本文の SHA-256 と `Content-Digest` の一致
10. `nonce` の挿入（3.6）

- 2 で上限を超えた要求は 429 を返す。problem details の `kind` を増やさず、本文のない 429 にし、`idpctl` は再試行しない（problem details でない応答として終了コード 1）。
- 4 から 10 のどこで拒否しても、今の `forbidden`（403）と同じ本文を返す。理由は返さない。どの確認で落ちたかは Worker のログにだけ書く（今の `GateRefusal` に理由を足す）。RFC 9421 の検証の失敗の理由を返すと、署名を作る側に推測の手がかりを与えるため。
- 10 の挿入が一意制約以外で失敗したときと、設定の誤りは `internal`（500）を返す（今と同じ）。
- 拒否した要求は、監査ログに行を書かない（今と同じ）。
- 検証を飛ばす経路を作らない。開発やテストのために検証を無効にする設定を持たない。RFC 9421 は、正しい署名のテストだけでは検証が実際に行われているかを確かめられないとし、正しくない署名で失敗することを確かめるよう求めている [R1 §7.1.1]。下の 3.11 の否定のテストで確かめる。

### 3.9 監査ログ

- 監査ログの `admin` の行は、今と同じく、許可リストで確定した管理者の名前を `admin_name` に持つ。
- 証明書のフィンガープリントの代わりに、署名を検証した鍵の `keyid`（SPKI の DER の SHA-256）を残す。同じ管理者の鍵のどれが使われたかを追える性質は変わらない。
- 列は次のように扱う。今の `admin_cert_sha256` の列は、`admin` の行で値を必須にする `CHECK` 制約を持つ（[データモデル](data-model.md)）。SQLite で `CHECK` を変えるには表を作り直す必要があり、追記だけの表を作り直すのは避けたい。そのため、`0004` のマイグレーション（`0003` は 3.6 の `admin_request_nonces`）で列 `admin_credential` を `ALTER TABLE … ADD COLUMN` で足し、値を `certificate`（`admin_cert_sha256` が証明書の DER の SHA-256）か `signing-key`（`admin_cert_sha256` が SPKI の DER の SHA-256）にする。`admin` の行に `admin_credential` を必須にし、`user` と `break_glass` の行には持たせないことは、挿入のトリガーで強制する。`0004` より前の行は `admin_credential` を持たず、すべて証明書の行である。`0004` は、書き込む側（管理用の Worker）が列を書くようになる切り替えの PR と同時に入れる。先に入れると、今の管理用の Worker の挿入がトリガーで拒否されるため。
- 署名だけにする決定（運用者の決定の 2）により、`0004` の後の `admin` の行は `signing-key` だけになり、トリガーは `certificate` を拒否する。
- 列の名前 `admin_cert_sha256` は、意味が「管理者の資格情報の SHA-256」に広がるが、名前を変えると表の作り直しが要るので残す。意味は[データモデル](data-model.md)と[実装に依存しない契約](cross-language-contract.md)の監査ログの行に書く。D1 の `ALTER TABLE … ADD COLUMN` とトリガーの組み合わせは、ローカルの D1 のスキーマのテストで確かめる（D1 の SQL の対応は未確認の項目がすでにある。[未決事項](open-questions.md)）。

### 3.10 鍵の生成と扱い

- 管理者の秘密鍵は、今と同じく、リポジトリのレビュー済みの生成スクリプトで生成し、`op` で 1Password に直接入れる。平文はディスクにも標準出力にも出さない。AI のコンテキストには、秘密鍵の値が一度も入らない（AGENT.md のセキュリティの規則のまま）。
- 生成スクリプトの変更点：CSR を作らず、デプロイの設定ファイルの `admin_signing_keys` に `keyid`、`name`、`public_key` の行を書く（今は `admin_client_certificates` に CSR を書いている）。出力は公開鍵と `keyid` だけにする。
- 今ある鍵（1Password のアイテム）は、新しい鍵を作らずに使える。アイテムは `public_key` と `public_key_sha256` を秘密でないフィールドとして持っているので、生成スクリプトに、既存のアイテムからこの 2 つだけを読んで許可リストの行を書くモードを足す。秘密鍵のフィールドは読まない。
- `idpctl` は秘密鍵の PEM を標準入力からだけ読む（今のまま）。管理者は `op read` の出力を渡すかどうかを自分で決める。

### 3.11 セキュリティ要件チェックリストの変わる項目

[セキュリティ要件チェックリスト](security-checklist.md)の「管理用の Worker（mTLS）」の節を、両方のモードに共通の「管理用の Worker（署名）」に置き換える。

外す項目：

- 管理用のホスト名の WAF のカスタムルールが、証明書のない要求などを遮断すること（③ でもともとなくなる）
- `certVerified`、`certRevoked`、`certFingerprintSHA256` の 3 つの再確認
- 同じアカウントで発行した証明書（サービスのものを含む）でも、許可リストにないものを拒否すること
- 管理用の Worker が `workers.dev` とプレビューの URL を無効にすること（モードの項目に置き換える）

足す項目：

- 署名のない要求、署名が 2 つ以上の要求、対象のコンポーネントが 3.2 の並びと 1 つでも違う要求、`alg` か `expires` か知らないパラメーターを持つ要求、`tag` が違う要求を、すべて `forbidden` で拒否する
- 許可リストにない `keyid`、許可リストの別の鍵で作った署名、96 バイトでない署名、署名の基底のどれか 1 バイトを変えた要求（メソッド、URI、ホスト、本文、`Content-Type`、`Idempotency-Key`）を拒否する
- `created` が窓の外の要求を拒否する
- 同じ `nonce` の要求の 2 回目を、署名が正しくても拒否する。期限切れの `nonce` の行を消した後でも、その `nonce` の古い要求は窓で拒否される
- `Content-Digest` がない、`sha-256` 以外、値が本文と合わない要求を拒否する
- 署名の検証が通らない要求は、D1 に書き込まない（`admin_request_nonces` にも監査ログにも行が増えない）
- どの理由で拒否しても、同じ `forbidden` の本文を返す
- 許可リストから消した鍵の署名は、そのデプロイの後は拒否する
- 管理 API に、許可リストと監査ログを変える操作がない（今のまま）
- 管理操作の監査ログの行は、管理者の名前と `keyid` と `admin_credential` を持つ
- 2 つの Worker は、設定のモードとホスト名の形が合わなければ、すべての要求を拒否する（1.4）
- IdP の Worker は `/.well-known/webauthn` に応答しない（2.2）
- `workers_dev` のモードで、バージョンとプレビューの URL のホスト名への要求を、2 つの Worker が処理しない
- 管理用の Worker は、署名を解析する前に、接続元の IP ごとの Rate Limiting バインディングで数え、上限を超えた要求を本文のない 429 で拒否する。バインディングがない、呼び出しが失敗した、接続元の IP が取れない要求も拒否する（6.2）

変えない項目：IdP の Worker のビルド成果物に管理系のモジュールが含まれないこと、IdP の Worker のホスト名で管理 API が応答しないこと、TLS のバージョンの確認、`Idempotency-Key` と秘密の扱い。

### 3.12 契約とテストベクタ

- 署名の形（3.2 から 3.7）は、Go の `idpctl` と TypeScript の管理用の Worker の間の契約なので、[実装に依存しない契約](cross-language-contract.md)に 1 行の取り決めとして書き、`contract/testdata/vectors.json` にテストベクタを置く。
- ベクタは、要求から作る署名の基底の文字列（本文あり、本文なし、`Idempotency-Key` あり、クエリあり、パーセントエンコードを含むパス）、`Content-Digest` の値、P-384 の公開鍵と署名（正しいものと、1 バイトずつ変えた否定のもの）を持つ。Go と TypeScript の両方のテストが同じベクタを検証する。ベクタの形は[実装に依存しない契約](cross-language-contract.md)に書いた。
- 署名のラベルは `sig1` に固定する。管理用の Worker はラベルの名前を解釈しない（3.2）が、`idpctl` が作る `Signature-Input` をベクタと 1 文字ずつ比べられるようにするため。
- `@target-uri` は、管理用の Worker が受け取った要求の URL から組み立てる。Workers の実行環境が要求の URL のパーセントエンコードを正規化するかは未確認で、`idpctl` の組み立てと食い違うと、正しい要求が `forbidden` になる（安全側の失敗）。実装の順番の 3 で、ローカルの workerd に共有コアの検証器を載せ、ベクタの要求を送って確かめた。パーセントエンコードを含むパスとクエリの要求で、Worker が受け取る `request.url` はベクタの URL と 1 文字も変わらず、すべての正しいケースが通り、否定のケースはすべて拒否された（`packages/core/test/admin-signature-vectors.test.ts`）。本物の Workers での確認は実装の順番の 6 のデプロイで行う。

## 4. カスタムドメインのモードでも署名を使うか

運用者は C（署名だけ）を採った（運用者の決定の 2）。A と B は採らず、下の比較は判断の経緯として残す。

### 4.1 選択肢

| 観点 | A：mTLS だけ（前の設計） | B：mTLS と署名の両方を求める | C：署名だけ（採用） |
| --- | --- | --- | --- |
| 管理者の信頼の根 | managed CA（アカウント単位）と、「SSL and Certificates Write」の権限と、許可リスト | A と C の両方 | 許可リストだけ |
| 証明書のない要求を Worker の前で止めるか | ③ で WAF のカスタムルールがなくなるので、止めない | 止めない | 止めない |
| 管理用の Worker の認証の経路 | モードで 2 つ（カスタムドメインは mTLS、`workers.dev` は署名） | モードで 2 つ（片方は両方） | 1 つ |
| ゾーンの単一資源 | mTLS のホスト名の割り当てが残る（`external` ではゾーンの持ち主との調整が要る） | 残る | なくなる |
| 鍵 | 証明書と秘密鍵 | 同じ鍵を使えば 2 つ目の要素にならない。別の鍵にしても、同じ 1Password のセッションで読むので、盗まれる経路は同じ | 秘密鍵だけ |
| リプレイと改ざん | TLS のセッションが守る | 署名も守る | 署名が守る（`nonce`、`Content-Digest`） |
| 実装の欠陥の影響 | 検証は Cloudflare のエッジと Worker の再確認 | 両方の欠陥が重ならなければ守られる | 署名の検証の欠陥が、そのまま管理者の認証の欠陥になる |
| D1 の書き込み | なし | 要求ごとに `nonce` | 要求ごとに `nonce` |
| fork する人に求めるもの | CSR、Terraform での証明書の発行、許可リスト | 両方 | 鍵の生成と許可リスト |
| 未確認の前提 | managed CA の P-384 の CSR、失効の反映の時間 | 両方 | workerd の P-384 の検証、`@target-uri` の正規化 |

### 4.2 決定：C（署名だけ）

カスタムドメインのモードでも、管理者の認証を RFC 9421 の署名だけにし、mTLS（ホスト名の割り当て、クライアント証明書、`certVerified` などの再確認、証明書の許可リスト）を外す。理由は次のとおり。

- **mTLS の最大の利点が ③ で消える**：今の設計で mTLS を選んだ理由の中心は、エッジで証明書のない要求を Worker に届く前に止め、1 日のリクエスト上限を守ることだった（[管理 CLI と管理用の Worker](idpctl.md)の管理用の Worker に API を置く理由）。③ では WAF のカスタムルールを置かないので、ホスト名に mTLS を割り当てても、証明書のない要求は管理用の Worker に届く。残るのは、Worker の再確認とフィンガープリントの許可リストで、これは署名の検証と許可リストで置き換えられる。
- **署名の検証は、どうせ実装する**：`workers_dev` のモードのために署名の検証を実装し、検証する。A を残すと、管理者の認証の経路が 2 つになり、モードごとに別のテスト、別のチェックリスト、別の鍵の手順、別の `idpctl` の設定が要る。経路を 1 つにすれば、両方のモードが同じコードで動き、モードは公開の仕方だけの違いになる（[信頼できる唯一の情報源](../philosophy/system-design/single-source-of-truth.md)）。
- **信頼の根が狭くなる**：A では、アカウントの managed CA で証明書を発行できる人（A2 ではサービスのアカウントの「SSL and Certificates Write」を持つ人）が、エッジの mTLS を通れる。境界は許可リストだけで、エッジは 1 日の上限を守るだけだった（[ドメインの置き場所](domain-placement.md)の共存の設計の 5）。C では managed CA が信頼の根から外れ、管理者になるにはデプロイの権限（許可リストの変更）だけが要る。証明書の失効の反映の時間（未確認）を待つ必要もなくなる。
- **ゾーンの単一資源がなくなる**：③ でルールセットがなくなった後、IdP がゾーンに置くものは mTLS のホスト名の割り当てだけになる。これはゾーンの持ち主が 1 つのリポジトリで持つ資源で、`external` のときはゾーンの持ち主の apply が要る。C ではこれもなくなり、IdP はゾーンにカスタムドメイン以外のものを置かない。
- **B は足し算にならない**：B の 2 つの要素は同じ管理者の同じ 1Password から出るので、独立した要素にならない。B は A と C の両方の費用（managed CA、ゾーンの単一資源、`nonce`）を払い、得るものは実装の欠陥が重なったときの保険だけである。

C で受け入れること：

- 署名の検証のコードの欠陥が、そのまま管理者の認証の欠陥になる。抑え方は、対象とパラメーターを 1 つの形に固定した最小の検証（3.2）、否定のテストベクタ（3.11、3.12）、Go と TypeScript の両方で同じベクタを通すこと。
- 管理用の Worker は、認証の前に攻撃者の送った構造化フィールドを解析する。mTLS では Cloudflare が TLS の層で行っていたことで、解析の面が増える。解析器を小さく保ち、長さの上限を置き、不正な入力のテストを持つ。
- 管理者の認証が D1 に依存する（`nonce` の保存）。D1 が止まると管理 API も止まる。管理操作はもともと D1 を書くので、止まる範囲は今と変わらない。
- 署名の検証は要求ごとに CPU を使う。`keyid` は許可リストとしてリポジトリに公開されているので、攻撃者は正しい形の要求で検証を 1 回ずつ起こせる。検証の前に Rate Limiting バインディングで IP ごとに数える（6.2）。P-384 の検証の CPU 時間は実測で確かめる（未確認）。
- 設計原則 1 とゴールの「管理者は IdP 自身ではなく mTLS で確かめる」「エッジの mTLS で、管理者の証明書を持たないリクエストを Worker に届く前に止める」を書き換えた（追従する変更）。「IdP 自身ではなく、IdP の外の鍵で確かめる」性質は保つ。

採らなかった A では、モードが許可リストの種類と `idpctl` の認証の方法を決め、`idpctl` に `IDPCTL_AUTH`（`mtls` か `signature`）を必須の設定として持たせる案だった。C を採ったので、これらは作らない。

## 5. `idpctl`

### 5.1 設定と鍵

- `idpctl` はモードを知らない。どちらのモードでも、管理 API のホスト名（`--host` か `IDPCTL_HOST`）と、標準入力の秘密鍵だけで動く。`--cert` と `IDPCTL_CERT` は廃止する（実装の順番の 7）。
- 秘密鍵は、今と同じく標準入力からだけ読み、ECDSA の P-384 だけを受け付ける（今は P-256 も受け付けるが、P-256 は managed CA が P-384 の CSR を受け付けないときの代わりだったので外す）。秘密鍵のパスを受け取るフラグと環境変数は置かない。
- `keyid` は、読み込んだ秘密鍵の公開鍵から計算する。フラグでは受け取らない。手で書いた `keyid` と鍵が食い違う余地をなくすため。
- ホスト名の検証（英小文字の DNS 名だけ、スキーム、ポート、パス、IP アドレスを拒否する）は今のまま。`workers.dev` のホスト名もこの規則で受け付ける。

### 5.2 送信

- 署名は、要求を送る直前に、送るバイト列そのもの（メソッド、URL、`Content-Type`、本文、`Idempotency-Key`）から作り、3.2 の形の `Signature-Input`、`Signature`、`Content-Digest` を付ける。
- **再試行のたびに署名し直す**：今の `idpctl` は、応答が届かないときに同じ要求をそのまま送り直す。署名を付けた要求をそのまま送り直すと、前の試行が管理用の Worker に届いていた場合、同じ `nonce` のリプレイとして `forbidden` になる。そのため、再試行のたびに新しい `created` と `nonce` で署名し直す。`Idempotency-Key` と本文は変えないので、管理用の Worker が前の試行を処理していても、`Idempotency-Key` で同じ作成や追記が 2 回起きることはない（今の保証のまま）。
- **`User-Agent`**：すべての要求に `idpctl/<バージョン>` の `User-Agent` を付ける。`workers.dev` の BIC は、ライブラリの既定の `User-Agent` を Worker に届く前に拒否する [W1]。Go の HTTP クライアントの既定の `User-Agent` が拒否される値に当たるかは未確認なので、モードによらず常に明示する。
- 接続は今のまま、TLS 1.2 以上、システムのルート証明書でサーバーを検証し、リダイレクトに従わない。クライアント証明書は出さない。
- `forbidden` のときは、今の終了コード（19）のまま、確かめること（手元の時計、鍵が許可リストにあり、そのデプロイが済んでいること、ホスト名）を標準エラー出力に出す。

## 6. 無料枠

### 6.1 `workers.dev` の上限

- `workers.dev` の要求も、Workers Free の 1 日 10 万件の要求の上限（アカウント全体、UTC 0 時にリセット）に数えられる [W3]。カスタムドメインのモードと同じ上限を使う。
- ゾーンがないので、WAF とレート制限ルールを置けない。③ ではカスタムドメインのモードでもゾーンのルールを置かないので、この点でモードの差はない。
- 1 日の上限を超えたときの振る舞いは、ルートの fail open と fail closed で設定する [W3]。`workers.dev` にはルートの設定がなく、上限を超えたときに何が返るかは未確認（Error 1027 の見込み）。どちらにしても、Worker が動かないときに IdP の機能は何も提供されないので、認証を迂回されることはない（`workers.dev` には Worker のほかにオリジンがない）。
- BIC で拒否された要求は、Worker に届かず、Worker のログにも現れない [W1]。1 日の要求の上限に数えられるかは未確認。

### 6.2 認証されない要求が Worker に届くこと

- ③ では、どちらのモードでも、署名（や証明書）のない管理 API の要求が管理用の Worker に届き、1 日の上限を使う。止められないので、受け入れるリスクとして記録する（[無料枠](free-tier.md)の「上限を使い切らせる攻撃への備え」と同じ扱い）。
- 管理用の Worker にも、接続元の IP ごとの Rate Limiting バインディングを置く（運用者の決定の 3）。前の設計は「証明書のない要求はエッジで止まる」「拒否される要求は D1 も CPU もほとんど使わない」ことを理由に置いていなかったが、③ と署名の検証でその前提がなくなる。守るのは 1 日の上限ではなく、署名の検証の CPU 時間である。
  - 名前空間の ID は、デプロイごとの新しい入力 `admin_rate_limit_namespace_id` にする。IdP の Worker の `rate_limit_namespace_id` と同じ規則（アカウントの中で一意の正の整数で、同じアカウントのほかの Worker と重ならない値）に従い、IdP の Worker の値とも違う値にする。数えを共有すると、管理 API への要求で利用者のサインインが 429 になり、その逆も起きるため。
  - 期間は 10 秒、上限は仮の値で 10 件にする。`idpctl` は 1 回の実行で 1 つの要求（再試行を含めて既定で最大 3 回）を送るので、正規の連続した操作で超えにくい。実測で置き換える（[未決事項](open-questions.md)）。
  - 数えるのは 3.8 の 2 で、署名の解析より前、ホスト名、スキーム、TLS のバージョンの確認の後。署名の検証を通った管理者の要求も数える（検証の前に数えるので、区別できない）。
  - バインディングがない、呼び出しが失敗した、接続元の IP が取れない要求は拒否する（IdP の Worker と同じ fail-closed）。IP はキーとしてだけ使い、ログにも D1 にも書かない。
  - 実装は実装の順番の 6 で、`gate.ts` の置き換えと一緒に行う。
- 認証されない要求は D1 に書かない（3.6）。そのため、管理用の Worker への攻撃は、D1 の 1 日の書き込みの上限を使わない。

### 6.3 `nonce` の書き込みの費用

- D1 の書き込みは、`INSERT`、`UPDATE`、`DELETE` のどれも書いた行の数だけ数えられ、索引のある列への書き込みは索引の分も 1 行として数えられる [C1]。
- 管理者の要求 1 回あたり、`nonce` の挿入が 2 行（表と `expires_at` の索引）、前の要求の期限切れの行の削除が 1 行につき 2 行になる。行は 60 秒で期限切れになり、次の要求で消えるので、ならすと要求 1 回あたり約 4 行。家族規模の管理（1 日に数十回）では 1 日数百行で、10 万行の上限に対して小さい。
- 主キーの索引（`nonce`）は表そのものの B-tree なので、別の行として数えられないと見込むが、D1 の数え方の資料は主キーについて書いていない（未確認）。数えられても 1 回あたり 2 行増えるだけ。

## 7. リスクと、モードの間に残る違い

### 7.1 署名による管理者の認証のリスク

- 検証のコードの欠陥：上の 4.2 で受け入れたとおり。否定のテストベクタを、署名の基底のすべての要素について持つ。
- 鍵の盗難：今の mTLS の秘密鍵と同じ。1Password で管理し、許可リストから消せば次のデプロイで使えなくなる [R1 §7.3.2]。
- 時計への依存：管理者の時計が 60 秒以上ずれると管理 API を使えない。管理用の Worker の時計は Cloudflare のもの。
- 署名の盗聴とリプレイ：TLS が署名を守り [R1 §7.1.2]、窓と `nonce` がリプレイを止める。窓の中の同じ `nonce` は D1 の一意制約で 1 回だけ通る。
- D1 の可用性：管理 API はもともと D1 に依存するので、新しい依存ではない。

### 7.2 モードの間に残る違い

| 観点 | `custom_domain` | `workers_dev` |
| --- | --- | --- |
| issuer の身元を握るもの | ゾーンの DNS とアカウント | Cloudflare の `workers.dev`、アカウントのサブドメイン、Worker の名前 |
| issuer が変わる操作 | ホスト名の変更 | サブドメインの変更、Worker の名前の変更、モードの変更 |
| 手放した名前を他人が取るリスク | ドメインの期限切れ | サブドメインを変えた後の古いサブドメイン（取れるかは未確認） |
| 自動のクライアント（RP のサーバー、`idpctl`） | ゾーンの持ち主の BIC の設定しだい | BIC を無効にできない。既定の `User-Agent` は Error 1010 [W1] |
| Cloudflare の位置付け | 本番向け | 本番の利用を勧めていない [W1] |
| エッジの TLS の最小バージョン | ゾーンの持ち主の設定（RFC 8996 の例外） | Cloudflare が管理する `workers.dev` の設定で、IdP からは変えられず、値は未確認（同じ例外） |
| 平文の HTTP | Worker が扱う（③） | Worker が扱う（③）。`workers.dev` が平文の要求を Worker に届けるかは未確認 |
| same-site の隣人 | ゾーンのほかのホスト名 | アカウントのほかの Worker |
| ほかのホスト名で届く経路 | なし（カスタムドメインだけ） | バージョン、プレビュー、デプロイメントの URL（Worker のホスト名の確認で拒否する） |
| 管理者の認証 | 署名（同じ） | 署名 |
| 必要なもの | ドメイン 1 つとゾーン | なし |

- エッジの TLS の最小バージョン：どちらのモードでも、IdP はエッジの設定を持たず、Worker が `request.cf.tlsVersion` で 1.2 未満を拒否する（③）。`workers.dev` で `request.cf.tlsVersion` が同じ値をとるかは未確認で、違えば 2 つの Worker がすべての要求を拒否するので、最初のデプロイで気付く。

## 8. 運用者に決めてもらうこと

次の 4 つを諮り、2026-11-10 に冒頭の「運用者の決定」のとおり決まった。問いは経緯として残す。

1. この設計（モードの入力、`workers.dev` の issuer の形、RFC 9421 の形）を承認するか。→ 承認。
2. 4 の C（カスタムドメインのモードでも署名だけにし、mTLS を外す）を採るか。採らなければ A（モードで認証の方法を分ける）にする。→ C を採る。
3. 管理用の Worker にも Rate Limiting バインディングを置き、名前空間の ID の入力を 1 つ足すか（6.2）。→ 置く。入力は `admin_rate_limit_namespace_id`。
4. P-384 が workerd で検証できなかったとき、Ed25519 に切り替えて鍵を作り直すか（3.3）。→ 切り替える。どちらになるかは実装の順番の 2 のテストベクタで決める。

## 9. 追従する変更

この文書を足した PR（#51）では既存の文書を変えなかった（③ の作業と衝突させないため）。運用者が承認し、③ の PR（#52）が main に入った後、実装の順番の 1 の PR で次を直した。データモデルと生成スクリプトは、下に書いたとおり後の PR で直す。

- [README](README.md)：ゴールの「管理者は IdP 自身ではなく mTLS で確かめる」、設計原則 1 のエッジの mTLS、全体構成の図（`waf` の箱と「HTTPS（mTLS）」の矢印）と説明を、署名と両方のモードに合わせる。ドキュメント一覧の行の説明（idpctl、デプロイと設定、ドメインの置き場所）。
- [管理 CLI と管理用の Worker](idpctl.md)：冒頭、「管理者の秘密鍵（mTLS）」の定義、管理用の Worker の設定の名前（`ADMIN_SIGNING_KEYS`、`HOSTING_MODE`）、「管理用の Worker に API を置く理由」の mTLS の段落、「管理者の認証（mTLS）」と「許可リストによる管理者の確定」の節を 3 の内容に置き換える。「管理者の秘密鍵と証明書」の CSR と証明書の記述、`idpctl` の手元の振る舞い（`--cert` の廃止、`User-Agent`、再試行ごとの署名、429、`forbidden` の手がかり）、監査ログの節、break-glass の「管理用の Worker やその mTLS」。
- [デプロイと設定](deployment.md)：デプロイごとの入力の表（`hosting_mode`、`workers_dev_subdomain`、`admin_signing_keys`、`admin_rate_limit_namespace_id` を足し、`admin_allowlist`、`admin_client_certificates` を廃止の予定にする。`zone_singletons_owner` は ③ で外れた）、直書きの禁止のフィンガープリント、設定値のモード、Terraform とスクリプトの分担（クライアント証明書と mTLS の割り当てを外す、モードでゾーンを使わない）、API トークンの権限（「SSL と証明書」を外す、`workers_dev` でのゾーンの権限をなくす、サブドメインを読む `Workers Scripts Read`）、ホスト名を変えるときの影響にモードとサブドメインを足す、鍵の生成スクリプトの説明。
- [ドメインの置き場所](domain-placement.md)：決定の節に `workers_dev` のモードを足す。共存の設計の 2 のゾーンの単一資源の一覧から mTLS のホスト名の割り当てを外す、5 の managed CA の節を外す、残るリスクの managed CA の行を外す。経緯の C の評価は、この文書へのリンクで補う。未確認の事項の「Workers の Web Crypto で ECDSA P-384 の署名を検証できるか」を[未決事項](open-questions.md)に移す。
- [セキュリティ要件チェックリスト](security-checklist.md)：3.11 のとおり。
- [無料枠](free-tier.md)：6 のとおり（管理用の Worker のバインディング、`nonce` の書き込み、`workers.dev` の上限と BIC、管理用のホスト名を mTLS で止めるという記述の削除）。
- [データモデル](data-model.md)：`admin_request_nonces` の表（`0003` のマイグレーション）と、`audit_log.admin_credential` の列とトリガー（`0004`）の SQL のブロックを足し、`admin_cert_sha256` の意味を広げる。削除する行の一覧に `admin_request_nonces` を足す。SQL のブロックはマイグレーションと 1 対 1 でなければテストが失敗するので、文書の追従の PR ではなく、それぞれのマイグレーションを足す PR（下の 10 の 3 と 6）で書く。
- [実装に依存しない契約](cross-language-contract.md)：RFC 9421 の形（3.2 から 3.7）、`keyid` の形、`nonce` の形、テストベクタ。監査ログの行の `admin_cert_sha256` の説明。
- [操作とリスク](operations-and-risks.md)：「mTLS と許可リストで確定した管理者」の記述、「クライアント証明書の発行と失効」の行を外す、「許可リストの変更」の行を鍵に合わせる、`workers.dev` のサブドメインと Worker の名前の変更を基盤の操作として足す（issuer を変える）、「ゾーンのルールの適用」の行の mTLS。
- [技術選定](technology.md)：管理者の認証に触れる記述があれば合わせる。
- [未決事項](open-questions.md)：下の「未確認の事項」のうち、採った形に関わるものを移す。mTLS に関わる項目（Free の WAF の `cf.tls_client_auth.*`、managed CA の P-384 の CSR、`cf` のクライアント証明書のコマンド、失効の反映の時間）は外す。
- [ブートストラップ](../deployment/bootstrap.md)と[実行手順](../deployment/runbook.md)：段階 4 の鍵の生成（CSR なし、許可リストの行）、段階 6 の確認（署名のない要求が `forbidden` になること、`workers_dev` での BIC と `User-Agent`）、`workers_dev` のモードの前提（アカウントのサブドメインの作成、2.4 の警告）。
- [参考資料](references.md)：RFC 9421、RFC 9530、PSL、draft-ietf-httpbis-rfc6265bis、WebAuthn Level 3 §5.11、Cloudflare「workers.dev」と「Get a Workers Subdomain」。
- `AGENT.md`：「管理者の秘密鍵（mTLS）」の言い方と、鍵の生成スクリプトが出力する値（CSR を外し、`keyid` を足す）。
- `scripts/generate-admin-key.sh` のヘッダーと使い方の説明（実装の PR で直す）。

## 10. 実装の順番

PR は積み重ねず、それぞれ main から作り、前の PR が main に入ってから次を作る。並べて進められるものはそう書く。main へのマージはデプロイを起こす（[デプロイと設定](deployment.md)のデプロイのパイプライン）ので、管理者が締め出されない順番にする。

1. **文書の追従**：9 の変更を既存の文書に入れる。③ の PR が main に入り、運用者が 8 の 1 と 2 を決めた後。コードは変えない。（済み）
2. **契約**：[実装に依存しない契約](cross-language-contract.md)の取り決めに沿って、`contract/testdata/vectors.json` に RFC 9421 と `Content-Digest` のテストベクタ（正しいものと否定のもの）を足し、どちらの実装もまだ使わない形で検証の形を固める。スキーマは変えない。ベクタの署名をローカルの workerd で検証し、P-384 か Ed25519 かを決める（運用者の決定の 4）。（済み。P-384 のまま）
3. **共有コアの検証器**：[データモデル](data-model.md)の SQL から `0003` のマイグレーション（`admin_request_nonces` だけ。今の書き込みに影響しない）を写し、スキーマのテストを足す。管理系のモジュールに、RFC 9421 の検証（3.2 から 3.8 の 4 から 9）を純粋な関数として足し、`nonce` の保存のポートと D1 アダプタを足す。テストベクタとローカルの workerd で、P-384 の検証、`@target-uri` の組み立て、否定のケースを確かめる。アルゴリズムは 2 で決まったものを使う（運用者の決定の 4）。管理用の Worker からはまだ呼ばない。（済み。`nonce` の保存の D1 アダプタは、IdP の Worker が取り込まないよう `@idp/d1-adapter/admin` に分けた）
4. **`idpctl` の署名**（3 と並べて進められる）：すべての要求に署名と `Content-Digest` と `User-Agent` を付け、再試行のたびに署名し直す。今の管理用の Worker は知らないヘッダーを無視するので、mTLS のまま動き続ける。Go のテストで同じテストベクタを検証する。
5. **生成スクリプトと入力**（3、4 と並べて進められる）：`generate-admin-key.sh` が `admin_signing_keys` の行を書くようにし、既存の 1Password のアイテムから公開鍵だけを読んで行を書くモードを足す。デプロイの設定ファイルの検証と Terraform の変数に `admin_signing_keys` と `admin_rate_limit_namespace_id` を足す（まだ Worker には渡さない）。マージの後、運用者がスクリプトを実行し、検証用のデプロイの許可リストの行を PR で足す。
6. **管理用の Worker の切り替え**：3 から 5 が main に入り、許可リストの行がデプロイの設定ファイルにあることが前提。`gate.ts` を署名の検証に置き換え、`ADMIN_SIGNING_KEYS` を設定にし、`nonce` の保存、`0004` のマイグレーションと監査ログの `keyid` と `admin_credential`、`admin_rate_limit_namespace_id` を名前空間にした Rate Limiting バインディング、`HOSTING_MODE` の確認を足す。mTLS の再確認と `ADMIN_ALLOWLIST` を外す。マージのデプロイの後、ブートストラップの段階 6 の確認を署名で行う。締め出されたら、この PR を戻す。
7. **mTLS の撤去**（6 のデプロイの確認の後）：`idpctl` の `--cert` と `IDPCTL_CERT`、Terraform の mTLS のホスト名の割り当てとクライアント証明書、`admin_allowlist`、`admin_client_certificates` の入力を外す（`zone_singletons_owner` は ③ で外れた）。Terraform の apply は運用者が行う（クライアント証明書の削除を含む）。
8. **モードの入力と `workers.dev`**：`hosting_mode` と `workers_dev_subdomain` の入力、1.4 の 3 か所の検証、2 つの Worker の `cloudflare.config.ts` のモードによる組み立て、デプロイのスクリプトのサブドメインの確認、Terraform のモードによるゾーンの扱い。`custom_domain` の既存のデプロイは `hosting_mode` を足すだけで、ほかは変わらない。
9. **`workers.dev` のモードの確かめ**：ブートストラップと実行手順に `workers_dev` の道筋を足し、Playwright の e2e を `workers.dev` の形の issuer でも流す。運用者が、ドメインを持たない 2 つ目のアカウントに、入力だけで段階 0 から 7 までを通す（[未決事項](open-questions.md)の移植性のテストの `workers_dev` 版）。

## 未確認の事項

公式の資料で確かめられなかったもの。推測で埋めない。採った形に関わるものは、文書の追従で[未決事項](open-questions.md)の「ホスティングのモードと署名による管理者の認証」に移した。ここには、採らなかった形にだけ関わり、確かめなくても設計が変わらないものを残す。

- WebAuthn の関連する origin の要求に、対象のブラウザが対応しているか（採らないので、確かめなくても設計は変わらない）

## 出典

調べた日：2026-11-09。

| 記号 | 出典 |
| --- | --- |
| R1 | RFC 9421「HTTP Message Signatures」 https://www.rfc-editor.org/rfc/rfc9421 （§2.2.1〜§2.2.3、§2.3、§2.5、§3.2、§3.2.1、§3.3.5、§3.3.6、§4.1、§4.2、§7.1.1、§7.1.2、§7.2.1、§7.2.2、§7.2.4〜§7.2.8、§7.3.2〜§7.3.6、§7.5.4） |
| R2 | RFC 9530「Digest Fields」 https://www.rfc-editor.org/rfc/rfc9530 （§2、§5、§6.3、§7.2） |
| P1 | Public Suffix List https://publicsuffix.org/list/public_suffix_list.dat （PRIVATE DOMAINS の「Cloudflare, Inc.」の項に `workers.dev`） |
| WA1 | W3C「Web Authentication: An API for accessing Public Key Credentials Level 3」 https://www.w3.org/TR/webauthn-3/ （§4 の RP ID、§5.1.3、§5.1.4、§5.11、§5.11.1）。RP ID の規則は HTML Standard の「is a registrable domain suffix of or is equal to」を参照する |
| CK1 | draft-ietf-httpbis-rfc6265bis-22「Cookies: HTTP State Management Mechanism」 https://www.ietf.org/archive/id/draft-ietf-httpbis-rfc6265bis-22.txt （§4.1.3.2 の `__Host-` の接頭辞。RFC ではない Internet-Draft） |
| W1 | Cloudflare Workers「workers.dev」 https://developers.cloudflare.com/workers/configuration/routing/workers-dev/ （サブドメインの形、本番の利用、BIC と Error 1010、`workers_dev = false` で無効にならない URL、名前の制約） |
| W2 | Cloudflare Workers「Web Crypto」の「Supported algorithms」 https://developers.cloudflare.com/workers/runtime-apis/web-crypto/ |
| W3 | Cloudflare Workers「Limits」の「Daily requests」 https://developers.cloudflare.com/workers/platform/limits/ |
| C1 | Cloudflare D1「Pricing」 https://developers.cloudflare.com/d1/platform/pricing/ （書き込みの行の数え方、索引の行、Free の 1 日の上限） |
| C4 | Cloudflare API「Get a Workers Subdomain」 https://developers.cloudflare.com/api/resources/workers/subresources/subdomains/methods/get/ |
| G1 | Go 標準ライブラリ `crypto/ecdsa` https://pkg.go.dev/crypto/ecdsa |
| G2 | Go 標準ライブラリ `crypto/ed25519` https://pkg.go.dev/crypto/ed25519 |
