# 管理 CLI と管理用の Worker（idpctl）

管理操作はすべて、IdP の Worker とは別のホスト名に置く管理用の Worker が、共有コアのユースケースとして実行する。手元の `idpctl` は、その HTTPS の管理 API を呼ぶだけの Go の薄いクライアントにする。管理者は、Cloudflare の managed CA が発行したクライアント証明書による mTLS と、管理用の Worker が持つ証明書のフィンガープリントの許可リストで確かめる。

このドキュメントでは、次の 2 種類の秘密を区別して書く。

- **管理者の秘密鍵（mTLS）**：管理者が自分で生成し、自分で持つ。クライアント証明書と対になり、管理 API への接続に使う。IdP は受け取らず、保存もしない。
- **IdP が発行する秘密（クライアントシークレット、登録トークン）**：管理用の Worker の共有コアが生成し、D1 にはハッシュだけを書く。

**構成**

- 管理用の Worker（`apps/admin-worker`）は、IdP の Worker と同じ D1 をバインディングで使い、共有コアの管理系のユースケースを管理 API として出す。`idpctl` の全 24 操作（下の一覧）は IdP のドメインの操作であり、すべて共有コアのユースケースとして実装する（[技術選定](technology.md)のコードの構成を参照）。
- 共有コアが持つもの：入力の検証、IdP が発行する秘密の生成とハッシュ、条件付きの SQL（パスキーの上限、最後の 1 本の規則など）、監査ログの行の組み立て、`grant_add` と `group_member_add` で新たに使えるようになるユーザーと client の組の計算。
- `idpctl` が持つもの：引数の解釈、管理 API の呼び出し、出力の整形、手元の入出力（管理者の秘密鍵を標準入力から読む、IdP が発行する秘密を `0600` のファイルに書く）だけ。ドメインの規則は評価せず、管理用の Worker が返すエラーをそのまま表示する。管理用の Worker が規則の唯一の判定者である。
- 管理 API の仕様（OpenAPI など）は共有コアの入力のスキーマから生成し、`idpctl` の Go の型はその仕様から生成する。仕様は Go と TypeScript の間の契約として扱う（[実装に依存しない契約](cross-language-contract.md)参照）。
- issuer は IdP の Worker と同じ値を管理用の Worker が設定として持ち、登録リンクの組み立てに使う。`idpctl` が持つ設定は、管理 API のホスト名だけにする。
- 管理用の Worker は、設定された管理用のホスト名へのリクエストだけを受け付ける。`workers.dev` とプレビューの URL は無効にする。そこでは mTLS も WAF のルールも効かないため。無効化を忘れても、下の Worker 側の再確認で拒否される。

**管理用の Worker に API を置く理由**

D1 を手元から直接操作する形（D1 REST API）をやめ、管理 API を置く。理由は次のとおり。

- 管理操作の規則（パスキーの上限、最後の 1 本の規則、無効化の確認、監査ログの行の形、入力の検証）を、共有コアの 1 か所だけに実装できる。手元のツールが D1 を直接書くと、同じ規則の実装が IdP の Worker と手元のツールの 2 つになる。
- 操作者を、操作する側の自己申告ではなく、サーバーが確かめた管理者として監査ログに残せる。
- 管理者ごとの独立した認証を持てる。D1 の API トークンは IdP の全データへの権限を 1 つの値で持ち、管理者を区別できない。

そのかわり、管理用のエンドポイントをインターネットに出すことになる。設計原則 1 は、次の形で保つ。

- IdP の Worker は OIDC とパスキーのエンドポイントだけを出し、管理系のコードをバンドルに含めない（[技術選定](technology.md)の境界を参照）。
- 管理 API は別のホスト名にだけ置き、エッジの mTLS で、有効なクライアント証明書を持たないリクエストを Worker に届く前に止める。
- 管理者の認証に IdP 自身は使わない。権限の根拠が守る対象の中に閉じること、IdP の欠陥がそのまま管理権限の奪取になること、IdP の障害時に直す手段も止まることを避けるため（[将来拡張](future-extensions.md)の管理権限の分離と同じ理由）。

**管理者の認証（mTLS）**

- クライアント証明書は Cloudflare の managed CA で発行する。自分の秘密鍵と CSR を使って発行でき（Cloudflare「Create a client certificate」）、API の発行要求が受け取るのは `csr` と `validity_days` だけである（Cloudflare API「Create Client Certificate」）。管理者の秘密鍵は Cloudflare にも IdP にも渡らない。
- managed CA の証明書は、Free、Pro、Business ではゾーンあたり有効なもの 100 枚までで、上限を上げるには API Shield 付きの Enterprise が要る（Cloudflare「Client certificates (mTLS)」の「Limits」）。家族規模の管理者の数には十分である。自前の CA（BYO CA）は Enterprise でしか使えない（Cloudflare「Bring your own CA for mTLS」の「Availability」）。Cloudflare Access の mTLS は Free プランに含まれない（Cloudflare One「Mutual TLS」の「Availability」）。
- 管理用のホスト名に mTLS を有効にし、WAF のカスタムルールで `(not cf.tls_client_auth.cert_verified or cf.tls_client_auth.cert_revoked)` に当たるリクエストを遮断する。`cf.tls_client_auth.cert_verified` は、有効だが失効した証明書にも `true` を返す（Cloudflare「cf.tls_client_auth.cert_verified」）。失効した証明書は、それを確かめる WAF のカスタムルールがなければ自動では遮断されない（Cloudflare「mTLS related features」の「WAF for Client Certificates」と「Certificate Revocation」）。そのため、失効の条件も同じルールに入れる。Free プランの WAF のカスタムルールでこのフィールドを使えるかは、実装の前に確かめる（[未決事項](open-questions.md)参照）。
- 管理用の Worker は、エッジの判定を信じきらず、自分でも fail-closed で確かめ直す。`request.cf.tlsClientAuth.certVerified` が文字列の `"SUCCESS"` であること（Workers では真偽値ではなく文字列で、証明書がなければ `"NONE"`、失敗なら `"FAILED:…"` になる）、`certRevoked` が `"0"` であること、`certFingerprintSHA256` が許可リストにあることの 3 つがそろわなければ拒否する（Cloudflare「Client certificate variables」の「Workers variables」）。値がない、形が違うなど判定できない場合も拒否する。
- 証明書の検証はアカウント単位の CA に対して行われ、同じアカウントのどのゾーンで発行した証明書でも、mTLS を有効にしたホストで通る（Cloudflare「Enable mTLS」の「CAs in use」）。IdP 専用のアカウントに置くのは、この範囲を IdP に閉じるためでもある（[デプロイと設定](deployment.md)参照）。

**許可リストによる管理者の確定**

管理者は、証明書の SHA-256 フィンガープリントから管理者の名前への許可リストで確定する。許可リストは管理用の Worker の設定としてリポジトリに置き、CI のデプロイでだけ変える。D1 には置かない。フィンガープリントは秘密ではない。

- **証明書の主体名で認可しない**：mTLS の認可は、証明書の CN や SAN で主体を決める形（Kubernetes の CN と O、SPIFFE の URI SAN、PostgreSQL の証明書認証など）が主流である。しかし managed CA はアカウント単位で検証するので、「SSL and Certificates Write」の権限を持つ人は、任意の主体名の証明書を発行して検証を通せる（Cloudflare API「Create Client Certificate」）。主体名で認可すると、管理者の権限が「証明書を発行できること」にまで下がる。許可リストは、証明書の発行に加えてデプロイの権限も求める。
- **すぐ締め出せる**：許可リストから消せば、その証明書はデプロイの時点で使えなくなる。Cloudflare の失効は、API で要求するとまず `pending_revocation` になり、非同期に `revoked` へ移る（Cloudflare API「Revoke Client Certificate」）。移るまでの時間は書かれていない。
- **管理 API から自分を足せない**：許可リストを D1 に置くと、管理者や盗まれた管理者の証明書が、管理 API で別の証明書を足せる。権限の根拠が守る対象の中に閉じるので、管理系を IdP の OIDC クライアントにしない理由（[将来拡張](future-extensions.md)参照）と同じ問題になる。
- SSH の `authorized_keys` と同じ形で、鍵（証明書）と人の対応を、守られる側の設定として持つ。
- **受け入れるコスト**：証明書を更新するたびに、許可リストを更新してデプロイする必要がある。新旧の証明書を一時的に両方載せ、移行が済んだら古いものを消して、Cloudflare でも失効させる。

**管理者の秘密鍵と証明書**

- 管理者の秘密鍵（mTLS）は、管理者が手元で生成し、CSR だけを Cloudflare に送る。鍵は ECDSA に限り、曲線は P-384 にする。NIST SP 800-57 Part 1 Rev. 5 §5.6.1.1 の Table 2 で、P-384 のセキュリティ強度は 192 bit、P-256 は 128 bit、RSA 2048 は 112 bit である。
- Cloudflare のドキュメントは managed CA が受け付ける CSR の鍵の種類を書いておらず、例は RSA 2048 だけなので、P-384 の CSR が受け付けられるかを実装の前に確かめる（[未決事項](open-questions.md)参照）。受け付けられなければ P-256 にし、RSA には戻さない。
- Ed25519 は使わない。Cloudflare Access の mTLS が CA の証明書に許す署名アルゴリズムは RSA と ECDSA だけで、Ed25519 はない（Cloudflare One「Mutual TLS」の「Prerequisites」）。Cloudflare の mTLS の学習パスも、現代の mTLS には楕円曲線暗号を勧めている（Cloudflare「mTLS related features」の「Customize Cipher Suites」。この節はエッジ証明書についての説明で、クライアント証明書の鍵の種類を定めたものではない）。
- IdP の署名鍵（[トークン設計](tokens.md)）とは別の鍵で、ここでの選択は署名鍵の種類を変えない。
- 秘密鍵は 1Password で管理する。`idpctl` は秘密鍵の PEM を標準入力からだけ読み、ファイルや引数では受け取らない。`op read` で渡すかどうかは管理者が決め、`idpctl` は 1Password に固有の機能を持たない。1Password のエージェントは SSH 用で、TLS のクライアント認証には使えない（1Password「1Password SSH Agent」）。
- 証明書は秘密ではないので、ファイルのパスで渡す。
- エージェント（AI）は、管理者の秘密鍵を生成、読み出し、受け渡ししない。

**操作の一覧**

書き込みの操作は、[認可](authorization.md)の管理の関心事で分類する。基盤の操作（署名鍵、Cloudflare の API トークンと証明書の発行、許可リストの変更、デプロイ）は `idpctl` の対象外。

- 読み取り：`users_list`、`user_get`、`clients_list`、`groups_list`、`grants_list`、`access_check`、`audit_tail`
- ユーザーの管理：`user_create`、`user_rename`、`user_disable`、`user_delete`、`enroll_link_issue`、`passkey_revoke`、`session_revoke`、`group_create`、`group_rename`、`group_delete`、`group_member_add`、`group_member_remove`
- RP の管理：`client_create`（public client は `--public`）、`client_set_redirects`、`client_rotate_secret`
- アクセスの管理：`grant_add`、`grant_remove`

**操作の分類**

各操作の分類は、共有コアでユースケースの隣にメタデータとして定義する。分類は、管理の関心事、読み取りか書き込みか、取り返しがつかないか（`user_delete`）、本人性を確定させるか（`enroll_link_issue`）の 4 つ。今の入り口は CLI だけで、すべての操作を出す。MCP などの別の入り口を足すとき（[将来拡張](future-extensions.md)参照）は、その入り口が出す範囲をこのメタデータから導き、取り返しのつかない操作と本人性を確定させる操作を出さない。入り口ごとに出す操作の一覧を手で持つと、誤って出してしまうため。

`audit_tail` は監査ログを新しい順に返し、対象（`user:<id>` など）で絞り込める。管理者はこれで、本人によるパスキーの追加と失効を含む出来事をいつでも確認できる。

`user_get` は、ユーザーのパスキーの一覧（credential ID、作成日時、最終使用日時、追加の経路、同期型かどうか）を返す。`passkey_revoke` はパスキーを 1 本ずつ失効させ、そのパスキーから作ったセッションだけを外部キーの連鎖で消す（[認証フロー](authentication.md)の復旧を参照）。本人による失効と同じく、最後の 1 本は失効できない。本数の確認は削除と同じ文の条件で行い、人の操作の誤りでユーザーを 0 本にしない。ユーザーを完全に締め出すときは `user_disable` か `user_delete` を使う。

`enroll_link_issue` は、発行の時点でパスキーの本数を確かめ、パスキーの上限（[実装に依存しない契約](cross-language-contract.md)参照）に達しているユーザーには発行しない。本人の目の前ではなく、管理者の側で失敗させるためである。無効化されたユーザーにも発行しない。発行から使用までの間に本人が追加することもあるので、IdP の Worker も登録の verify で上限を確かめる。どちらの確認も共有コアの同じ規則を使う。

ユーザーとグループの名前と削除は、次のように扱う。

- `user_rename` は表示名（`users.name`）を、`group_rename` はグループ名（`groups.name`）を変える。ID は変わらないので、`sub`、所属、grant はそのまま残る。変更前と変更後の名前を `detail_json` に残す。
- `user_delete` は、ユーザーを `principals` の行ごと消す。外部キーの連鎖で、パスキー、セッション、所属、grant、登録トークン、チャレンジ、認可コードも消える。消えた所属と grant は `detail_json` に残すので戻せるが、ユーザーとパスキーは戻せない（`sub` は再利用しないので、同じ人を作り直しても別のユーザーになる）。そのため取り返しのつかない操作として分類する。止めるだけなら、元に戻せる `user_disable` を使う。
- これらも他の書き込みと同じく、監査ログに 1 行を書く。

`access_check(user, client)` は、許可か拒否かに加えて、どの grant にマッチしたか（直接付与か、どのグループ経由か。または何が足りないか）を返す。

ユーザーとグループは同じ主体として扱う（[認可](authorization.md)参照）。

- `grant_add(principal, client)` と `grant_remove(principal, client)` は、主体を `user:<id>` か `group:<name>` で受け取る。どちらも同じ操作で、共有コアが主体の ID に解決してから `client_access` に書く。
- `grant_add` と `group_member_add` で存在しない主体やグループを指定すると、解決の段階か外部キーの制約で失敗する。打ち間違えた名前で、誰にもマッチしない grant が黙って作られることはない。
- `grant_add` と `group_member_add` は、新たに使えるようになるユーザーと client の組を共有コアで計算し、結果に含める。グループへの grant やメンバーの追加は複数の人の権限をまとめて広げるので、操作する人に影響の範囲が見えるようにするため。
- `group_create` は、メンバーと grant が 0 件のグループを作れる。`groups_list` は、グループごとにメンバーと client の一覧を返す。
- ユーザーとグループの削除は `principals` の行を消し、外部キーの連鎖で所属と grant も消す。

**IdP が発行する秘密の扱い**

- クライアントシークレットと登録トークンは、管理用の Worker の共有コアだけが生成する。どちらも使うときには平文で IdP の Worker に提示される値であり、256 bit の乱数であることを保証できるのはサーバーだけである。乱数は Workers の Web Crypto の `crypto.getRandomValues` で作る。D1 にはハッシュだけを書く。
- 平文は、発行した HTTPS の応答で 1 回だけ返し、応答には `Cache-Control: no-store` を付ける。管理用の Worker は平文をログに書かない。
- `idpctl` は受け取った平文を権限 `0600` のファイルに書き出し、パスだけを表示する。平文を標準出力に出さないので、AI のコンテキストにも流れない。
- 登録リンクは発行から 10 分で切れるので、管理者は本人に渡すその場で `enroll_link_issue` を実行し、メールではなく対面など信頼できる経路で渡す（[認証フロー](authentication.md)参照）。

**監査ログ**

- 管理用の Worker は管理操作を監査ログに書き、操作者として、許可リストで確定した管理者の名前と、使われた証明書のフィンガープリントを残す。本人のパスキー操作（登録リンクによる登録、本人による追加と失効）は IdP の Worker が同じ表に書く。セッション ID、トークン、シークレット、登録トークンは書かない（スキーマは[データモデル](data-model.md)参照）。失敗した操作も `failure` の行として記録する（IdP の Worker は成功の行だけを書く）。
- 操作者はサーバーが確かめた値なので、管理者が監査ログの行を管理 API で偽造したり消したりすることはできない。管理 API には監査ログを書き換える操作を置かない。
- **受け入れるリスク**：D1 の API トークンを持つ人（下の break-glass、基盤の権限）は、共有コアを通らずに D1 を書けるので、管理者の行も `actor` が `user` の行（本人によるパスキーの追加と失効）も偽造でき、行を消すこともできる。本人の行は、本人への通知をしない NIST の通知要件の例外を補う手段（[認証フロー](authentication.md)参照）なので、API トークンを持つ人に対しては、その補いが効かない。ただし API トークンはそれだけで全ユーザーの全操作ができる基盤の権限であり（[操作とリスク](operations-and-risks.md)参照）、監査ログでそれを防ぐことはもともとできない。家族規模の運用では、この限界を受け入れる。

**break-glass（管理用の Worker が使えないとき）**

- 管理用の Worker やその mTLS が使えないときは、基盤の権限で `cf` CLI の `cf d1 query <DATABASE_ID>` を、D1 の API トークンで実行する。`cf` はデータベースの名前ではなく ID を受け取り、既定でリモートのデータを対象にする（Cloudflare「cf for Wrangler users」の「What changes」）。`cf` はベータで、コマンドが安定版の前に変わりうる（Cloudflare「Cloudflare CLI」）。
- break-glass の書き込みは共有コアを通らないので、パスキーの上限などの規則は SQL を書く人が守る必要があり、監査ログの行も手で書かなければ残らない。日常の管理には使わないので、このことを受け入れる。
- D1 の API トークンは日常の管理には使わない。扱いは[デプロイと設定](deployment.md)にまとめる。
