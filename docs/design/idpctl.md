# 管理 CLI と管理用の Worker（idpctl）

管理操作はすべて、IdP の Worker とは別のホスト名に置く管理用の Worker が、共有コアのユースケースとして実行する。手元の `idpctl` は、その HTTPS の管理 API を呼ぶだけの Go の薄いクライアントにする。管理者は、Cloudflare の managed CA が発行したクライアント証明書による mTLS と、管理用の Worker が持つ証明書のフィンガープリントの許可リストで確かめる。

このドキュメントでは、次の 2 種類の秘密を区別して書く。

- **管理者の秘密鍵（mTLS）**：管理者が自分で生成し、自分で持つ。クライアント証明書と対になり、管理 API への接続に使う。IdP は受け取らず、保存もしない。
- **IdP が発行する秘密（クライアントシークレット、登録トークン）**：管理用の Worker の共有コアが生成し、D1 にはハッシュだけを書く。

**構成**

- 管理用の Worker（`apps/admin-worker`）は、IdP の Worker と同じ D1 をバインディングで使い、共有コアの管理系のユースケースを管理 API として出す。`idpctl` の全 28 操作（下の一覧）は IdP のドメインの操作であり、すべて共有コアのユースケースとして実装する（[技術選定](technology.md)のコードの構成を参照）。
- 共有コアが持つもの：入力の検証、IdP が発行する秘密の生成とハッシュ、条件付きの SQL（パスキーの上限、最後の 1 本の規則など）、監査ログの行の組み立て、`grant_add` と `group_member_add` で新たに使えるようになるユーザーと client の組の計算。
- `idpctl` が持つもの：引数の解釈、管理 API の呼び出し、出力の整形、手元の入出力（管理者の秘密鍵を標準入力から読む、IdP が発行する秘密を `0600` のファイルに書く）、`Idempotency-Key` の生成と自分の再試行での再利用だけ。ドメインの規則は評価せず、管理用の Worker が返すエラーをそのまま表示する。管理用の Worker が規則の唯一の判定者である。
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

- 管理者の秘密鍵（mTLS）は、リポジトリのレビュー済みの生成スクリプトで手元で生成し、CSR だけを Cloudflare に送る（[ブートストラップ](../deployment/bootstrap.md)参照）。鍵は ECDSA に限り、曲線は P-384 にする。NIST SP 800-57 Part 1 Rev. 5 §5.6.1.1 の Table 2 で、P-384 のセキュリティ強度は 192 bit、P-256 は 128 bit、RSA 2048 は 112 bit である。
- Cloudflare のドキュメントは managed CA が受け付ける CSR の鍵の種類を書いておらず、例は RSA 2048 だけなので、P-384 の CSR が受け付けられるかを実装の前に確かめる（[未決事項](open-questions.md)参照）。受け付けられなければ P-256 にし、RSA には戻さない。
- Ed25519 は使わない。Cloudflare Access の mTLS が CA の証明書に許す署名アルゴリズムは RSA と ECDSA だけで、Ed25519 はない（Cloudflare One「Mutual TLS」の「Prerequisites」）。Cloudflare の mTLS の学習パスも、現代の mTLS には楕円曲線暗号を勧めている（Cloudflare「mTLS related features」の「Customize Cipher Suites」。この節はエッジ証明書についての説明で、クライアント証明書の鍵の種類を定めたものではない）。
- IdP の署名鍵（[トークン設計](tokens.md)）とは別の鍵で、ここでの選択は署名鍵の種類を変えない。
- 秘密鍵は 1Password で管理する。生成スクリプトは秘密鍵を `op` で 1Password のアイテムに直接入れ、平文をディスクにも標準出力にも出さず、CSR と公開鍵だけを出力する。`idpctl` は秘密鍵の PEM を標準入力からだけ読み、ファイルや引数では受け取らない。`op read` で渡すかどうかは管理者が決め、`idpctl` は 1Password に固有の機能を持たない。1Password のエージェントは SSH 用で、TLS のクライアント認証には使えない（1Password「1Password SSH Agent」）。
- 証明書は秘密ではないので、ファイルのパスで渡す。
- 生成はスクリプトを通すので、人が実行してもエージェント（AI）が実行しても結果は変わらない。そのため、実行する主体は限らない。ただし、秘密鍵の値そのものを AI のコンテキストに入れてはいけない（標準出力に出さない、ファイルに書かない、プロンプトに貼らない）。この規則は変わらない。

**操作の一覧**

CLI のサブコマンドは操作名をそのまま使う（`idpctl client_create --public`、`idpctl grant_add group:<group_id> <client_id>` など）。操作名は共有コアのユースケースの名前と同じで、管理 API の OpenAPI の `operationId` と監査ログの `operation` にも同じ値が入るので、呼び方を 1 つに揃える。

書き込みの操作は、[認可](authorization.md)の管理の関心事で分類する。基盤の操作（署名鍵、Cloudflare の API トークンと証明書の発行、許可リストの変更、デプロイ）は `idpctl` の対象外。全 28 操作は次のとおり。

- 読み取り（7）：`users_list`、`user_get`、`clients_list`、`groups_list`、`grants_list`、`access_check`、`audit_tail`
- ユーザーの管理（13）：`user_create`、`user_rename`、`user_disable`、`user_enable`、`enroll_link_issue`、`passkey_revoke`、`session_revoke`、`group_create`、`group_rename`、`group_disable`、`group_enable`、`group_member_add`、`group_member_remove`
- RP の管理（6）：`client_create`（public client は `--public`、ID トークンの署名アルゴリズムは `--id-token-alg`）、`client_set_redirects`、`client_rotate_secret`、`client_set_id_token_alg`、`client_disable`、`client_enable`
- アクセスの管理（2）：`grant_add`、`grant_remove`

ユーザー、client、グループは完全に削除しない。`user_delete`、`client_delete`、`group_delete` は置かず、終わらせるときは無効化する。行を消さないことは D1 のトリガーで強制する（[データモデル](data-model.md)参照）。

**操作の分類**

各操作の分類は、共有コアでユースケースの隣にメタデータとして定義する。分類は、管理の関心事、読み取りか書き込みか、本人性を確定させるか（`enroll_link_issue`）の 3 つ。完全な削除の操作を置かないので、取り返しのつかない操作という分類は持たない。今の入り口は CLI だけで、すべての操作を出す。MCP などの別の入り口を足すとき（[将来拡張](future-extensions.md)参照）は、その入り口が出す範囲をこのメタデータから導き、本人性を確定させる操作を出さない。入り口ごとに出す操作の一覧を手で持つと、誤って出してしまうため。

`audit_tail` は監査ログを新しい順に返し、対象（`user:<id>` など）、操作名、期間で絞り込める。管理者はこれで、本人によるパスキーの追加と失効を含む出来事をいつでも確認できる。

`user_get` は、ユーザーのパスキーの一覧（credential ID、作成日時、最終使用日時、追加の経路、同期型かどうか）を返す。`passkey_revoke` はパスキーを 1 本ずつ失効させ、そのパスキーから作ったセッションだけを外部キーの連鎖で消す（[認証フロー](authentication.md)の復旧を参照）。本人による失効と同じく、最後の 1 本は失効できない。本数の確認は削除と同じ文の条件で行い、人の操作の誤りでユーザーを 0 本にしない。ユーザーを完全に締め出すときは `user_disable` を使う。

`enroll_link_issue` は、発行の時点でパスキーの本数を確かめ、パスキーの上限（[実装に依存しない契約](cross-language-contract.md)参照）に達しているユーザーには発行しない。本人の目の前ではなく、管理者の側で失敗させるためである。無効化されたユーザーにも発行しない。発行から使用までの間に本人が追加することもあるので、IdP の Worker も登録の verify で上限を確かめる。どちらの確認も共有コアの同じ規則を使う。発行は、同じバッチでそのユーザーの未使用の登録トークンをすべて消すので、有効な登録リンクはユーザーごとに常に 1 つまでになる。

ユーザーとグループの名前は、次のように扱う。

- `user_rename` は表示名（`users.name`）を、`group_rename` はグループ名（`groups.name`）を変える。ID は変わらないので、`sub`、所属、grant はそのまま残る。変更前と変更後の名前を `detail_json` に残す。
- これらも他の書き込みと同じく、監査ログに 1 行を書く。

有効化と無効化は、次のように扱う。

- `user_disable`、`client_disable`、`group_disable` は、出来事の表に `disabled` の行を、`user_enable`、`client_enable`、`group_enable` は `enabled` の行を追記する。今の状態と同じ値への変更は拒否し（`state-conflict`）、行も成功の監査ログの行も書かない。理由は `detail_json` に入れ、出来事の表には書かない（[データモデル](data-model.md)参照）。
- `user_disable` は、同じバッチでそのユーザーの全セッションを消す。無効化の前に始めたセレモニーは、書き込みの条件で止める（[認証フロー](authentication.md)参照）。
- `client_disable` の後は、その client の `/authorize` はリダイレクトせずエラーページを返し、`/token` と `/userinfo` も拒否する。grant と redirect URI は残るので、`client_enable` で元に戻せる。
- `group_disable` の後は、そのグループ経由の grant は誰にも許可を出さない（`effective_access` が除く）。所属と grant は残るので、`group_enable` で元に戻せる。
- 無効化したユーザーの行は表示名とパスキーの公開鍵を持ったまま残る。設計原則 7 との関係と、表示名を中立にする方法は[データモデル](data-model.md)を参照。

client ID は次のように扱う。

- client ID は管理者が `client_create` で決める（`grafana` など）。不変で、client の行を消さないので二度と使われない（主キーとして再利用できない）。表示名は `clients.name` で、こちらは変えられる。RFC 6749 §2.2 は、client identifier は秘密ではなく、認可サーバーの中で一意な文字列であるとしている。再利用を防ぐためにランダムな ID にする必要はない。
- 形式は、英小文字、数字、ハイフンからなる 3〜64 文字で、先頭と末尾は英小文字か数字とする。共有コアが入力の検証で確かめる。

ID トークンの署名アルゴリズム（[トークン設計](tokens.md)参照）は、次のように扱う。

- `client_create` は、ID トークンの署名アルゴリズム（`Ed25519` か `RS256`）を `clients.id_token_signed_response_alg` に必ず明示して書く。指定がなければ `Ed25519` にする。OIDC Dynamic Client Registration 1.0 §2 は省略時の既定を RS256 としているので、値を書かずに既定に任せることはしない。
- `RS256` は、ライブラリが Ed25519 の ID トークンを検証できない RP にだけ選ぶ。
- `client_set_id_token_alg` は、登録済みの client のアルゴリズムを変える。変更前と変更後の値を `detail_json` に残し、ほかの書き込みと同じく監査ログに 1 行を書く。
- RS256 が無効なデプロイでは、管理用の Worker は `client_create` と `client_set_id_token_alg` での `RS256` の指定を拒否する。有効かどうかは IdP の Worker の discovery から判断し、判断できなければ拒否する（fail-closed）。
- `clients_list` は client ごとのアルゴリズムを返し、アルゴリズムで絞り込める。RS256 を無効にする前に、`RS256` を登録した client が残っていないことをこれで確かめる。

`access_check(user, client)` は、許可か拒否かに加えて、どの grant にマッチしたか（直接付与か、どのグループ経由か。または何が足りないか。無効なユーザー、client、グループを含む）を返す。

ユーザーとグループは同じ主体として扱う（[認可](authorization.md)参照）。

- `grant_add(principal, client)` と `grant_remove(principal, client)` は、主体を `user:<id>` か `group:<id>` で受け取る。どちらも同じ操作で、共有コアが接頭辞と ID の種類（`principals.kind`）が合うことを確かめてから `client_access` に書く。グループ名では受け取らない（名前は変えられるので、パスに置く識別子にしない）。
- `grant_add` と `group_member_add` で存在しない主体やグループを指定すると、解決の段階か外部キーの制約で失敗する。打ち間違えた名前で、誰にもマッチしない grant が黙って作られることはない。
- `grant_add` と `group_member_add` は、新たに使えるようになるユーザーと client の組を共有コアで計算し、結果に含める。グループへの grant やメンバーの追加は複数の人の権限をまとめて広げるので、操作する人に影響の範囲が見えるようにするため。
- `group_create` は、メンバーと grant が 0 件のグループを作れる。`groups_list` は、グループごとに有効・無効、メンバーと client の一覧を返す。
- 所属と grant は関係の行なので、`group_member_remove` と `grant_remove` で削除する。ユーザーとグループの行そのものは削除しない。

**管理 API の形**

管理 API は、RPC ではなく、リソースと HTTP のメソッドで表す REST の形にする。取り決めは次のとおり。

1. 1 つのエンドポイントは、ちょうど 1 つの共有コアの操作に対応する。OpenAPI の `operationId` は操作名（CLI のサブコマンド、監査ログの `operation` と同じ値）にする。例外は下の 2 にだけ置く。
2. 有効化と無効化は、`POST /v1/{users|clients|groups}/{id}/enablement-events` に `{"enablement": "enabled" | "disabled"}` を送る。出来事の表に行を足す操作なので、出来事のリソースへの追加として表す。このエンドポイントだけは、本文の値で 2 つの操作（`user_enable` と `user_disable` など）のどちらかになる。OpenAPI の `operationId` は 1 つしか付けられないので、`user_enablement_append`、`client_enablement_append`、`group_enablement_append` とし、共有コアが本文の値から操作名を決めて、監査ログの `operation` と CLI のサブコマンドには `user_enable` などの操作名を使う。
3. 属性の変更は、属性ごとのサブリソースへの `PUT` で行い、`PATCH` は使わない。1 回の呼び出しが、監査ログの 1 つの操作に対応するようにするため。
4. `GET` の応答には `Cache-Control: no-store` を付ける。クエリのパラメータは共有コアのスキーマで検証する。
5. パスは複数形の kebab-case にし、ID はパスに入れる。

| 操作 | メソッドとパス |
| --- | --- |
| `user_create`、`users_list` | `POST /v1/users`、`GET /v1/users` |
| `user_get` | `GET /v1/users/{id}` |
| `user_rename` | `PUT /v1/users/{id}/name` |
| `user_enable`、`user_disable` | `POST /v1/users/{id}/enablement-events` |
| `enroll_link_issue` | `POST /v1/users/{id}/enrollment-links` |
| `passkey_revoke` | `DELETE /v1/users/{id}/passkeys/{credential_id}` |
| `session_revoke` | `DELETE /v1/users/{id}/sessions` |
| `client_create`、`clients_list` | `POST /v1/clients`、`GET /v1/clients` |
| `client_set_redirects` | `PUT /v1/clients/{id}/redirect-uris` |
| `client_set_id_token_alg` | `PUT /v1/clients/{id}/id-token-alg` |
| `client_rotate_secret` | `POST /v1/clients/{id}/secrets` |
| `client_enable`、`client_disable` | `POST /v1/clients/{id}/enablement-events` |
| `group_create`、`groups_list` | `POST /v1/groups`、`GET /v1/groups` |
| `group_rename` | `PUT /v1/groups/{id}/name` |
| `group_enable`、`group_disable` | `POST /v1/groups/{id}/enablement-events` |
| `group_member_add`、`group_member_remove` | `PUT /v1/groups/{id}/members/{user_id}`、`DELETE /v1/groups/{id}/members/{user_id}` |
| `grant_add`、`grant_remove` | `PUT /v1/clients/{id}/grants/{principal}`、`DELETE /v1/clients/{id}/grants/{principal}`（`principal` は `user:<id>` か `group:<id>`） |
| `grants_list` | `GET /v1/grants` |
| `access_check` | `GET /v1/access?user=<id>&client=<id>` |
| `audit_tail` | `GET /v1/audit-events` |

- 状態を変えない `PUT`（今と同じ名前への `user_rename`、すでにある grant への `grant_add` など）は成功として返し、行も監査ログの行も書かない。書き込みは監査ログの行と同じ条件を付けて同じバッチに置くので、変化がなければどちらも起きない。
- 存在しない関係への `DELETE`（所属していないメンバー、ない grant、ないパスキー）は `not-found` を返す。RFC 9110 §9.2.2 の冪等はサーバーの状態への効果についての性質で、2 回目の応答が 1 回目と同じであることまでは求めない。打ち間違えた ID が黙って成功することを避ける。

**エラーの形（RFC 9457）**

管理 API のエラーは、RFC 9457 の problem details（`application/problem+json`。RFC 9457 §6）で返し、`type`、`title`、`status`、`detail` を持たせる（RFC 9457 §3.1）。`title` と `detail` は英語で書く。

- `type` は `urn:ojilab:idp:problem:<kind>` にする。RFC 9457 §3.1.1 は、`type` の URI が解決できない URI であってもよいとしている。
- `kind` と HTTP のステータスは次のとおり。`kind` は共有コアで定義し、OpenAPI の仕様に載せる。
  - `validation-failed`（400）：入力の検証に失敗した。どのフィールドかを JSON Pointer の一覧で返す
  - `not-found`（404）
  - `already-exists`（409）
  - `state-conflict`（409）：今の状態と同じ値への有効化・無効化など、今の状態では実行できない
  - `limit-reached`（409）：パスキーの上限
  - `last-passkey`（409）：最後の 1 本のパスキーは失効できない
  - `algorithm-disabled`（409）：RS256 が無効なデプロイでの `RS256` の指定
  - `secret-not-replayable`（409）：秘密を返す操作の `Idempotency-Key` による再生（下記）
  - `idempotency-key-reused`（422）：同じ `Idempotency-Key` を別の要求に使った（下記）
  - `forbidden`（403）：mTLS の再確認か許可リストで拒否した。理由は返さない
  - `internal`（500）：内部の詳細は返さず、管理用の Worker のログにだけ残す
- `detail` には、秘密、トークン、SQL、スタックトレースを入れない。
- `idpctl` は `type` で分岐し、表示のために `type` を日本語の文に対応付けてよい。規則の判定には使わない（規則の判定者は管理用の Worker だけ）。
- 失敗した管理操作は、許可リストで管理者が確定した後なら、管理用の Worker が `failure` の監査ログの行を書く（[データモデル](data-model.md)参照）。
- エッジの WAF が止めたリクエストは Cloudflare のブロックの応答になり、problem details ではない。

**Idempotency-Key（管理 API の作成と追記の POST）**

通信の失敗で `idpctl` が再試行しても、同じ作成や追記が 2 回起きないようにする。対象は管理 API の利用者（今は `idpctl`、将来の管理用のクライアント）だけで、公開の OIDC とパスキーのエンドポイントは、仕様が定める 1 回だけ使える値（RFC 6749 §4.1.2 の認可コード、1 回だけ使えるチャレンジ）のままにする。そこに `Idempotency-Key` を足すのは、標準にない拡張になるため（設計原則 3）。

- 管理 API の作成と追記の `POST`（`user_create`、`client_create`、`group_create`、有効化と無効化、`enroll_link_issue`、`client_rotate_secret`）は、`Idempotency-Key` ヘッダーを必須にする。ヘッダーは IETF の draft-ietf-httpapi-idempotency-key-header で定義されている。この文書はまだ RFC ではない Internet-Draft で、確認した時点の最新は -08（2026-10-22）である。ヘッダーがなければ `validation-failed`（400）を返す（draft §2.7 は、ヘッダーを必須とする操作でヘッダーがなければ 400 を返すべき（SHOULD）としている）。
- `idpctl` は 1 回の実行ごとに乱数のキー（[契約](cross-language-contract.md)のトークンと同じ形）を作り、自分の再試行で同じキーを使う。管理用の Worker は、その形でないキーを `validation-failed` で拒否する。
- 管理用の Worker は、キー、操作名、要求の本文のハッシュ、応答、有効期限（24 時間）を `idempotency_keys` に書く。行は操作と同じバッチで書くので、操作と保存した応答は一緒に確定するか、一緒に消える。同時に同じキーで来た 2 つ目の要求は、主キーの衝突で失敗してから保存した応答を返す。期限切れの行は、ほかの短命の行と同じく、新しい行を書くバッチで削除する。キーは管理者ごとに分け、別の管理者の応答は返さない。
- 同じキーで同じ本文なら、保存した応答をそのまま返す。同じキーで本文か操作が違えば `idempotency-key-reused`（422）を返す（draft §2.2 はキーを別の本文の要求に再利用してはならない（MUST NOT）とし、§2.7 はそのとき 422 を返すべき（SHOULD）としている）。
- 秘密は保存しない。秘密を返す操作（confidential client の `client_create`、`client_rotate_secret`、`enroll_link_issue`）は応答を保存せず、同じキーの再生には `secret-not-replayable` を返す。管理者は新しいキーで操作をやり直す。`enroll_link_issue` のやり直しは前のリンクを無効にし、`client_rotate_secret` のやり直しは前のシークレットを置き換えるので、平文を受け取れなかった秘密が有効なまま残ることはない。confidential client の `client_create` を再生できなかったときは、`client_rotate_secret` で新しいシークレットを発行する。
- `PUT` と `DELETE` は HTTP の意味で冪等（RFC 9110 §9.2.2）なので、ヘッダーを求めない。
- 登録リンクの登録が verify まで成功したのに、ブラウザが応答を受け取れなかった場合、トークンは消費済みで、パスキーは保存されている。登録ページはこの場合に、サインインを試すよう案内する（[認証フロー](authentication.md)参照）。

**一覧のページング**

5 つの一覧（`users_list`、`clients_list`、`groups_list`、`grants_list`、`audit_tail`）は、同じカーソルのページングにする。

- パラメータは `limit`（既定 50、最大 200）と、不透明な `cursor`。応答の本文は `items`、`next_cursor`、`prev_cursor`（どちらも文字列か `null`）を持つ。`Link` ヘッダー、総件数、ページ番号は返さない。
- 並び順は、`audit_tail` が `id` の新しい順、ほかは作成の順（`created_at` と ID）。
- カーソルは、最後の行の並びのキーを base64url にしたもので、署名しない。共有コアがカーソルを検証し、不正なら `validation-failed` を返す。秘密を含まず、並びのキーを知られても困らないので、署名は要らない。
- `audit_tail` は、`target`、`operation`、`since`、`until`（UNIX 秒）で絞り込める。
- オフセットのページングにしない理由：行が追加されるとオフセットのページがずれ、`OFFSET` と総件数の `COUNT` は読み飛ばす行も読むので、D1 はそれも読み取りとして数える（[無料枠](free-tier.md)参照）。

**IdP が発行する秘密の扱い**

- クライアントシークレットと登録トークンは、管理用の Worker の共有コアだけが生成する。どちらも使うときには平文で IdP の Worker に提示される値であり、256 bit の乱数であることを保証できるのはサーバーだけである。乱数は Workers の Web Crypto の `crypto.getRandomValues` で作る。D1 にはハッシュだけを書く。
- 平文は、発行した HTTPS の応答で 1 回だけ返し、応答には `Cache-Control: no-store` を付ける。管理用の Worker は平文をログに書かず、`idempotency_keys` にも保存しない。
- `idpctl` は受け取った平文を権限 `0600` のファイルに書き出し、パスだけを表示する。平文を標準出力に出さないので、AI のコンテキストにも流れない。
- 登録リンクは発行から 10 分で切れるので、管理者は本人に渡すその場で `enroll_link_issue` を実行し、メールではなく対面など信頼できる経路で渡す（[認証フロー](authentication.md)参照）。

**監査ログ**

- 管理用の Worker は管理操作を監査ログに書き、操作者として、許可リストで確定した管理者の名前と、使われた証明書のフィンガープリントを残す。本人のパスキー操作（登録リンクによる登録、本人による追加と失効）は IdP の Worker が同じ表に書く。セッション ID、トークン、シークレット、登録トークンは書かない（スキーマは[データモデル](data-model.md)参照）。失敗した操作も `failure` の行として記録する（IdP の Worker は成功の行だけを書く）。
- 操作者はサーバーが確かめた値なので、管理者が監査ログの行を管理 API で偽造したり消したりすることはできない。管理 API には監査ログを書き換える操作を置かない。
- **受け入れるリスク**：D1 の API トークンを持つ人（下の break-glass、基盤の権限）は、共有コアを通らずに D1 を書けるので、管理者の行も `actor` が `user` の行（本人によるパスキーの追加と失効）も偽造でき、行を消すこともできる。本人の行は、本人への通知をしない NIST の通知要件の例外を補う手段（[認証フロー](authentication.md)参照）なので、API トークンを持つ人に対しては、その補いが効かない。ただし API トークンはそれだけで全ユーザーの全操作ができる基盤の権限であり（[操作とリスク](operations-and-risks.md)参照）、監査ログでそれを防ぐことはもともとできない。家族規模の運用では、この限界を受け入れる。

**break-glass（管理用の Worker が使えないとき）**

- 管理用の Worker やその mTLS が使えないときは、基盤の権限で `cf` CLI の `cf d1 query <DATABASE_ID>` を、break-glass 用の D1 の API トークンで実行する。このトークンは常設せず、必要になったときに作り、作業が終わったら失効させる（[デプロイと設定](deployment.md)参照）。`cf` はデータベースの名前ではなく ID を受け取り、既定でリモートのデータを対象にする（Cloudflare「cf for Wrangler users」の「What changes」）。`cf` はベータで、コマンドが安定版の前に変わりうる（Cloudflare「Cloudflare CLI」）。
- break-glass の書き込みは共有コアを通らないので、パスキーの上限などの規則は SQL を書く人が守る必要があり、監査ログの行も手で書かなければ残らない。日常の管理には使わないので、このことを受け入れる。
- 行の削除を拒否するトリガー（[データモデル](data-model.md)参照）は、break-glass でも外さない限り効く。誤って入れた個人情報を消すなど、緊急に行を消すときだけ、同じ作業の中で先にトリガーを外し、消した後に戻す。外したことと戻したことは、手で監査ログの行を書いて残す。
- D1 の API トークンは日常の管理には使わない。扱いは[デプロイと設定](deployment.md)にまとめる。
