# 管理 CLI と管理用の Worker（idpctl）

管理操作はすべて、IdP の Worker とは別のホスト名に置く管理用の Worker が、共有コアのユースケースとして実行する。手元の `idpctl` は、その HTTPS の管理 API を呼ぶだけの Go の薄いクライアントにする。管理者は、`idpctl` が管理者の秘密鍵で要求ごとに付ける HTTP Message Signatures（RFC 9421）の署名を、管理用の Worker が持つ公開鍵の許可リストで検証して確かめる。どちらのホスティングのモード（カスタムドメインと `workers.dev`）でも同じ方法を使う（[ホスティングのモード](hosting-modes.md)。運用者の決定は 2026-11-10）。

経緯：管理用の Worker は、[ホスティングのモード](hosting-modes.md)の実装の順番の 6 で署名だけで管理者を確かめるようになり、mTLS の再確認と `ADMIN_ALLOWLIST` を外した。実装の順番の 7 で、`idpctl` の `--cert` と `IDPCTL_CERT`、Terraform の mTLS のホスト名の割り当てとクライアント証明書、デプロイの入力の `admin_allowlist` と `admin_client_certificates` も外した。mTLS を使うデプロイは一度もなかったので、Cloudflare に残る証明書や割り当てはない。

このドキュメントでは、次の 2 種類の秘密を区別して書く。

- **管理者の秘密鍵（署名鍵）**：管理者が生成スクリプトで生成し、自分で持つ。管理 API への要求に署名するのに使う。IdP は公開鍵だけを持ち、秘密鍵は受け取らず、保存もしない。
- **IdP が発行する秘密（クライアントシークレット、登録トークン）**：管理用の Worker の共有コアが生成し、D1 にはハッシュだけを書く。

**構成**

- 管理用の Worker（`apps/admin-worker`）は、IdP の Worker と同じ D1 をバインディングで使い、共有コアの管理系のユースケースを管理 API として出す。`idpctl` の全 29 操作（下の一覧）は IdP のドメインの操作であり、すべて共有コアのユースケースとして実装する（[技術選定](technology.md)のコードの構成を参照）。
- 共有コアが持つもの：入力の検証、IdP が発行する秘密の生成とハッシュ、条件付きの SQL（パスキーの上限、最後の 1 本の規則など）、監査ログの行の組み立て、`grant_add` と `group_member_add` で新たに使えるようになるユーザーと client の組の計算。
- `idpctl` が持つもの：引数の解釈、管理 API の呼び出し、出力の整形、手元の入出力（管理者の秘密鍵を標準入力から読む、IdP が発行する秘密を `0600` のファイルに書く）、`Idempotency-Key` の生成と自分の再試行での再利用だけ。ドメインの規則は評価せず、管理用の Worker が返すエラーをそのまま表示する。管理用の Worker が規則の唯一の判定者である。
- 管理 API の仕様（OpenAPI など）は共有コアの入力のスキーマから生成し、`idpctl` の Go の型はその仕様から生成する。仕様は Go と TypeScript の間の契約として扱う（[実装に依存しない契約](cross-language-contract.md)参照）。
- issuer は IdP の Worker と同じ値を管理用の Worker が設定として持ち、登録リンクの組み立てに使う。`idpctl` が持つ設定は、管理 API のホスト名だけにする。
- 管理用の Worker は、設定された管理用のホスト名へのリクエストだけを受け付ける。カスタムドメインのモードでは `workers.dev` とプレビューの URL を無効にし、`workers.dev` のモードでは `workers.dev` のルートだけで公開してプレビューの URL を無効にする（[ホスティングのモード](hosting-modes.md)の 1.2）。どちらでも、ほかのホスト名で届いた要求は下の Worker 側の確認で拒否される。ホスト名の確認は、URL が `https` で、ホストが管理用のホスト名と完全に一致する（ポートを含まない）ことで行い、違えば何もせずに `forbidden` を返す。平文の HTTP の要求もこの確認で拒否し、リダイレクトはしない（`idpctl` はリダイレクトに従わず、平文で届いた要求の中身はすでに露出しているため）。
- 管理用の Worker の設定の名前は次のとおり。D1 のバインディングは `DB`、IdP の Worker への Service Binding は `IDP`、issuer は `ISSUER`、管理用のホスト名は `ADMIN_HOST`、ホスティングのモードは `HOSTING_MODE`、署名鍵の許可リストは `ADMIN_SIGNING_KEYS`（下の許可リストの節を参照）、Rate Limiting のバインディングは `RATE_LIMITER`、Worker のバージョンのメタデータのバインディングは `CF_VERSION_METADATA` とする。監査ログの `writer_version` は `admin-worker@<バージョンの ID>` にする。
- 設定は最初のリクエストの前に検証し、どれかが欠けているか形が違えば、すべてのリクエストを `internal` で拒否する（fail-closed）。管理用のホスト名は issuer と同じ規則（正規の形、ポートなし、IP アドレスでない）に従い、issuer のホスト名と同じ値も拒否する。管理 API を公開のエンドポイントと同じホストに置かないため。`HOSTING_MODE` と、issuer と管理用のホスト名の形が合わない設定も拒否する（[ホスティングのモード](hosting-modes.md)の 1.4）。`IDP` だけは欠けても拒否せず、RS256 を無効として扱う（下記）。

**管理用の Worker に API を置く理由**

D1 を手元から直接操作する形（D1 REST API）をやめ、管理 API を置く。理由は次のとおり。

- 管理操作の規則（パスキーの上限、最後の 1 本の規則、無効化の確認、監査ログの行の形、入力の検証）を、共有コアの 1 か所だけに実装できる。手元のツールが D1 を直接書くと、同じ規則の実装が IdP の Worker と手元のツールの 2 つになる。
- 操作者を、操作する側の自己申告ではなく、サーバーが確かめた管理者として監査ログに残せる。
- 管理者ごとの独立した認証を持てる。D1 の API トークンは IdP の全データへの権限を 1 つの値で持ち、管理者を区別できない。

そのかわり、管理用のエンドポイントをインターネットに出すことになる。設計原則 1 は、次の形で保つ。

- IdP の Worker は OIDC とパスキーのエンドポイントだけを出し、管理系のコードをバンドルに含めない（[技術選定](technology.md)の境界を参照）。
- 管理 API は別のホスト名にだけ置き、許可リストの鍵による正しい署名を持たないリクエストを、管理用の Worker のゲートで、どの処理（D1 の読み書きを含む）よりも前に拒否する。以前は、エッジの mTLS と WAF のカスタムルールで、有効なクライアント証明書のない要求を Worker に届く前に止めていたが、IdP がゾーンのルールセットを持たない決定（[ドメインの置き場所](domain-placement.md)の決定 ③）で WAF のルールを外し、その後、管理者の認証を署名だけにする決定（[ホスティングのモード](hosting-modes.md)の 4）で mTLS も外した。失うのは、そうした要求が 1 日のリクエスト上限に数えられないことだけで、管理 API に入れないことは変わらない。
- 管理者の認証に IdP 自身は使わない。権限の根拠が守る対象の中に閉じること、IdP の欠陥がそのまま管理権限の奪取になること、IdP の障害時に直す手段も止まることを避けるため（[将来拡張](future-extensions.md)の管理権限の分離と同じ理由）。

**管理者の認証（RFC 9421 の署名）**

署名の形、検証の手順、リプレイの防止の正本は[ホスティングのモード](hosting-modes.md)の 3 で、言語をまたぐ取り決めは[実装に依存しない契約](cross-language-contract.md)にある。ここには管理用の Worker の振る舞いとして要点だけを書く。

- `idpctl` は、要求ごとに管理者の秘密鍵で RFC 9421 の署名を作り、`Signature-Input`、`Signature`、`Content-Digest` のヘッダーで送る。対象のコンポーネントは `@method`、`@target-uri`、`@authority`、`content-digest`、本文が空でない要求の `content-type`、`Idempotency-Key` を持つ要求の `idempotency-key` に固定し、パラメーターは `created`、`nonce`、`keyid`、`tag`（`idp-admin`）の 4 つだけにする。アルゴリズムは ECDSA P-384 と SHA-384 で、要求の `alg` は受け付けない。管理者の秘密鍵は Cloudflare にも IdP にも渡らない。
- 管理用の Worker のゲートが、管理者の認証の唯一の強制の箇所になり、fail-closed で確かめる。順番は、ホスト名、スキーム、TLS のバージョン、接続元の IP ごとの Rate Limiting バインディング、本文の大きさ、構造化フィールドの厳格な解析、コンポーネントとパラメーターの形、`keyid` が許可リストにあること、`created` が今の時刻の前後 60 秒にあること、許可リストの公開鍵による署名の検証、本文の SHA-256 と `Content-Digest` の一致、`nonce` の D1 への一意な挿入（[ホスティングのモード](hosting-modes.md)の 3.8）。D1 に書くのは最後の `nonce` だけで、署名の検証を通らない要求は D1 に 1 行も書かない。
- Rate Limiting で上限を超えた要求は、本文のない 429 を返す。接続元の IP がない要求は `forbidden`、バインディングの呼び出しの失敗は `internal` にする。本文の大きさ（64 KiB）を超えた要求と、解析から `nonce` までのどこで拒否した要求には、同じ `forbidden` の本文を返し、理由は Worker のログにだけ書く。`nonce` の挿入が一意制約以外の理由で失敗したときは `internal` を返す。管理操作は、署名の対象になった本文のバイト列だけを入力として解釈する。
- 同じ `nonce` の 2 回目の要求は、署名が正しくてもリプレイとして拒否する。`nonce` は D1 の `admin_request_nonces` に `created` から 60 秒の有効期限で置き、期限切れから窓 1 つ分（60 秒）を過ぎた行は次の挿入と同じバッチで消す（[ホスティングのモード](hosting-modes.md)の 3.6）。
- Cloudflare の managed CA とクライアント証明書は使わない。前の設計では、エッジの mTLS と、Worker での `request.cf.tlsClientAuth` の再確認（`certVerified`、`certRevoked`、`certFingerprintSHA256`）を使っていた。③ で WAF のカスタムルールを外した後は、証明書のない要求も管理用の Worker に届き、mTLS に残る利点は小さかった。managed CA はアカウント単位で検証するので、A2 ではサービスのために発行した証明書もエッジを通り、信頼の根が広かった。両方のモードで 1 つの認証の経路にするため、署名だけにした（[ホスティングのモード](hosting-modes.md)の 4.2）。
- 管理用の Worker は、`request.cf.tlsVersion` が `TLSv1.2` か `TLSv1.3` でない要求を、ホスト名の確認と同じく何もせずに `forbidden` で拒否する。ゾーンの TLS の最小バージョンを IdP は持たないため（[デプロイと設定](deployment.md)の設定値）。

**許可リストによる管理者の確定**

管理者は、署名を検証した公開鍵から管理者の名前への許可リストで確定する。許可リストはデプロイの設定ファイル（[デプロイと設定](deployment.md)のデプロイごとの入力の `admin_signing_keys`）としてリポジトリに置き、管理用の Worker の設定 `ADMIN_SIGNING_KEYS` として CI のデプロイでだけ変える。D1 には置かない。公開鍵と `keyid` は秘密ではない。

- **署名鍵の許可リストだけで決める**：要求の `keyid` は許可リストを引く鍵としてだけ使い、許可リストにない `keyid` は拒否する。検証には許可リストの公開鍵を使い、要求が名乗る鍵も `alg` も信じない（RFC 9421 §3.2 の手順 5、§7.3.4、§7.3.6）。前の設計の mTLS では、managed CA で証明書を発行できる人（「SSL and Certificates Write」の権限を持つ人）がエッジの検証を通れたが、署名ではそうした第三の信頼の根がなく、管理者になるにはデプロイの権限（許可リストの変更）だけが要る。
- **すぐ締め出せる**：許可リストから消せば、その鍵の署名はデプロイの時点で使えなくなる。Cloudflare で失効させる手順はない。
- **管理 API から自分を足せない**：許可リストを D1 に置くと、管理者や盗まれた管理者の鍵が、管理 API で別の鍵を足せる。権限の根拠が守る対象の中に閉じるので、管理系を IdP の OIDC クライアントにしない理由（[将来拡張](future-extensions.md)参照）と同じ問題になる。
- SSH の `authorized_keys` と同じ形で、鍵と人の対応を、守られる側の設定として持つ。
- **設定の形**：`ADMIN_SIGNING_KEYS` は、`keyid`、`name`、`public_key` の 3 つのメンバーだけを持つオブジェクトの JSON 配列にする。`keyid` は公開鍵の SubjectPublicKeyInfo（SPKI）の DER の SHA-256 を小文字の 16 進 64 文字で書き、`public_key` は SPKI の DER を base64（パディングあり）で 1 行に書き、`name` は管理者の名前を英小文字、数字、ハイフンの 1〜64 文字（先頭と末尾は英小文字か数字）で書く。1 人の管理者が鍵の移行の間に複数の行を持ってよい。空の配列、JSON でない値、ほかのメンバー、`keyid` の形の誤り、P-384 の公開鍵として読み込めない `public_key`、`keyid` と `public_key` の SHA-256 の食い違い、同じ `keyid` の重複は、設定の誤りとしてすべてのリクエストを拒否する。`keyid` を `public_key` から計算できるのに書かせるのは、レビューする人が 1Password のアイテムの `public_key_sha256` と監査ログの値に照らし合わせられるようにするため。オブジェクトのキーにしないのは、JSON の重複したキーが黙って後勝ちになり、レビューで見落とされるため。設定はレビューされた形のまま使い、管理用の Worker の側で正規化しない。
- **リクエストの値の扱い**：要求の `keyid` は、小文字の 16 進 64 文字であるときだけ許可リストと比べる。大文字、区切り、長さの違うものは正規化せずに拒否する。
- 管理用の Worker は、署名のどの確認で拒否しても、同じ `forbidden` の本文を返す。どの確認で落ちたかは Worker のログにだけ書く（[デプロイと設定](deployment.md)のログを参照）。
- **受け入れるコスト**：鍵を替えるたびに、許可リストを更新してデプロイする必要がある。新旧の鍵を一時的に両方載せ、移行が済んだら古いものを消す。

**管理者の秘密鍵**

- 管理者の秘密鍵（署名鍵）は、リポジトリのレビュー済みの生成スクリプトで手元で生成する（[ブートストラップ](../deployment/bootstrap.md)参照）。鍵は ECDSA に限り、曲線は P-384 にする。NIST SP 800-57 Part 1 Rev. 5 §5.6.1.1 の Table 2 で、P-384 のセキュリティ強度は 192 bit、P-256 は 128 bit、RSA 2048 は 112 bit である。署名のアルゴリズムは RFC 9421 §3.3.5 の `ecdsa-p384-sha384` になる。
- 前の設計（mTLS）で作った P-384 の鍵は、新しく作らずにそのまま使える。1Password のアイテムが秘密でないフィールドとして持つ公開鍵と `public_key_sha256` から許可リストの行を作る（[ホスティングのモード](hosting-modes.md)の 3.10）。
- Workers の Web Crypto で P-384 の署名を検証できなければ、Ed25519（RFC 9421 §3.3.6）に切り替え、管理者の鍵を作り直す（運用者の決定）。どちらにするかは、契約のテストベクタをローカルの workerd で検証して決める（[ホスティングのモード](hosting-modes.md)の 3.3）。
- IdP の署名鍵（[トークン設計](tokens.md)）とは別の鍵で、ここでの選択は署名鍵の種類を変えない。
- 秘密鍵は 1Password で管理する。生成スクリプトは秘密鍵を `op` で 1Password のアイテムに直接入れ、平文をディスクにも標準出力にも出さず、公開鍵と `keyid` だけを出力し、デプロイの設定ファイルの `admin_signing_keys` に行を書く。`idpctl` は秘密鍵の PEM を標準入力からだけ読み、ファイルや引数では受け取らない。`op read` で渡すかどうかは管理者が決め、`idpctl` は 1Password に固有の機能を持たない。
- 生成はスクリプトを通すので、人が実行してもエージェント（AI）が実行しても結果は変わらない。そのため、実行する主体は限らない。ただし、秘密鍵の値そのものを AI のコンテキストに入れてはいけない（標準出力に出さない、ファイルに書かない、プロンプトに貼らない）。この規則は変わらない。

**操作の一覧**

CLI のサブコマンドは操作名をそのまま使う（`idpctl client_create --public`、`idpctl grant_add group:<group_id> <client_id>` など）。操作名は共有コアのユースケースの名前と同じで、監査ログの `operation` にも同じ値が入る。管理 API の OpenAPI の `operationId` も操作名にする。例外は enablement-events のエンドポイントだけで、その `operationId` は `user_enablement_switch`、`client_enablement_switch`、`group_enablement_switch` とし、1 つのエンドポイントで `*_enable` と `*_disable` の両方を受ける（下の管理 API の 2 を参照）。呼び方を 1 つに揃えるため、例外はこの 1 つだけにする。

書き込みの操作は、[認可](authorization.md)の管理の関心事で分類する。基盤の操作（署名鍵、管理者の鍵の生成、Cloudflare の API トークン、許可リストの変更、デプロイ）は `idpctl` の対象外。全 29 操作は次のとおり。

- 読み取り（7）：`users_list`、`user_get`、`clients_list`、`groups_list`、`grants_list`、`access_check`、`audit_tail`
- ユーザーの管理（13）：`user_create`、`user_rename`、`user_disable`、`user_enable`、`enroll_link_issue`、`passkey_revoke`、`session_revoke`、`group_create`、`group_rename`、`group_disable`、`group_enable`、`group_member_add`、`group_member_remove`
- RP の管理（7）：`client_create`（public client は `--public`、ID トークンの署名アルゴリズムは `--id-token-alg`）、`client_rename`、`client_set_redirects`、`client_rotate_secret`、`client_set_id_token_alg`、`client_disable`、`client_enable`
- アクセスの管理（2）：`grant_add`、`grant_remove`

ユーザー、client、グループは完全に削除しない。`user_delete`、`client_delete`、`group_delete` は置かず、終わらせるときは無効化する。行を消さないことは D1 のトリガーで強制する（[データモデル](data-model.md)参照）。

**操作の分類**

各操作の分類は、共有コアでユースケースの隣にメタデータとして定義する。分類は、管理の関心事、読み取りか書き込みか、本人性を確定させるか（`enroll_link_issue`）の 3 つ。完全な削除の操作を置かないので、取り返しのつかない操作という分類は持たない。今の入り口は CLI だけで、すべての操作を出す。MCP などの別の入り口を足すとき（[将来拡張](future-extensions.md)参照）は、その入り口が出す範囲をこのメタデータから導き、本人性を確定させる操作を出さない。入り口ごとに出す操作の一覧を手で持つと、誤って出してしまうため。

`audit_tail` は監査ログを新しい順に返し、対象（`user:<id>` など）、操作名、期間で絞り込める。管理者はこれで、本人によるパスキーの追加と失効を含む出来事をいつでも確認できる。期間は `since` を含み `until` を含まない半開区間で、どちらも UNIX 秒にする。隣り合う期間を続けて読んだときに、境界の秒の行が重複も欠落もしないようにするため。

`user_get` は、ユーザーのパスキーの一覧（credential ID、作成日時、最終使用日時、追加の経路、同期型かどうか）を返す。`passkey_revoke` はパスキーを 1 本ずつ失効させ、そのパスキーから作ったセッションだけを外部キーの連鎖で消す（[認証フロー](authentication.md)の復旧を参照）。本人による失効と同じく、最後の 1 本は失効できない。本数の確認は削除と同じ文の条件で行い、人の操作の誤りでユーザーを 0 本にしない。最後の 1 本への要求は `last-passkey` を、そのユーザーのものでないパスキーへの要求は `not-found` を返す。無効化されたユーザーのパスキーも失効できる。ユーザーを完全に締め出すときは `user_disable` を使う。

`enroll_link_issue` は、発行の時点でパスキーの本数を確かめ、パスキーの上限（[実装に依存しない契約](cross-language-contract.md)参照）に達しているユーザーには発行しない。本人の目の前ではなく、管理者の側で失敗させるためである。無効化されたユーザーにも発行しない。発行から使用までの間に本人が追加することもあるので、IdP の Worker も登録の verify で上限を確かめる。どちらの確認も共有コアの同じ規則を使う。発行は、同じバッチでそのユーザーの未使用の登録トークンをすべて消すので、有効な登録リンクはユーザーごとに常に 1 つまでになる。同じバッチで、ほかのユーザーの期限切れの登録トークンも消す。上限に達したユーザーへの発行は `limit-reached`、無効化されたユーザーへの発行は `state-conflict` を返し、どちらも既存のリンクを消さない。上限と無効化の確認は、トークンの挿入と同じ文の条件で行う。この条件の SQL は共有のモジュールに置き、IdP の Worker の登録の verify も同じ条件を使う。監査ログの行には有効期限だけを残す。

ユーザー、グループ、client の名前は、次のように扱う。

- 名前（`users.name`、`groups.name`、`clients.name`）の形式は共有コアの入力の検証で確かめる。1〜64 文字（Unicode のコードポイントで数える）で、Unicode の NFC であり、前後に空白を持たず、制御文字、書式文字などの一般カテゴリ C の文字と、行と段落の区切り文字を含まない。NFC に揃えるのは、見た目が同じ 2 つの書き方を同じ名前として扱い、グループ名の一意性を書き方の違いで迂回させないため。制御文字と区切り文字を除くのは、`idpctl` の表示で行を壊したり、保存した値と違って見えたりしないようにするため。
- グループ名の一意性は、同じバッチの条件で確かめ、ほかのグループが持つ名前への `group_create` と `group_rename` は `already-exists` にする。

- `user_rename` は表示名（`users.name`）を、`group_rename` はグループ名（`groups.name`）を、`client_rename` は client の表示名（`clients.name`）を変える。ID は変わらないので、`sub`、client ID、所属、grant はそのまま残る。変更前と変更後の名前は `detail_json` に残さない。監査ログは削除しないので、名前を残すと、表示名を中立にしても旧名が消えないため（[データモデル](data-model.md)の監査ログを参照）。
- これらも他の書き込みと同じく、監査ログに 1 行を書く。

有効化と無効化は、次のように扱う。

- `user_disable`、`client_disable`、`group_disable` は、出来事の表に `disabled` の行を、`user_enable`、`client_enable`、`group_enable` は `enabled` の行を追記する。今の状態と同じ値への変更は拒否し（`state-conflict`）、行も成功の監査ログの行も書かない。理由は受け取らず、出来事の表にも監査ログにも書かない。自由記述の個人情報を、削除しない行に入れないため（[データモデル](data-model.md)参照）。
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
- RS256 が無効なデプロイでは、管理用の Worker は `client_create` と `client_set_id_token_alg` での `RS256` の指定を拒否する。有効かどうかは IdP の Worker の discovery から判断し、判断できなければ拒否する（fail-closed）。管理用の Worker は、この 2 つの操作のときだけ `IDP` の Service Binding で IdP の Worker の discovery の文書を読み、`issuer` が設定の issuer と一致し、`id_token_signing_alg_values_supported` が `RS256` を含む配列であるときだけ有効とみなす。バインディングがない、失敗した、形が違う場合はすべて無効とみなす。
- `IDP` の Service Binding は、IdP の Worker の公開の `fetch` ではなく、名前付きのエントリポイント `IdpInternal`（`WorkerEntrypoint`）に向け、その RPC の `discovery()` を呼ぶ。`discovery()` は `/.well-known/openid-configuration` と同じコードで文書を作る。Service Binding の呼び出しはエッジを通らないので、`request.cf.tlsVersion` も `CF-Connecting-IP` も持たず、公開の経路の TLS のバージョンの確認とレート制限で拒否されるため。公開の経路の確認を、ヘッダーやパスのような、クライアントが送れるもので外すことはしない。`IdpInternal` は IdP の Worker の `cloudflare.config.ts` の `exports` で宣言し、インターネットからは届かない。管理用の Worker の設定では、`IDP` を IdP の Worker の `IdpInternal`（`exportName`）へのバインディングとして宣言する。
- `clients_list` は client ごとのアルゴリズムを返し、アルゴリズムで絞り込める。RS256 を無効にする前に、`RS256` を登録した client が残っていないことをこれで確かめる。

`access_check(user, client)` は、許可か拒否かに加えて、どの grant にマッチしたか（直接付与か、どのグループ経由か。または何が足りないか。無効なユーザー、client、グループを含む）を返す。許可か拒否かは `effective_access` ビューそのものから読み、説明は同じスナップショットの行から組み立てる。説明がビューの判定と食い違えば、`access_check` は `internal` を返す。説明の組み立てがビューの定義からずれたことを、黙って誤った説明を返さずに検出するため。

`client_rotate_secret` は confidential client だけが対象で、public client への要求は `state-conflict` を返す。`client_set_id_token_alg` で今と同じアルゴリズムを指定した要求は、状態を変えない `PUT` として成功を返す。

ユーザーとグループは同じ主体として扱う（[認可](authorization.md)参照）。

- `grant_add(principal, client)` と `grant_remove(principal, client)` は、主体を `user:<id>` か `group:<id>` で受け取る。どちらも同じ操作で、共有コアが接頭辞と ID の種類（`principals.kind`）が合うことを確かめてから `client_access` に書く。グループ名では受け取らない（名前は変えられるので、パスに置く識別子にしない）。
- `grant_add` と `group_member_add` で存在しない主体やグループを指定すると、解決の段階か外部キーの制約で失敗する。打ち間違えた名前で、誰にもマッチしない grant が黙って作られることはない。
- `grant_add` と `group_member_add` は、新たに使えるようになるユーザーと client の組を共有コアで計算し、結果に含める。グループへの grant やメンバーの追加は複数の人の権限をまとめて広げるので、操作する人に影響の範囲が見えるようにするため。
- `group_create` は、メンバーと grant が 0 件のグループを作れる。`groups_list` は、グループごとに有効・無効、メンバーと client の一覧を返す。
- 所属と grant は関係の行なので、`group_member_remove` と `grant_remove` で削除する。ユーザーとグループの行そのものは削除しない。

**管理 API の形**

管理 API は、RPC ではなく、リソースと HTTP のメソッドで表す REST の形にする。取り決めは次のとおり。

1. 1 つのエンドポイントは、ちょうど 1 つの共有コアの操作に対応する。OpenAPI の `operationId` は操作名（CLI のサブコマンド、監査ログの `operation` と同じ値）にする。例外は下の 2 の enablement-events のエンドポイントだけで、その `operationId` は `*_enablement_switch` とし、`*_enable` と `*_disable` の両方を受ける。
2. 有効化と無効化は、`POST /v1/{users|clients|groups}/{id}/enablement-events` に `{"enablement": "enabled" | "disabled"}` を送る。出来事の表に行を足す操作なので、出来事のリソースへの追加として表す。このエンドポイントだけは、本文の値で 2 つの操作（`user_enable` と `user_disable` など）のどちらかになる。OpenAPI の `operationId` は 1 つしか付けられないので、`user_enablement_switch`、`client_enablement_switch`、`group_enablement_switch` とする。共有コアが本文の値から操作名を決め、CLI のサブコマンド、共有コアのユースケース、監査ログの `operation`、`idempotency_keys.operation` には `user_enable`、`user_disable` などの操作名を使う。`*_enablement_switch` は操作名ではないので、これらには入れない。
3. 属性の変更は、属性ごとのサブリソースへの `PUT` で行い、`PATCH` は使わない。1 回の呼び出しが、監査ログの 1 つの操作に対応するようにするため。
4. `GET` の応答には `Cache-Control: no-store` を付ける。クエリのパラメータは共有コアのスキーマで検証する。
5. パスは複数形の kebab-case にし、ID はパスに入れる。
6. 共有コアに渡す入力は、パスのパラメータ、クエリ、本文（`POST` と `PUT` だけ）をまとめた 1 つのオブジェクトにする。パスの `{id}` は、リソースに応じて `user_id`、`client_id`、`group_id` の入力になる。同じメンバーが 2 か所に現れる要求（本文がパスと別の ID を名乗るなど）、同じ名前のクエリのパラメータを繰り返す要求、本文かクエリに `__proto__`、`constructor`、`prototype` という名前のメンバーを持つ要求（JavaScript のオブジェクトに入れると、メンバーではなくプロトタイプを置き換え、重複の確認とスキーマの未知のメンバーの確認をすり抜けうるため）、`application/json` でない本文、JSON のオブジェクトでない本文は `validation-failed` にする。これらも許可リストで管理者が確定した後の失敗なので、書き込みの操作なら共有コアが `failure` の監査ログの行を書く。ただし enablement-events の本文が不正なときは、本文の値で決まる操作名がないので、監査ログの行を書かない。
7. 管理用の Worker は、どの応答（成功、problem details、拒否）にも `Cache-Control: no-store` を付ける。

管理 API の OpenAPI 3.1 の仕様は `contract/openapi/admin.json` に置く。管理用の Worker のルートの表と共有コアの入力のスキーマから生成し、手で編集しない。テストが仕様を生成し直してファイルと比べ、ずれれば失敗する。生成し直すときはルートの `package.json` の `openapi:generate` を使う。パスのパラメータの名前はパスのテンプレートの名前（`id` など）にし、`Idempotency-Key` を求める操作にはそのヘッダーを必須のパラメータとして載せる。各操作は、その操作が表す共有コアの操作名の一覧を `x-operation-names` に持つ（enablement-events のエンドポイントだけが 2 つを持つ）。

成功の応答の本文は、共有コアが操作ごとに持つ出力のスキーマ（Zod）から生成する。

- 出力のスキーマは操作のメタデータ（`output`）として入力のスキーマの隣に置き、型は操作の結果の型で縛る。スキーマが結果の型に合わなければ型検査で失敗し、さらに型のテストが、スキーマから導いた型と結果の型が完全に等しいことを確かめる。どちらか片方だけにメンバーを足すと、ビルドが失敗する。結果の型を手で書き写した型を別に置かないため。
- 出力のスキーマは仕様の生成にだけ使い、実行時に結果を検証しない。結果は共有コアが組み立てた値で、外からの入力ではないため。代わりに、テストが実際の結果をスキーマで検証する。
- 仕様は出力の側を表すので、省略しうるメンバー（public client の `client_create` の `client_secret` など）は必須にしない。値を `undefined` として送らず、メンバーごと省く。
- エラーの応答は、ステータスごとに、そのステータスで返しうる `kind` を `type` の列挙として載せる。全エンドポイントが `validation-failed`（400）、`forbidden`（403）、`not-found`（404）、`internal`（500）を返しうる。409 は書き込みの操作だけが返し、`secret-not-replayable`（409）と `idempotency-key-reused`（422）は `Idempotency-Key` を求める操作だけが返す。同じステータスの中では操作ごとに絞らず、共有コアの一覧をそのまま載せる。操作ごとに返す `kind` を手で持つと、規則を足したときにずれるため。`idpctl` は `type` で分岐し、ステータスでは分岐しない。
- 共通の応答は `components` に 1 つずつ置き、各エンドポイントは参照だけを持つ。

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
| `client_rename` | `PUT /v1/clients/{id}/name` |
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
- `session_revoke`（`DELETE /v1/users/{id}/sessions`）は、ユーザーの全セッションを消す操作で、関係の 1 行を指す `DELETE` ではない。ユーザーが存在すれば、消すセッションが 0 件でも成功を返し、監査ログに 1 行を書いて消した件数を `detail_json` に残す。ユーザーが存在しなければ `not-found` を返す。
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
  - `forbidden`（403）：ゲート（ホスト名とスキーム、TLS のバージョン、署名の解析と検証、許可リスト、`created` の窓、`Content-Digest`、`nonce` のリプレイ）で拒否した。理由は返さない
- Rate Limiting バインディングの上限を超えた要求は、`kind` を増やさず、本文のない 429 を返す（problem details ではない）。
  - `internal`（500）：内部の詳細は返さず、管理用の Worker のログにだけ残す
- `detail` には、秘密、トークン、SQL、スタックトレースを入れない。
- `idpctl` は `type` で分岐し、表示のために `type` を日本語の文に対応付けてよい。規則の判定には使わない（規則の判定者は管理用の Worker だけ）。
- 失敗した管理操作は、許可リストで管理者が確定した後なら、管理用の Worker が `failure` の監査ログの行を書く（[データモデル](data-model.md)参照）。
- Cloudflare のエッジが Worker に届けずに返した応答（エラーやブロックのページ）は、problem details ではない。IdP はゾーンのルールで要求を止めない（[ドメインの置き場所](domain-placement.md)の決定 ③）が、Cloudflare 自身の応答はありうる。

**Idempotency-Key（管理 API の作成と追記の POST）**

通信の失敗で `idpctl` が再試行しても、同じ作成や追記が 2 回起きないようにする。対象は管理 API の利用者（今は `idpctl`、将来の管理用のクライアント）だけで、公開の OIDC とパスキーのエンドポイントは、仕様が定める 1 回だけ使える値（RFC 6749 §4.1.2 の認可コード、1 回だけ使えるチャレンジ）のままにする。そこに `Idempotency-Key` を足すのは、標準にない拡張になるため（設計原則 3）。

- 管理 API の作成と追記の `POST`（`user_create`、`client_create`、`group_create`、有効化と無効化、`enroll_link_issue`、`client_rotate_secret`）は、`Idempotency-Key` ヘッダーを必須にする。ヘッダーは IETF の draft-ietf-httpapi-idempotency-key-header で定義されている。この文書はまだ RFC ではない Internet-Draft で、確認した時点の最新は -08（2026-10-22）である。ヘッダーがなければ `validation-failed`（400）を返す（draft §2.7 は、ヘッダーを必須とする操作でヘッダーがなければ 400 を返すべき（SHOULD）としている）。
- `idpctl` は 1 回の実行ごとに乱数のキー（[契約](cross-language-contract.md)のトークンと同じ形）を作り、自分の再試行で同じキーを使う。管理用の Worker は、その形でないキーを `validation-failed` で拒否する。
- ハッシュする「要求の本文」は、管理用の Worker がパスのパラメータ、クエリ、本文をまとめて共有コアに渡し、共有コアのスキーマで検証した後の入力とする。オブジェクトのメンバーをキーの順に並べた JSON の SHA-256 で、メンバーの順番が違うだけの要求は同じハッシュになる。HTTP の本文だけをハッシュすると、有効化と無効化の本文（`{"enablement": "disabled"}` など）はどのユーザーでも同じなので、同じキーを別のユーザーに使った要求に、前のユーザーの応答を再生してしまうため。[データモデル](data-model.md)の `idempotency_keys.request_hash` の注釈の「要求の本文」は、この入力を指す。
- 管理用の Worker は、キー、操作名、要求の本文のハッシュ、応答、有効期限（24 時間）を `idempotency_keys` に書く。行は操作と同じバッチで書くので、操作と保存した応答は一緒に確定するか、一緒に消える。同時に同じキーで来た 2 つ目の要求は、主キーの衝突で失敗してから保存した応答を返す。期限切れの行は、ほかの短命の行と同じく、新しい行を書くバッチで削除する。キーは管理者ごとに分け、別の管理者の応答は返さない。
- 同じキーで同じ本文なら、保存した応答をそのまま返す。同じキーで本文か操作が違えば `idempotency-key-reused`（422）を返す（draft §2.2 はキーを別の本文の要求に再利用してはならない（MUST NOT）とし、§2.7 はそのとき 422 を返すべき（SHOULD）としている）。
- 秘密は保存しない。秘密を返す操作（confidential client の `client_create`、`client_rotate_secret`、`enroll_link_issue`）は応答を保存せず、同じキーの再生には `secret-not-replayable` を返す。管理者は新しいキーで操作をやり直す。`enroll_link_issue` のやり直しは前のリンクを無効にし、`client_rotate_secret` のやり直しは前のシークレットを置き換えるので、平文を受け取れなかった秘密が有効なまま残ることはない。confidential client の `client_create` を再生できなかったときは、`client_rotate_secret` で新しいシークレットを発行する。
- `PUT` と `DELETE` は HTTP の意味で冪等（RFC 9110 §9.2.2）なので、ヘッダーを求めない。
- 登録リンクの登録が verify まで成功したのに、ブラウザが応答を受け取れなかった場合、トークンは消費済みで、パスキーは保存されている。登録ページはこの場合に、サインインを試すよう案内する（[認証フロー](authentication.md)参照）。

**一覧のページング**

5 つの一覧（`users_list`、`clients_list`、`groups_list`、`grants_list`、`audit_tail`）は、同じカーソルのページングにする。

- パラメータは `limit`（既定 50、最大 200）と、不透明な `cursor`。応答の本文は `items`、`next_cursor`、`prev_cursor`（どちらも文字列か `null`）を持つ。`Link` ヘッダー、総件数、ページ番号は返さない。
- 並び順は、`audit_tail` が `id` の新しい順、ほかは作成の順（`created_at` と ID）。
- 中身のない最後のページの先を指すカーソル（境界の行より後に行がない場合）には、`items` を空にし、`next_cursor` と `prev_cursor` をどちらも `null` にして返す。指す行がないため。
- `limit` は、JSON の本文では整数で、クエリでは 10 進の文字列（先頭に 0 を付けない）で受け取る。どちらも共有コアのスキーマで検証する。
- カーソルは、向き（次か前か）と境界の行の並びのキーを base64url にしたもので、署名しない。`next_cursor` は向きが「次」で、そのページの最後の行のキーを持ち、`prev_cursor` は向きが「前」で、そのページの最初の行のキーを持つ。最初のページの `prev_cursor` と最後のページの `next_cursor` は `null` にする。共有コアがカーソルを検証し、不正なら `validation-failed` を返す。秘密を含まず、並びのキーを知られても困らないので、署名は要らない。
- `audit_tail` は、`target`、`operation`、`since`、`until`（UNIX 秒）で絞り込める。
- オフセットのページングにしない理由：行が追加されるとオフセットのページがずれ、`OFFSET` と総件数の `COUNT` は読み飛ばす行も読むので、D1 はそれも読み取りとして数える（[無料枠](free-tier.md)参照）。

**IdP が発行する秘密の扱い**

- クライアントシークレットと登録トークンは、管理用の Worker の共有コアだけが生成する。どちらも使うときには平文で IdP の Worker に提示される値であり、256 bit の乱数であることを保証できるのはサーバーだけである。乱数は Workers の Web Crypto の `crypto.getRandomValues` で作る。D1 にはハッシュだけを書く。
- 平文は、発行した HTTPS の応答で 1 回だけ返し、応答には `Cache-Control: no-store` を付ける。管理用の Worker は平文をログに書かず、`idempotency_keys` にも保存しない。
- `idpctl` は受け取った平文を権限 `0600` のファイルに書き出し、パスだけを表示する。平文を標準出力に出さないので、AI のコンテキストにも流れない。
- 登録リンクは発行から 10 分で切れるので、管理者は本人に渡すその場で `enroll_link_issue` を実行し、メールではなく対面など信頼できる経路で渡す（[認証フロー](authentication.md)参照）。

**`idpctl` の手元の振る舞い**

ここに書くのは `idpctl` の手元の入出力の決定で、管理用の Worker の規則には関わらない。

- **設定**：管理 API のホスト名は `--host` か環境変数 `IDPCTL_HOST` で渡し、フラグが環境変数より優先する。`idpctl` はホスティングのモードを知らず、`workers.dev` のホスト名も同じ規則で受け付ける。ホスト名は英小文字の DNS 名だけを受け付け、スキーム、ポート、パス、利用者情報、IP アドレス、末尾のドットを含むものは、何も送らずに使い方の誤りにする。署名した要求を意図しない相手に送らないため。管理者の秘密鍵は上のとおり標準入力からだけ読み、秘密鍵のパスを受け取るフラグも環境変数も置かない。鍵は ECDSA の P-384 だけを受け付ける。`keyid` は読み込んだ秘密鍵の公開鍵から計算し、フラグでは受け取らない。手で書いた `keyid` と鍵が食い違う余地をなくすため。前の設計のクライアント証明書の `--cert` と `IDPCTL_CERT` は、mTLS の撤去（[ホスティングのモード](hosting-modes.md)の実装の順番の 7）で外した。`--cert` を渡すと、知らないフラグとして何も送らずに使い方の誤りになる。
- **署名**：要求を送る直前に、送るバイト列そのもの（メソッド、URL、`Content-Type`、本文、`Idempotency-Key`）から署名を作り、`Signature-Input`、`Signature`、`Content-Digest` を付ける（[ホスティングのモード](hosting-modes.md)の 5.2）。
- **`User-Agent`**：すべての要求に `idpctl/<バージョン>` の `User-Agent` を付ける。`workers.dev` の Browser Integrity Check は、ライブラリの既定の `User-Agent` を Worker に届く前に拒否するため。モードによらず常に付ける。
- **接続**：TLS 1.2 以上で、サーバーの証明書はシステムのルート証明書で必ず検証する。リダイレクトには従わない。管理 API はリダイレクトを返さず、従うと署名した要求を別のホストに送りうるため。クライアント証明書は出さない。
- **再試行**：応答が届かなかったとき（接続の失敗や 1 回ごとの時間切れ）と、problem details でない 502、503、504（エッジが Worker に届けなかった応答）のときだけ、同じ要求を送り直す。回数は `--retries`（既定 2、0〜10）、1 回ごとの時間切れは `--timeout`（既定 30 秒）で変えられる。再試行の前の待ち時間は 1 回ごとに倍にし、30 秒で頭打ちにする。`Idempotency-Key` は 1 回の実行ごとに 1 つ作り、再試行では同じキーと同じ本文を送る。再試行のたびに、新しい `created` と `nonce` で署名し直す。前の試行が管理用の Worker に届いていた場合、同じ署名を送り直すと `nonce` のリプレイとして `forbidden` になるため。管理用の Worker が返した problem details は、`internal` も含めて再試行しない。本文のない 429 も再試行せず、problem details でない応答として終了コード 1 で終わる。
- **`forbidden` の手がかり**：`forbidden` のときは、確かめること（手元の時計が合っているか、鍵が許可リストにあり、そのデプロイが済んでいるか、ホスト名）を標準エラー出力に出す。管理用の Worker は理由を返さないため。
- **出力**：成功の応答の本文は JSON のまま整形して標準出力に出す。ログと problem details は `slog` のテキストの形で標準エラー出力に出し、problem details は `kind`、ステータス、`title`、`detail`、`validation-failed` の JSON Pointer の一覧を表示する。
- **IdP が発行する秘密の書き出し**：秘密を返す操作（confidential client の `client_create`、`client_rotate_secret`、`enroll_link_issue`）は、書き出し先の `--secret-out` を必須にする。登録リンクは登録トークンを含むので、秘密として扱う。ファイルは要求を送る前に、権限 `0600` で、既存のファイルやシンボリックリンクがあれば失敗する排他的な作成で作る。書き出せないパスのせいで、受け取れない秘密をサーバーに発行させないため。操作が失敗すれば、ファイルを消す。標準出力には、秘密のメンバーを除き、代わりに `<メンバー名>_file` として書き出したファイルの絶対パスを入れた JSON を出す。秘密を返さない操作に `--secret-out` を渡すと、使い方の誤りにする。どの操作でも、`--secret-out` に書き出さなかった `client_secret` か `enrollment_link` のメンバーが応答のどこかに残っていれば、何も表示せずに失敗にする。サーバーの誤りで秘密が返っても、標準出力に出さないため。このときファイルに書き出した秘密があれば、ファイルを消して、やり直し方を表示する。ファイルを残すのは、そのパスを含む出力を表示できると決まった後だけにする。`secret-not-replayable` のときは、やり直し方（`client_create` なら `client_rotate_secret`、ほかは同じ操作を新しいキーで実行し直す）を標準エラー出力に表示する。
- **引数**：位置の引数は操作の対象の ID と値で、`grant_add` と `grant_remove` は主体（`user:<id>` か `group:<id>`）、client ID の順に受け取る。一覧のページングは `--limit` と `--cursor` で渡し、応答の `next_cursor` と `prev_cursor` を次の呼び出しの `--cursor` に使う。絞り込みは、`clients_list` が `--id-token-alg`、`grants_list` が `--client` と `--principal`、`audit_tail` が `--target`、`--operation`、`--since`、`--until` を受け取る。`client_create` は redirect URI を繰り返しの `--redirect-uri` で、`client_set_redirects` は位置の引数で受け取る。値はどれも手元で検証しない。
- **終了コード**：`idpctl` はステータスではなく `type` で分岐し、`kind` ごとに別の終了コードを返す。スクリプトが標準エラー出力を解釈せずに分岐できるようにするため。成功は 0、problem details 以外の失敗（通信の失敗、エッジのブロックの応答などの管理 API の形でない応答、手元の入出力の失敗）は 1、引数と手元の設定の誤り（何も送っていない）は 2 にする。`kind` ごとには、`validation-failed` を 10、`not-found` を 11、`already-exists` を 12、`state-conflict` を 13、`limit-reached` を 14、`last-passkey` を 15、`algorithm-disabled` を 16、`secret-not-replayable` を 17、`idempotency-key-reused` を 18、`forbidden` を 19、`internal` を 20 とし、この版の `idpctl` が知らない `kind` は 21 にする。仕様に `kind` を足すと、`idpctl` のテストが終了コードの割り当ての漏れを検出する。

**監査ログ**

- 管理用の Worker は管理操作を監査ログに書き、操作者として、許可リストで確定した管理者の名前と、署名を検証した鍵の `keyid`（SPKI の DER の SHA-256）を残す。列は前の設計の `admin_cert_sha256` を使い、資格情報の種類を `admin_credential`（`signing-key`）で区別する（[ホスティングのモード](hosting-modes.md)の 3.9。列とトリガーは `0004` のマイグレーションで足した）。本人のパスキー操作（登録リンクによる登録、本人による追加と失効）は IdP の Worker が同じ表に書く。セッション ID、トークン、シークレット、登録トークンは書かない（スキーマは[データモデル](data-model.md)参照）。失敗した操作も `failure` の行として記録する（IdP の Worker は成功の行だけを書く）。
- 操作者はサーバーが確かめた値なので、管理者が監査ログの行を管理 API で偽造したり消したりすることはできない。管理 API には監査ログを書き換える操作を置かない。
- **受け入れるリスク**：D1 の API トークンを持つ人（下の break-glass、基盤の権限）は、共有コアを通らずに D1 を書けるので、管理者の行も `actor` が `user` の行（本人によるパスキーの追加と失効）も偽造でき、行を消すこともできる。本人の行は、本人への通知をしない NIST の通知要件の例外を補う手段（[認証フロー](authentication.md)参照）なので、API トークンを持つ人に対しては、その補いが効かない。ただし API トークンはそれだけで全ユーザーの全操作ができる基盤の権限であり（[操作とリスク](operations-and-risks.md)参照）、監査ログでそれを防ぐことはもともとできない。家族規模の運用では、この限界を受け入れる。

**break-glass（管理用の Worker が使えないとき）**

- 管理用の Worker やその署名の検証が使えないときは、基盤の権限で `cf` CLI の `cf d1 query <DATABASE_ID>` を、break-glass 用の D1 の API トークンで実行する。このトークンは常設せず、必要になったときに作り、作業が終わったら失効させる（[デプロイと設定](deployment.md)参照）。`cf` はデータベースの名前ではなく ID を受け取り、既定でリモートのデータを対象にする（Cloudflare「cf for Wrangler users」の「What changes」）。`cf` はベータで、コマンドが安定版の前に変わりうる（Cloudflare「Cloudflare CLI」）。
- break-glass の書き込みは共有コアを通らないので、パスキーの上限などの規則は SQL を書く人が守る必要があり、監査ログの行も手で書かなければ残らない。日常の管理には使わないので、このことを受け入れる。
- 行の削除を拒否するトリガー（[データモデル](data-model.md)参照）は、break-glass でも外さない限り効く。誤って入れた個人情報を消すなど、緊急に行を消すときだけ、同じ作業の中で先にトリガーを外し、消した後に戻す。外したことと戻したことは、手で監査ログの行を書いて残す。行の形は、`actor` を `break_glass`、`target` を `schema`、`result` を `success` にし、管理者の列を持たせない（[データモデル](data-model.md)の監査ログを参照）。出来事の表は対象を ON DELETE なしで参照し、自分の削除を拒否するトリガーも持つので、対象ごとに次のトリガーを外し、出来事の行を先に消してから対象を消す。
  - ユーザー：`principals_no_delete`、`users_no_delete`、`user_enablement_events_no_delete` を外し、`user_enablement_events` のそのユーザーの行を消してから、`principals` の行を消す。外部キーの連鎖で、`users` の行、パスキー、セッション、所属、grant、登録トークン、チャレンジ、認可コードも消える。
  - グループ：`principals_no_delete`、`groups_no_delete`、`group_enablement_events_no_delete` を外し、`group_enablement_events` のそのグループの行を消してから、`principals` の行を消す。連鎖で `groups` の行、所属、grant も消える。
  - client：`clients_no_delete`、`client_enablement_events_no_delete` を外し、`client_enablement_events` のその client の行を消してから、`clients` の行を消す。連鎖で grant、認可コード、`authorize_requests` も消える。
  - 出来事の表の `*_no_update` のトリガーは外さない。外したトリガーは、マイグレーションと同じ定義で作り直す。`audit_log` の行は外部キーを持たないので残るが、ID だけを持ち名前を持たないので、消す必要はない。
  - この順番は `sqlite3` で確かめた。出来事の行を残したまま対象を消すと、外部キーの制約で失敗する。
- D1 の API トークンは日常の管理には使わない。扱いは[デプロイと設定](deployment.md)にまとめる。
