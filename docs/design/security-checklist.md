# セキュリティ要件チェックリスト

各項目は e2e テスト（Playwright）の攻撃ケースとして実装し、回帰テストにする。カッコ内は、2026 年に Pocket ID や edge-idp で実際に問題になった事例。

**OIDC**

- [ ] `redirect_uri` は登録済みの値と完全一致で比較し、例外はループバックのポートだけにする（RFC 8252 §8.4、RFC 9700 §2.1）
- [ ] ループバックの `redirect_uri` は IP リテラル（`127.0.0.1` と `[::1]`）だけを登録でき、`localhost` は拒否する（RFC 8252 §8.3）
- [ ] client type を登録時に記録する。confidential client が認証なしで `/token` を呼んだら拒否し、public client が送ってきたシークレットは受け付けない（RFC 8252 §8.4・§8.5）
- [ ] public client には、既存のセッションや以前の許可があっても毎回パスキー認証を求める（RFC 8252 §8.6）
- [ ] どのエンドポイントも CORS ヘッダーを返さず、ブラウザから直接 `/token` と `/userinfo` を呼べないようにする（RFC 10017 の BFF を前提にする。OIDC の SHOULD からの例外は[標準準拠](standards-compliance.md)を参照）
- [ ] client と `redirect_uri` を検証する前のエラーはリダイレクトせず、エラーページを返す。`prompt=none` の場合も同じ（Pocket ID CVE-2026-55834）
- [ ] 認可コードは client、`redirect_uri`、PKCE に紐付け、すべて検証してから原子的に消費する（Pocket ID CVE-2026-28513）
- [ ] PKCE S256 を全クライアントで必須にし、`code_challenge` のない認可リクエストと `plain` は拒否する。これで PKCE ダウングレード（RFC 9700 §2.1.1）も防ぐ
- [ ] 認可レスポンスとエラーレスポンスに `iss` を付ける（RFC 9207）
- [ ] リクエストの `state` を、成功・エラーどちらのレスポンスにもそのまま返す（RFC 6749 §4.1.2）
- [ ] `client_id` と `redirect_uri` の検証後に起きたエラーは、検証済みの `redirect_uri` に `error` を付けて返す。アクセス権のないユーザーには `access_denied` を返す
- [ ] `/authorize` は GET と POST の両方を受け付ける
- [ ] `scope` に `openid` を含まない認可リクエストは、検証済みの `redirect_uri` に `invalid_scope` を返して拒否する（仕様では動作が未規定。fail-closed の方針として拒否する）
- [ ] `prompt=login` と `max_age` で、パスキーによる再認証を強制できる。`prompt=none` に他の値が混ざっていればエラーにする
- [ ] `display`、`claims_locales`、`acr_values` を送られてもエラーにしない。`ui_locales` は UI の言語の候補として使い、対応しない言語だけが送られてもエラーにせず、ブラウザの言語、既定の英語の順に進む（OIDC Core §3.1.2.1）
- [ ] 無効な client（`client_enablement` が `enabled` でないか、行がない）の `/authorize` は、`redirect_uri` が一致していてもリダイレクトせずエラーページを返す。`/token` は `invalid_client` で拒否し、認可コードを消費しない。`/userinfo` はその client のアクセストークンを拒否する
- [ ] `request`、`request_uri`、`registration` には、それぞれ `request_not_supported`、`request_uri_not_supported`、`registration_not_supported` を返す
- [ ] `id_token_hint` は自分が発行したものか検証し、通らなければ `invalid_request` を返す。セッションのユーザーと違えば、`prompt=none` なら `login_required` を返し、それ以外はパスキーのサインインに進めて、hint と違うユーザーでサインインしたら `login_required` を返す
- [ ] `/userinfo` は GET と POST の両方で、`Authorization` ヘッダーの Bearer のアクセストークンを受け付ける
- [ ] discovery に `response_types_supported: ["code"]`、`subject_types_supported: ["public"]`、`grant_types_supported: ["authorization_code"]`、`response_modes_supported: ["query"]`、`request_uri_parameter_supported: false` を明示し、省略による既定値で implicit、fragment、`request_uri` を広告しない（OIDC Discovery 1.0 §3）
- [ ] トークンレスポンスに `Cache-Control: no-store` を付け、`redirect_uri` へのリダイレクトに 307 を使わない
- [ ] JWT の `alg` は許可リスト（`Ed25519` と、RS256 を有効にしたときの `RS256`）で固定し、`typ` で ID トークンとアクセストークンを区別する
- [ ] JWT の検証で `alg` と鍵の種類を結び付ける。`Ed25519` は `kty: OKP` / `crv: Ed25519` の鍵とだけ、`RS256` は RSA の鍵とだけ受け付け、`EdDSA`、`none`、鍵の種類と合わない `alg` は拒否する（RFC 8725 §3.1、RFC 9864 §4.1.2）
- [ ] `/userinfo` は `alg` が `Ed25519` のアクセストークンだけを受け付ける。`id_token_hint` は `Ed25519` と `RS256` の ID トークンを受け付ける
- [ ] discovery の `id_token_signing_alg_values_supported` と JWKS は設定された鍵から導き、RSA の鍵がないデプロイでは `RS256` を載せない。JWKS には公開鍵のメンバーと `kid`、`alg`、`use` だけを載せる
- [ ] RS256 が無効な間は、管理用の Worker が client への `RS256` の登録を拒否する。`RS256` を登録した client があるのに RSA の鍵がなければ、その client へのトークンの発行を失敗させ、別のアルゴリズムで署名して返さない
- [ ] クレームは要求されたスコープの分だけ返す
- [ ] `/token` と `/userinfo` で、無効化されたユーザーとアクセス可否を再確認する（Pocket ID CVE-2026-43983 の教訓）
- [ ] `effective_access` は、有効なユーザー、有効な client、グループ経由なら有効なグループの grant だけを数える。出来事の行がないユーザー、client、グループには何も許可しない
- [ ] `/userinfo` は `typ: at+jwt` かつ `aud` が issuer のトークンだけを受け付け、ID トークンや他の `aud` のトークンは拒否する。トークンの `client_id` に対するアクセス可否も確認する
- [ ] 未登録の resource や audience を受け付けない（Pocket ID CVE-2026-62662）
- [ ] メールアドレスを保存しない。`email` スコープを要求されても無視し、`email` と `email_verified` のクレームを返さない。メールアドレスの検証や変更の仕組みそのものを持たないことで、その欠陥の経路をなくす（Pocket ID CVE-2026-115770、edge-idp 2.2.0 の修正）

**パスキー**

- [ ] チャレンジは 256 bit、10 分で、用途ごとに発行元へ紐付ける（登録は登録トークン、サインインは認可リクエストの Cookie、本人による追加の再認証と登録はセッション、本人による失効はセッションと失効させる credential ID）。verify で紐付けを確認し、`DELETE … RETURNING` で原子的に消費する。別の登録トークン、別のブラウザの Cookie、別のセッション、別の credential ID で発行されたチャレンジは使えない
- [ ] `challenges` は、`purpose` を 5 つの用途（`enroll`、`sign_in`、`add_reauth`、`add_register`、`revoke`）に CHECK で限り、用途ごとに決まった紐付けの列だけを持つことを CHECK で強制する。紐付け先（登録トークン、認可リクエスト、セッション、失効させるパスキー）が消えれば、チャレンジも外部キーの連鎖で消える
- [ ] チャレンジは紐付け先より先に消費する（登録ではチャレンジ、登録トークンの順、本人による失効ではチャレンジ、パスキーの削除の順）
- [ ] ユーザー検証（UV）を必須にし、origin と RP ID を固定する
- [ ] `crossOrigin` が true の `clientDataJSON` を拒否する
- [ ] BE / BS フラグの不正な組み合わせを拒否する
- [ ] 公開鍵のアルゴリズムは -8 / -7 / -257 以外を拒否する
- [ ] 別のユーザーに登録済みの credential ID での登録を拒否する
- [ ] user handle は 64 バイトの乱数にし、個人情報を含めない
- [ ] 登録時は、チャレンジと登録トークンの紐付けを確認してからトークンを消費する
- [ ] 登録トークンは発行から 10 分で切れ、1 回だけ使える。期限切れや使用済みのトークンでは登録できない
- [ ] サインイン中の認可リクエストは ID のハッシュで 15 分保存し（チャレンジより先に切れないようにする）、`__Host-` Cookie でブラウザに紐付け、`DELETE … RETURNING` で一度だけ取り出す。別のブラウザの Cookie や期限切れの行では再開できない
- [ ] 再開時に client、`redirect_uri`、アクセス可否を確認し直し、`prompt=login` のときと public client のときは、セッションの `auth_time` がリクエストの保存時刻以降であることを確認する
- [ ] 本人によるパスキーの追加は、セッションだけでは進めない。直前に、そのユーザーの既存のパスキーで UV 付きの再認証を求め、再認証と登録のチャレンジはどちらも同じセッションに紐付ける。別のセッションで発行されたチャレンジ、別のユーザーのパスキーによる再認証、再認証を飛ばした登録は拒否する（NIST SP 800-63B-4 §4.1.2.1）
- [ ] 本人によるパスキーの追加と失効は、同一オリジンの確認を通ったリクエストだけを受け付ける
- [ ] 1 人あたりのパスキーが上限（[実装に依存しない契約](cross-language-contract.md)の「パスキーの上限」）に達していれば、本人による追加も登録リンクによる登録も拒否する。上限の確認は挿入と同じ文の条件で行い、同時に追加しても上限を超えない
- [ ] 管理用の Worker の `enroll_link_issue` は、発行の時点で本数を確かめ、上限に達しているユーザーには発行しない。IdP の Worker も登録の verify で上限を確かめる
- [ ] 無効化されたユーザーには、`/webauthn/auth/verify` でセッションを作らない。登録リンクによる登録は options と verify で拒否し、本人による追加と失効は各段階で無効化を確かめ直す。書き込みには「無効化されていない」条件を付ける。管理用の Worker は、無効化されたユーザーに登録リンクを発行しない
- [ ] 本人によるパスキーの失効は、直前に UV 付きの再認証を求め、チャレンジを同じセッションと失効させる credential ID の両方に紐付ける。別の credential ID への付け替え、別のユーザーのパスキーの失効、再認証を飛ばした失効は拒否する
- [ ] 管理者による `passkey_revoke` も、そのユーザーのパスキーが 2 本以上あるときだけ、削除と同じ文の条件で本数を確認して行う。最後の 1 本は失効できない
- [ ] 本人によるパスキーの失効は、そのユーザーのパスキーが 2 本以上あるときだけ、削除と同じ文の条件で本数を確認して行う。1 本しかないときは拒否し、同時に 2 本を失効させても 0 本にならない
- [ ] パスキーを失効させると、そのパスキーから作ったセッションと、そのセッションから発行した未使用の認可コードが消える。今のセッションを作ったパスキーを失効させた場合は、今のセッションも終わる
- [ ] `/token` は、認可コードを発行したセッションが残っていて期限内であることを確認する。サインアウト、`session_revoke`、パスキーの失効、セッションの期限切れの後には、そのセッションから発行したコードを交換できない
- [ ] 本人のパスキー操作（登録リンクによる登録、本人による追加と失効）は、`credentials` への書き込みと同じ条件を付けて、同じバッチで監査ログに 1 行を書く。条件が成り立たず書き込みが起きなかったとき（最後の 1 本の失効、上限、無効化など）は、成功の行を書かない
- [ ] Worker は監査ログに `success` の行だけを書き、失敗と拒否は Worker のログに残す。認証前のリクエストで監査ログの行を書かせ、D1 の書き込み上限を消費させることはできない（管理用の Worker は、許可リストで管理者が確定した後の失敗の行も書く）
- [ ] アカウントページ（`/account`）は純粋な静的アセットにし、`run_worker_first` の対象に含めない。`/authorize` を経由しないサインインは置かず、セッションがなければアプリからのサインインを案内する
- [ ] `GET /webauthn/credentials` は、セッションのユーザーのパスキーだけを、credential ID、作成日時、最終使用日時、追加の経路、backup state に限って返す。`Sec-Fetch-Site` が `same-origin` でないリクエスト（ヘッダーがないものを含む）、セッションのないリクエスト、無効化されたユーザーは拒否し、`Cache-Control: no-store` を付ける

**セッションと通信**

- [ ] Cookie は `__Host-`、Secure、HttpOnly、SameSite=Lax にする。クロスサイトの `POST /authorize` にはセッションが付かず、必ずパスキーのサインインに進む
- [ ] セッショントークンはハッシュで保存し、サインインのたびに作り直す
- [ ] セッションはサインインから 1 時間の絶対期限で切れ、使っても延長しない（NIST SP 800-63B-4 の AAL2）
- [ ] ID トークンとアクセストークンは 5 分で切れ、期限切れのアクセストークンは `/userinfo` で拒否する
- [ ] `POST /logout` は今のセッションの行を、`session_revoke` と `user_disable` はそのユーザーの全セッションの行を削除する。`passkey_revoke` と本人による失効は、失効させたパスキーから作ったセッションの行だけを外部キーの連鎖で削除し、別のパスキーから作ったセッションは残す
- [ ] issuer、RP ID、origin は設定値から導き、リクエストの `Host` ヘッダーからは作らない
- [ ] issuer が未設定または形式が不正なら、リクエストを処理せずエラーを返す
- [ ] IdP の Worker は、issuer のホスト名以外へのリクエストと `https` でないリクエストを、処理せずに 404 で拒否する。エッジでは、issuer のホスト名に絞ったシングルリダイレクトのルールが平文の HTTP を HTTPS にリダイレクトし、ゾーン全体の Always Use HTTPS には頼らない
- [ ] IdP の Worker と管理用の Worker は、`request.cf.tlsVersion` が `TLSv1.2` か `TLSv1.3` でないリクエスト（値がない、知らない値を含む）を、何も処理せずに拒否する。ゾーンの TLS の最小バージョンは IdP が持たないので、エッジで TLS 1.0 と 1.1 の接続が成立しうること、Worker を通らない静的アセットのページには確認が効かないことを、RFC 8996 の例外として記録している（[ドメインの置き場所](domain-placement.md)の共存の設計の 3）
- [ ] 管理用の Worker の `IDP` の Service Binding は IdP の Worker の内部のエントリポイント `IdpInternal` に向け、公開の経路の TLS とレート制限の確認を、ヘッダーやパスで外す仕組みを持たない。RSA の鍵があるときは、管理用の Worker が RS256 を有効と判断できる
- [ ] IdP の Worker は、接続元の IP ごとの Rate Limiting バインディングの上限を超えたリクエストを 429 で拒否する。バインディングがない、呼び出しが失敗した、接続元の IP が取れない場合も、処理せずに拒否する（fail-closed）。IP をログにも D1 にも書かない
- [ ] IdP が置くゾーンのルール（WAF のカスタムルール、リダイレクト）は、IdP のホスト名に絞った条件を持つ。ゾーン全体の設定を Terraform で変えない
- [ ] セッションの Cookie で認証する状態を変える POST（`/webauthn/*`、`/authorize/resume`、`/logout`）は、`Sec-Fetch-Site` が `same-origin` か（なければ `Origin` が issuer と一致するか）を確認し、どちらのヘッダーもないリクエストは拒否する。`/authorize` はクロスサイトからの POST が正規の動作で、`/token` と `/userinfo` はサーバーからの呼び出しで Cookie を使わない（クライアント認証、PKCE、Bearer のアクセストークンで守る）ので、この確認の対象にしない
- [ ] サインイン画面、登録画面、アカウントページは、CSP の `frame-ancestors 'none'` でクリックジャッキングを防ぐ
- [ ] 登録リンクのトークンは URL のフラグメントに入れ、登録ページは `Referrer-Policy: no-referrer` にする

**シークレットとデータ**

- [ ] クライアントシークレットは 256 bit で生成し、SHA-256 で保存し、定数時間で比較する
- [ ] 壊れた行（JSON がパースできないなど）に当たったら拒否する
- [ ] 有効・無効の出来事の表（`user_enablement_events`、`client_enablement_events`、`group_enablement_events`）の UPDATE と DELETE、`principals`、`users`、`clients`、`groups` の DELETE を、D1 のトリガーが拒否する。今と同じ値への有効化・無効化は行を足さず、`state-conflict` を返し、成功の監査ログの行を書かない
- [ ] Workers Logs に、トークン、認可コード、Cookie、IdP が発行する秘密、登録トークン、チャレンジ、`Authorization` ヘッダー、要求の本文、IP アドレスを書かない（[デプロイと設定](deployment.md)のログを参照）
- [ ] 管理用の Worker は、クライアントシークレットと登録トークンの平文を、発行した応答で 1 回だけ返し、`Cache-Control: no-store` を付け、ログに書かない。`idpctl` は平文を `0600` のファイルに書き、パスだけを表示する
- [ ] 管理 API の作成と追記の `POST` は `Idempotency-Key` がなければ 400 で拒否する。同じキーと同じ本文には保存した応答を返し、本文か操作が違えば 422 を返す。秘密を返す操作の応答は `idempotency_keys` に保存せず、再生には `secret-not-replayable` を返す。別の管理者のキーの応答は返さない
- [ ] 登録リンクを発行すると、そのユーザーの未使用の登録トークンがすべて使えなくなる
- [ ] 管理 API のエラーは RFC 9457 の problem details で、`detail` に秘密、トークン、SQL、スタックトレースを含まない。`forbidden` は理由を返さない

**管理用の Worker（mTLS）**

- [ ] 管理用のホスト名の WAF のカスタムルールが、`(not cf.tls_client_auth.cert_verified or cf.tls_client_auth.cert_revoked)` に当たるリクエストを遮断する。証明書のないリクエスト、managed CA 以外の証明書、失効した証明書のそれぞれで、Worker に届かないことを確かめる
- [ ] 管理用の Worker は、`request.cf.tlsClientAuth.certVerified` が `"SUCCESS"`、`certRevoked` が `"0"`、`certFingerprintSHA256` が許可リストにある、の 3 つがそろわないリクエストを拒否する。値がない、形が違う場合も拒否する（WAF を通らない経路を想定した fail-closed の再確認）
- [ ] 同じアカウントで発行した有効な証明書（IdP をサービスのアカウントに置くときは、サービスのために発行したものを含む）でも、許可リストにないものは拒否する。許可リストから消した証明書は、Cloudflare で失効させる前でも、そのデプロイの後は拒否する
- [ ] 管理 API に、許可リストと監査ログを変える操作がない。許可リストは管理用の Worker の設定で、CI のデプロイでだけ変わる
- [ ] 管理用の Worker は `workers.dev` とプレビューの URL を無効にし、設定された管理用のホスト名以外へのリクエストを拒否する
- [ ] 管理操作の監査ログの行は、許可リストで確定した管理者の名前と証明書のフィンガープリントを持つ。証明書の検証や許可リストで拒否したリクエストは、監査ログに行を書かない
- [ ] IdP の Worker のビルド成果物に、共有コアの管理系のモジュールのコードが含まれていない。IdP の Worker のホスト名では、管理 API のどのパスも応答しない
