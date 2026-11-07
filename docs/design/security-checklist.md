# セキュリティ要件チェックリスト

各項目は e2e テスト（Playwright）の攻撃ケースとして実装し、回帰テストにする。カッコ内は、2026 年に Pocket ID や edge-idp で実際に問題になった事例。

**OIDC**

- [ ] `redirect_uri` は登録済みの値と完全一致で比較し、例外はループバックのポートだけにする（RFC 8252 §8.4、RFC 9700 §2.1）
- [ ] ループバックの `redirect_uri` は IP リテラル（`127.0.0.1` と `[::1]`）だけを登録でき、`localhost` は拒否する（RFC 8252 §8.3）
- [ ] client type を登録時に記録する。confidential client が認証なしで `/token` を呼んだら拒否し、public client が送ってきたシークレットは受け付けない（RFC 8252 §8.4・§8.5）
- [ ] public client には、既存のセッションや以前の許可があっても毎回パスキー認証を求める（RFC 8252 §8.6）
- [ ] CORS ヘッダーを返さず、ブラウザから直接 `/token` を呼べないようにする（RFC 10017 の BFF を前提にする）
- [ ] client と `redirect_uri` を検証する前のエラーはリダイレクトせず、エラーページを返す。`prompt=none` の場合も同じ（Pocket ID CVE-2026-55834）
- [ ] 認可コードは client、`redirect_uri`、PKCE に紐付け、すべて検証してから原子的に消費する（Pocket ID CVE-2026-28513）
- [ ] PKCE S256 を全クライアントで必須にし、`code_challenge` のない認可リクエストと `plain` は拒否する。これで PKCE ダウングレード（RFC 9700 §2.1.1）も防ぐ
- [ ] 認可レスポンスとエラーレスポンスに `iss` を付ける（RFC 9207）
- [ ] リクエストの `state` を、成功・エラーどちらのレスポンスにもそのまま返す（RFC 6749 §4.1.2）
- [ ] `client_id` と `redirect_uri` の検証後に起きたエラーは、検証済みの `redirect_uri` に `error` を付けて返す。アクセス権のないユーザーには `access_denied` を返す
- [ ] `/authorize` は GET と POST の両方を受け付ける
- [ ] `scope` に `openid` を含まない認可リクエストは、検証済みの `redirect_uri` に `invalid_scope` を返して拒否する（仕様では動作が未規定。fail-closed の方針として拒否する）
- [ ] `prompt=login` と `max_age` で、パスキーによる再認証を強制できる。`prompt=none` に他の値が混ざっていればエラーにする
- [ ] `display`、`ui_locales`、`claims_locales`、`acr_values` を送られてもエラーにしない
- [ ] `request`、`request_uri`、`registration` には、それぞれ `request_not_supported`、`request_uri_not_supported`、`registration_not_supported` を返す
- [ ] `id_token_hint` は自分が発行したものか検証し、セッションのユーザーと違えば `login_required` を返す
- [ ] トークンレスポンスに `Cache-Control: no-store` を付け、`redirect_uri` へのリダイレクトに 307 を使わない
- [ ] JWT の `alg` は RS256 の許可リストで固定し、`typ` で ID トークンとアクセストークンを区別する
- [ ] クレームは要求されたスコープの分だけ返す
- [ ] `/token` と `/userinfo` で、無効化されたユーザーとアクセス可否を再確認する（Pocket ID CVE-2026-43983 の教訓）
- [ ] `/userinfo` は `typ: at+jwt` かつ `aud` が issuer のトークンだけを受け付け、ID トークンや他の `aud` のトークンは拒否する。トークンの `client_id` に対するアクセス可否も確認する
- [ ] 未登録の resource や audience を受け付けない（Pocket ID CVE-2026-62662）
- [ ] メールアドレスを保存しない。`email` スコープを要求されても無視し、`email` と `email_verified` のクレームを返さない。メールアドレスの検証や変更の仕組みそのものを持たないことで、その欠陥の経路をなくす（Pocket ID CVE-2026-115770、edge-idp 2.2.0 の修正）

**パスキー**

- [ ] チャレンジは 256 bit、10 分で、用途ごとに発行元へ紐付ける（登録は登録トークン、サインインは認可リクエストの Cookie、本人による追加はセッション）。verify で紐付けを確認し、`DELETE … RETURNING` で原子的に消費する。別の登録トークンや別のブラウザの Cookie で発行されたチャレンジは使えない
- [ ] ユーザー検証（UV）を必須にし、origin と RP ID を固定する
- [ ] `crossOrigin` が true の `clientDataJSON` を拒否する
- [ ] BE / BS フラグの不正な組み合わせを拒否する
- [ ] 公開鍵のアルゴリズムは -8 / -7 / -257 以外を拒否する
- [ ] 別のユーザーに登録済みの credential ID での登録を拒否する
- [ ] user handle は 64 バイトの乱数にし、個人情報を含めない
- [ ] 登録時は、チャレンジと登録トークンの紐付けを確認してからトークンを消費する
- [ ] 登録トークンは発行から 10 分で切れ、1 回だけ使える。期限切れや使用済みのトークンでは登録できない
- [ ] サインイン中の認可リクエストは ID のハッシュで 15 分保存し（チャレンジより先に切れないようにする）、`__Host-` Cookie でブラウザに紐付け、`DELETE … RETURNING` で一度だけ取り出す。別のブラウザの Cookie や期限切れの行では再開できない
- [ ] 再開時に client、`redirect_uri`、アクセス可否を確認し直し、`prompt=login` ではセッションの `auth_time` がリクエストの保存時刻以降であることを確認する
- [ ] 本人によるパスキーの追加は、セッションだけでは進めない。直前に、そのユーザーの既存のパスキーで UV 付きの再認証を求め、再認証と登録のチャレンジはどちらも同じセッションに紐付ける。別のセッションで発行されたチャレンジ、別のユーザーのパスキーによる再認証、再認証を飛ばした登録は拒否する（NIST SP 800-63B-4 §4.1.2.1）
- [ ] 本人によるパスキーの追加は、同一オリジンの確認を通ったリクエストだけを受け付ける
- [ ] 1 人あたりのパスキーが 10 本に達していれば、追加を拒否する
- [ ] 本人がパスキーを削除する経路を作らない
- [ ] パスキーの結び付け（登録リンクによる登録と本人による追加）は、`credentials` への書き込みと同じバッチで監査ログに 1 行を書く

**セッションと通信**

- [ ] Cookie は `__Host-`、Secure、HttpOnly、SameSite=Lax にする。クロスサイトの `POST /authorize` にはセッションが付かず、必ずパスキーのサインインに進む
- [ ] セッショントークンはハッシュで保存し、サインインのたびに作り直す
- [ ] セッションはサインインから 1 時間の絶対期限で切れ、使っても延長しない（NIST SP 800-63B-4 の AAL2）
- [ ] ID トークンとアクセストークンは 5 分で切れ、期限切れのアクセストークンは `/userinfo` で拒否する
- [ ] `POST /logout`、`session_revoke`、`user_disable`、`passkey_revoke` で、対象のセッション行を削除する
- [ ] issuer、RP ID、origin は設定値から導き、リクエストの `Host` ヘッダーからは作らない
- [ ] issuer が未設定または形式が不正なら、リクエストを処理せずエラーを返す
- [ ] 状態を変える POST は `Sec-Fetch-Site`（なければ `Origin`）で同一オリジンかを確認する
- [ ] サインイン画面と登録画面は、CSP の `frame-ancestors 'none'` でクリックジャッキングを防ぐ
- [ ] 登録リンクのトークンは URL のフラグメントに入れ、登録ページは `Referrer-Policy: no-referrer` にする

**シークレットとデータ**

- [ ] クライアントシークレットは 256 bit で生成し、SHA-256 で保存し、定数時間で比較する
- [ ] 壊れた行（JSON がパースできないなど）に当たったら拒否する
