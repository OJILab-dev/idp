# 標準準拠

OIDC と WebAuthn は、仕様の MUST だけでなくセキュリティ上の SHOULD（推奨）にも従う。仕様が実装者に選択を委ねている箇所は安全側を選び、準拠は OpenID Foundation の適合性テストと e2e テストで確認する。

| 規格 | 主な準拠ポイント |
| --- | --- |
| OpenID Connect Core 1.0 | 認可コードフロー（`response_type=code`）のみ。`prompt`（`none` / `login`）と `max_age` を正しく扱い、`auth_time` と `nonce` を ID トークンに入れる。クレームは要求されたスコープの分だけ返す |
| OpenID Connect Discovery 1.0 | `/.well-known/openid-configuration` を公開する。各エンドポイントの URL は、issuer に `/authorize`、`/token`、`/userinfo`、`/jwks`、`/end_session`（`end_session_endpoint`。RP-Initiated Logout 1.0 §2.1）を付けたものにする。`id_token_signing_alg_values_supported` は設定された署名鍵から導き、既定は `["Ed25519"]`、RS256 を有効にしたデプロイでは `["Ed25519", "RS256"]` にする（RS256 を無効にしている間は §3 から外れる。下の例外を参照）。§3 で省略すると既定値で対応を意味する項目は、対応しない機能を広告しないように明示する。`response_types_supported: ["code"]`、`subject_types_supported: ["public"]`（どちらも §3 で REQUIRED）、`grant_types_supported: ["authorization_code"]`（省略時の既定は `["authorization_code", "implicit"]`）、`response_modes_supported: ["query"]`（省略時の既定は `["query", "fragment"]`）、`request_uri_parameter_supported: false`（省略時の既定は true）、`request_parameter_supported: false`、`claims_parameter_supported: false` を載せる。省略しても対応を意味しない任意の項目のうち、実装していない機能は載せない。`code_challenge_methods_supported: ["S256"]`（RFC 8414）、`token_endpoint_auth_methods_supported: ["client_secret_basic", "none"]`、`authorization_response_iss_parameter_supported: true`（RFC 9207）を明示する。`scopes_supported` は `openid` と `profile` だけにする |
| OAuth 2.0（RFC 6749）と Security BCP（RFC 9700） | implicit と password グラントは提供しない。クライアント認証は client\_secret\_basic（RFC 6749 でサーバーに必須の方式）と、public client 向けの none だけにする。redirect URI は完全一致で、例外はネイティブアプリのループバックのポートだけ（RFC 9700 §2.1）。PKCE ダウングレード対策（RFC 9700 §2.1.1）は、`code_challenge` のない認可リクエストを拒否することで満たす |
| OAuth 2.0 for Native Apps（RFC 8252） | redirect URI の 3 方式（ループバック、カスタムスキーム、https）をすべて受け付ける。client type を登録時に記録し、public client には毎回ユーザーの操作を求める |
| OAuth 2.0 for Browser-Based Applications（RFC 10017） | ブラウザだけで動く SPA は受け付けず、BFF（confidential client）にしてもらう |
| PKCE（RFC 7636） | `S256` のみ受け付け、`plain` は拒否する |
| 認可レスポンスの `iss`（RFC 9207） | 認可レスポンス（エラーレスポンスを含む）に `iss` を付け、mix-up 攻撃を防ぐ |
| JWT（RFC 7519 / RFC 8725）と JWT アクセストークン（RFC 9068） | `alg` は許可リスト（`Ed25519` と、RS256 を有効にしたときの `RS256`）で固定し、鍵の種類と結び付ける。`Ed25519` は `kty: OKP` / `crv: Ed25519` の鍵とだけ、`RS256` は RSA の鍵とだけ使い、`EdDSA` と `none` を含むそれ以外は拒否する（RFC 8725 §3.1）。アクセストークンは `Ed25519` だけを受け付ける。`typ` で ID トークン（`JWT`）とアクセストークン（`at+jwt`）を区別する。`aud` を必ず検証する。アクセストークンの `aud` は、`resource` の指定がないときの既定のリソースである issuer にする（RFC 9068 §3） |
| JWS / JWK（RFC 7515 / RFC 7517） | JWKS に `kid` 付きで公開鍵を載せ、ローテーション中は新旧両方を載せる。Ed25519 の鍵は `kty: OKP`、`crv: Ed25519`、`x` で表す（RFC 8037 §2） |
| 完全指定のアルゴリズム（RFC 9864） | JWS の `alg` は完全指定の `Ed25519`（§2.2、§4.1.1）を使う。§4.1.2 で Deprecated になった多態の `EdDSA` は、発行も受け付けもしない |
| OpenID Connect RP-Initiated Logout 1.0 | `end_session_endpoint` を公開し、GET と POST で受け付ける。`id_token_hint` は発行者であることを確かめ、期限切れも受け付ける。`post_logout_redirect_uri` は事前登録した値との完全一致だけでリダイレクトする（下記）。Front-Channel Logout 1.0 と Back-Channel Logout 1.0 は実装しない |
| WebAuthn Level 3（W3C） | 登録と認証の検証手順を省略せずに実装する（下記） |

**OIDC Core で守ること**

- `/authorize` は GET と POST の両方を受け付ける。
- `scope` に `openid` がない認可リクエストは、`invalid_scope` で拒否する。OIDC Core §3.1.2.1 は `openid` がないときの動作を規定していないので、仕様の要求ではなく、fail-closed（設計原則 4）による方針として決める。
- リクエストに `state` があれば、成功・エラーどちらのレスポンスにもその値をそのまま返す。
- Core 15.1 の必須機能を満たす（RS256 による ID トークンの署名だけは、RS256 を有効にしたデプロイで満たす。下の例外を参照）。`prompt`（`none` / `login`）と `max_age` を正しく処理し、`max_age` があれば ID トークンに `auth_time` を入れる（`max_age=0` は `prompt=login` と同じ扱い）。`display`、`claims_locales`、`acr_values` は、送られてもエラーにせず、値を無視する。`ui_locales` は UI の言語の最初の候補として使い、対応しない言語が含まれてもエラーにしない（§3.1.2.1 の SHOULD NOT。[認証フロー](authentication.md)の画面と言語を参照）。`claims` パラメータには対応しないので、`acr` を Essential Claim として要求されることはなく、§5.5.1.1 の場合は起きない。
- `prompt=none` に他の値が混ざっていたらエラーにする。
- `id_token_hint` があれば、自分が発行したもの（`iss` が issuer で、current か previous の鍵で署名が通る）か検証し、通らなければ検証済みの `redirect_uri` に `invalid_request` を返す。`exp` は確かめない。§3.1.2.2 の 5 は、OP が発行者であることを確かめなければならない（MUST）とし、RP にセッションがあるか最近あったなら、`exp` を過ぎた ID トークンも受け入れるべき（SHOULD）としている。ID トークンは 5 分で切れ、hint はサインインの条件を狭めるだけで権限を与えないので、期限は見ない。§3.1.2.1 は、hint のユーザーがサインイン済みか、その要求でサインインしたなら成功を返し、そうでなければ `login_required` などのエラーを返さなければならない（MUST）としている。そこで、セッションのユーザーが hint の `sub` と違うとき、`prompt=none` なら `login_required` を返し、それ以外はパスキーのサインインに進め、サインインしたユーザーが hint の `sub` と違えば `login_required` を返す（[認証フロー](authentication.md)参照）。
- `/userinfo` は GET と POST の両方を受け付ける（§5.3 の MUST）。アクセストークンは `Authorization` ヘッダーの Bearer で受け取る（§5.3.1、RFC 6750 §2.1。リソースサーバーに必須の方式）。本文とクエリでの受け渡し（RFC 6750 §2.2・§2.3、どちらも任意）には対応しない。
- 対応しない `request`、`request_uri`、`registration` には、それぞれ `request_not_supported`、`request_uri_not_supported`、`registration_not_supported` を返す。対応しない `response_mode` には、エラーパラメータなしの 400 を返す。
- トークンレスポンスには `Cache-Control: no-store` を付ける。
- `redirect_uri` へのリダイレクトには 307 を使わない（303 か 302）。
- サインイン画面と登録画面は、クリックジャッキングと CSRF の対策をする。

**RP-Initiated Logout 1.0 で守ること**

手順の全体は[認証フロー](authentication.md)の「RP からのログアウト」に置く。節ごとの準拠は次のとおり。

| 節 | 要求 | 対応 |
| --- | --- | --- |
| §2 | OP は Logout Endpoint で GET と POST の両方に対応しなければならない（MUST） | `/end_session` で両方を受け付ける。GET はクエリ、POST はフォームの本文だけを読む |
| §2 | `id_token_hint` があれば、OP は自分が発行者であることを確かめなければならない（MUST） | 今の JWKS のどれかの鍵での署名、`typ: JWT`、`iss` の一致を確かめる。通らなければエラーページを返し、ログアウトもリダイレクトもしない |
| §2 | RP にセッションがあるか最近あったなら、`exp` を過ぎた ID トークンも受け付けるべき（SHOULD） | `exp` を確かめない。期限切れの hint でも、`aud` の client と `sub` を使える |
| §2 | `client_id` と `id_token_hint` の両方があれば、`client_id` が ID トークンの発行に使ったものと一致することを確かめなければならない（MUST） | hint の `aud`（1 つの文字列）と比べ、違えば `client_id_mismatch` のエラーページを返す |
| §2 | hint の `sid` が RP の今か最近のセッションに当たらなければ、要求を疑わしいものとして扱うべき（SHOULD）で、断ってもよい（MAY） | `sid` を発行しないので、`sub` と `auth_time` を今のセッションと比べる。当たらなければ確認のページを出し、黙ってはログアウトしない |
| §2 | OP は OP からもログアウトするか利用者に尋ねるべき（SHOULD）。hint がないか、hint が今の OP のセッションやサインイン中の利用者のものでなければ尋ねなければならない（MUST）。利用者が「はい」と答えたらログアウトしなければならない（MUST） | MUST の場合は必ず確認のページを出し、確認されたらセッションを終わらせる。hint の `sub` と `auth_time` が今のセッションと一致するときだけ尋ねない（下の例外） |
| §2 | `logout_hint` の値と意味は OP に委ねる | 受け取って無視する |
| §2 | `ui_locales` の一部または全部に対応していなくてもエラーにすべきでない（SHOULD NOT） | 対応しない言語は飛ばし、`Accept-Language`、英語の順に決める |
| §2.1 | `end_session_endpoint` を discovery に含めなければならない（MUST）。https でなければならない（MUST） | `<issuer>/end_session` を載せる。issuer は https に固定している |
| §3 | `id_token_hint` がなければ、リダイレクト先の正当性を確かめる別の手段がない限り、リダイレクトしてはならない（MUST NOT） | hint がないときは、`client_id` で指定した client に事前登録した値との完全一致を、その手段として扱う |
| §3 | 登録した `post_logout_redirect_uris` のどれとも完全に一致しなければ、リダイレクトしてはならない（MUST NOT） | 文字列の完全一致だけで比べる。ループバックのポートの例外も設けない。一致しなければ IdP のサインアウト済みのページを出す |
| §3 | `state` があれば、OP はリダイレクトでその値を返す | 一致した URI へのリダイレクトにだけ付ける |
| §3.1 | `post_logout_redirect_uris` は https を使うべき（SHOULD）。http は confidential client だけが使ってよい（MAY） | 管理者が `idpctl` で登録する。https の URI だけを受け付け、http とカスタムスキームは登録できない（下の決定） |
| §4 | 検証に失敗した情報は使ってはならず（MUST NOT）、それを必要とする操作は中止しなければならない（MUST）。要求に誤りがあればリダイレクトしてはならない（MUST not） | 誤りのある要求にはエラーページだけを返し、ログアウトもリダイレクトもしない |
| §4 | OP が利用者をサインインしていないと考えるときのログアウトの要求はエラーではない | セッションがなければ、サインアウト済みとして扱う（リダイレクトの規則は同じ） |
| §6 | 有効な `id_token_hint` のない要求はサービス妨害の手段になるので、明示の確認を得るべき | 上の §2 の確認の規則で満たす。確認の送信は同一オリジンの `POST` だけで受ける |

- **登録できる URI の決定**：§3.1 は、confidential client に http を、ネイティブアプリにカスタムスキームを許している。この IdP では、まず必要な Web アプリ（confidential client）のために https だけを受け付ける。ネイティブアプリのログアウト後の戻り先が必要になったときに、カスタムスキームを足すか見直す。ループバックの http は、§3.1 が public client に http を許していないので受け付けない。
- **例外：確認を省く場合（§2 の SHOULD）**：有効な hint の `sub` と `auth_time` が今のセッションと一致するときは、利用者に尋ねずにログアウトする。§2 の MUST の条件（hint がない、hint が今のセッションや利用者のものでない）には当たらず、RP で利用者がサインアウトを選んだ結果として届く要求なので、もう一度尋ねるのは利用者の手間を増やすだけと判断する。攻撃者がこの経路で利用者をログアウトさせるには、今のセッションから発行されたその利用者の ID トークンが要る。
- **Front-Channel Logout 1.0 と Back-Channel Logout 1.0**：実装しない。IdP はセッションごとにどの RP にサインインさせたかを記録せず、ID トークンに `sid` も入れないので、IdP から RP へ知らせる相手がいない。RP のセッションの終了は RP 自身が行い、IdP のセッションの終了は RP-Initiated Logout で RP から求める（[将来拡張](future-extensions.md)参照）。

**例外：RS256 を既定で無効にする**

- RS256 は、RSA の署名鍵を設定したデプロイだけで有効になる任意の機能にする（[トークン設計](tokens.md)参照）。既定のデプロイは RSA の鍵を持たない。
- RS256 を無効にしている間は、次の 3 つの MUST から外れる。
  - OIDC Discovery 1.0 §3：`id_token_signing_alg_values_supported` に RS256 を含めなければならない。
  - OIDC Core 1.0 §15.1：OP は ID トークンを RS256 で署名することをサポートしなければならない。例外は、ID トークンを Token Endpoint からだけ返し、client に `none` だけを登録させる OP で、IdP は `none` を使わないのでこの例外にも当たらない。
  - RFC 9068 §2.1：この仕様に準拠する認可サーバーとリソースサーバーは、サポートする署名アルゴリズムに RS256 を含めなければならない。IdP のアクセストークンは RS256 を有効にしたデプロイでも常に `Ed25519` で署名するので、この逸脱は RS256 の有効・無効にかかわらず続く。
- 理由：RSA を必要とする RP がいない間は、持つ秘密鍵の素材と攻撃面（RSA の署名の実装、鍵の保管とローテーション）を最小にする。署名できないアルゴリズムを discovery に載せると、RP がそれを選んだときに発行が失敗するので、載せる値は設定された鍵から導き、署名できるものだけにする。RFC 9068 §2.1 については、アクセストークンを検証するのは IdP 自身の `/userinfo` だけで、外部のリソースサーバーがないので、相互運用の問題も起きない。外部の API（認可レベル 3）を足すときに見直す（[将来拡張](future-extensions.md)参照）。
- OIDC Discovery 1.0 §3 と OIDC Core 1.0 §15.1 からの逸脱は、RS256 を無効にしている間に限られる。RFC 9068 §2.1 からの逸脱は、上のとおりアクセストークンの署名が常に `Ed25519` なので、RS256 を有効にしても残る（アクセストークンを RS256 で署名できるようにはしない）。RSA を必要とする RP をつなぐときは、運用者が RSA の鍵を設定して RS256 を有効にし、その RP に `RS256` を登録する。
- ID トークンの署名のアルゴリズムは client ごとに必ず明示して登録するので、OIDC Core 1.0 §3.1.3.7 の 7（`alg` は既定の RS256 か、登録時に送った `id_token_signed_response_alg` であるべき（SHOULD））の後者に当たる。

**例外：CORS に対応しない**

- IdP はどのエンドポイントでも CORS のヘッダーを返さない。
- 外れる SHOULD：OIDC Core 1.0 §5.3 は UserInfo Endpoint が CORS に対応すべき（SHOULD）とし、OIDC Discovery 1.0 §3 は Token Endpoint、UserInfo Endpoint、`jwks_uri` が、§4 は設定の情報のエンドポイントが、CORS に対応すべき（SHOULD）としている。
- 理由：ブラウザだけで動く SPA は登録せず、BFF にしてもらう（RFC 10017 §6。[クライアントの種類](clients.md)参照）。RP はすべてサーバー側かネイティブアプリなので、ブラウザから IdP のエンドポイントを直接呼ぶ正規の利用者がいない。CORS を開くと、ブラウザから `/token` と `/userinfo` を呼ぶ経路が増えるだけで、利点がない。
- ブラウザだけで動く RP を受け付けることにしたときに見直す。

**例外：再利用された認可コードの発行済みトークンを失効させない（RFC 6749 §4.1.2）**

- 再利用されたコードは拒否しなければならず（MUST）、可能なら発行済みのトークンを失効させるべき（SHOULD）とされている。コードは `DELETE … RETURNING` で消費するので、2 回目は行が見つからず拒否され、MUST を満たす。
- 外れる SHOULD：アクセストークンをステートレスな JWT にしたので、発行済みのトークンを失効させる手段がない。失効できないのは設計の選択の結果なので、「可能なら」を理由に準拠とはせず、例外として記録する。
- 理由と補い：トークンを D1 で照合する形にすると、`/userinfo` のたびに読み取りが増え、トークンの短さ（5 分）に比べて得るものが小さい。再利用されたときの影響は、トークンの短い有効期限と PKCE で抑える。リフレッシュトークンを発行しないので、長く使える値は残らない。

**WebAuthn で守ること**

- 公開鍵のアルゴリズムは、Level 3 の推奨どおり -8（EdDSA）、-7（ES256）、-257（RS256）を提示する。Workers の WebCrypto は Ed25519 にも対応している。RFC 9864 §4.2.2 は COSE の -8 も Deprecated にしたが、WebAuthn Level 3 §5.4 は、後方互換のために、完全指定の -19（Ed25519）を `pubKeyCredParams` に含めることを推奨せず（NOT RECOMMENDED）、代わりに、または併せて -8 を使うよう求めている。そのため、JOSE では `EdDSA` を拒否して `Ed25519` を使う一方、WebAuthn では仕様の指示どおり -8 を使う。食い違いではなく、それぞれの仕様に従った結果である。
- チャレンジはサーバー側で乱数から生成して一時保存し、有効期間はセレモニーのタイムアウトの推奨範囲（300000〜600000 ミリ秒、既定 300000 ミリ秒）の上限と同程度にすべき（SHOULD）とされている（§13.4.3）。これに従い、登録とサインインのどちらもチャレンジを 10 分有効にし、ブラウザに渡す options の `timeout` も 600000 ミリ秒と明示して、クライアント側のタイムアウトとサーバー側の有効期間を揃える。
- `clientDataJSON` の `type`、`challenge`、`origin` を検証し、`crossOrigin` が true のものは拒否する。
- `rpIdHash`、UP フラグ、UV フラグを検証し、BE / BS フラグの組み合わせが不正なもの（BS だけが立っているなど）は拒否する。
- `user.id`（user handle）は 64 バイトの乱数にし、メールアドレスなどの個人情報を含めない。
- 別のユーザーに登録済みの credential ID での登録は拒否し、登録時は `excludeCredentials` で重複を防ぐ。
- attestation は `none` にする（認証器の機種で信頼を判断しない）。
- パスキーは discoverable credential（`residentKey: required`）にし、ユーザー名なしでサインインできるようにする。
- sign count は、どちらかが 0 でない場合に値が増えていなければ拒否する（同期型パスキーは常に 0 なので対象外）。

**準拠の確認方法**

- OpenID Foundation がホストする適合性テスト（certification.openid.net、無料アカウントで実行可能）で、Basic OP と Config OP のテストプランを流す。Basic OP には `prompt=login` や `max_age` の確認も含まれる。
- 正式な認定（OpenID Certified）は、費用がかかるので取得しない。認定を取らなくても、Basic OP と Config OP のテストプランの全項目合格は必須条件にする。テストプランは RS256 を有効にしたデプロイで流し、RS256 を無効にした既定の構成で RS256 の項目を免除することはしない。
- WebAuthn は、仕様のテストベクタと、Playwright で仮想オーセンティケータを使う e2e テストで確認する。
