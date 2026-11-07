# 標準準拠

OIDC と WebAuthn は、仕様の MUST だけでなくセキュリティ上の SHOULD（推奨）にも従う。仕様が実装者に選択を委ねている箇所は安全側を選び、準拠は OpenID Foundation の適合性テストと e2e テストで確認する。

| 規格 | 主な準拠ポイント |
| --- | --- |
| OpenID Connect Core 1.0 | 認可コードフロー（`response_type=code`）のみ。`prompt`（`none` / `login`）と `max_age` を正しく扱い、`auth_time` と `nonce` を ID トークンに入れる。クレームは要求されたスコープの分だけ返す |
| OpenID Connect Discovery 1.0 | `/.well-known/openid-configuration` を公開する。`id_token_signing_alg_values_supported` に RS256 を含め、実装していない機能は載せない。`code_challenge_methods_supported: ["S256"]`（RFC 8414）、`token_endpoint_auth_methods_supported: ["client_secret_basic", "none"]`、`authorization_response_iss_parameter_supported: true`（RFC 9207）を明示する |
| OAuth 2.0（RFC 6749）と Security BCP（RFC 9700） | implicit と password グラントは提供しない。クライアント認証は client\_secret\_basic（RFC 6749 でサーバーに必須の方式）と、public client 向けの none だけにする。redirect URI は完全一致で、例外はネイティブアプリのループバックのポートだけ（RFC 9700 §2.1）。PKCE ダウングレード対策（RFC 9700 §2.1.1）は、`code_challenge` のない認可リクエストを拒否することで満たす |
| OAuth 2.0 for Native Apps（RFC 8252） | redirect URI の 3 方式（ループバック、カスタムスキーム、https）をすべて受け付ける。client type を登録時に記録し、public client には毎回ユーザーの操作を求める |
| OAuth 2.0 for Browser-Based Applications（RFC 10017） | ブラウザだけで動く SPA は受け付けず、BFF（confidential client）にしてもらう |
| PKCE（RFC 7636） | `S256` のみ受け付け、`plain` は拒否する |
| 認可レスポンスの `iss`（RFC 9207） | 認可レスポンス（エラーレスポンスを含む）に `iss` を付け、mix-up 攻撃を防ぐ |
| JWT（RFC 7519 / RFC 8725）と JWT アクセストークン（RFC 9068） | `alg` は許可リスト（RS256）で固定し、`typ` で ID トークン（`JWT`）とアクセストークン（`at+jwt`）を区別する。`aud` を必ず検証する。アクセストークンの `aud` は、`resource` の指定がないときの既定のリソースである issuer にする（RFC 9068 §3） |
| JWS / JWK（RFC 7515 / RFC 7517） | JWKS に `kid` 付きで公開鍵を載せ、ローテーション中は新旧両方を載せる |
| WebAuthn Level 3（W3C） | 登録と認証の検証手順を省略せずに実装する（下記） |

**OIDC Core で守ること**

- `/authorize` は GET と POST の両方を受け付ける。
- `scope` に `openid` がない認可リクエストは、`invalid_scope` で拒否する。OIDC Core §3.1.2.1 は `openid` がないときの動作を規定していないので、仕様の要求ではなく、fail-closed（設計原則 4）による方針として決める。
- リクエストに `state` があれば、成功・エラーどちらのレスポンスにもその値をそのまま返す。
- Core 15.1 の必須機能を満たす。`prompt`（`none` / `login`）と `max_age` を正しく処理し、`max_age` があれば ID トークンに `auth_time` を入れる（`max_age=0` は `prompt=login` と同じ扱い）。`display`、`ui_locales`、`claims_locales`、`acr_values` は、送られてもエラーにしない（値は無視してよい）。
- `prompt=none` に他の値が混ざっていたらエラーにする。
- `id_token_hint` があれば自分が発行したものか検証し、セッションのユーザーと違えば `login_required` を返す。
- 対応しない `request`、`request_uri`、`registration` には、それぞれ `request_not_supported`、`request_uri_not_supported`、`registration_not_supported` を返す。対応しない `response_mode` には、エラーパラメータなしの 400 を返す。
- トークンレスポンスには `Cache-Control: no-store` を付ける。
- `redirect_uri` へのリダイレクトには 307 を使わない（303 か 302）。
- サインイン画面と登録画面は、クリックジャッキングと CSRF の対策をする。

**認可コードの再利用（RFC 6749 §4.1.2）**

- 再利用されたコードは拒否しなければならず（MUST）、可能なら発行済みのトークンを失効させるべき（SHOULD）とされている。コードは `DELETE … RETURNING` で消費するので、2 回目は行が見つからず拒否され、MUST を満たす。アクセストークンはステートレスな JWT で失効させる手段がないため、「可能なら」が条件の SHOULD は対象にならず、準拠している。再利用されたときの影響は、トークンの短い有効期限と PKCE で抑える。

**WebAuthn で守ること**

- 公開鍵のアルゴリズムは、Level 3 の推奨どおり -8（Ed25519）、-7（ES256）、-257（RS256）を提示する。Workers の WebCrypto は Ed25519 にも対応している。
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
- 正式な認定（OpenID Certified）は、費用がかかるので取得しない。認定を取らなくても、Basic OP と Config OP のテストプランの全項目合格は必須条件にする。
- WebAuthn は、仕様のテストベクタと、Playwright で仮想オーセンティケータを使う e2e テストで確認する。
