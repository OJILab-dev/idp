# 認証フロー

サインインは「client と redirect\_uri を最初に検証 → パスキーでセッションを作る → 使い捨ての認可コードをトークンに交換」の順で進む。どの段階でも、検証が終わる前の値は信用しない。

**サインイン（認可コードフロー）**

1. RP アプリが `/authorize` にリダイレクトする。Worker は最初に `client_id` と `redirect_uri`（完全一致。ループバックだけポートを問わない）を検証し、不一致ならリダイレクトせずエラーページを返す。続いて `scope` に `openid` が含まれるかを確認し、なければ検証済みの `redirect_uri` に `invalid_scope` を返す。`openid` がないときの動作は仕様で規定されていない（OIDC Core §3.1.2.1）ので、仕様の要求ではなく fail-closed（設計原則 4）の方針として拒否する。
2. `effective_access` で、セッションのユーザーがこのクライアントを使えるか確認する（セッションがなければ手順 4 へ。public client は、セッションがあっても `prompt=login` と同じに扱って手順 4 へ）。使えなければ、検証済みの `redirect_uri` に `access_denied` を返す。セッションの Cookie は SameSite=Lax なので、クロスサイトからの `POST /authorize` にはセッションが付かず、常に手順 4 のパスキーのサインインに進む。安全側に倒れる、意図した動作である。
3. アクセスが許可されていれば、認可コード（60 秒、ハッシュ保存）を発行して `redirect_uri` に戻す。`prompt=none` のとき、セッションがないか public client からの要求なら、検証済みの `redirect_uri` にだけ `login_required` を返す。
4. セッションがない、または `prompt=login` や `max_age` で再認証が必要なら、検証済みのリクエストを `authorize_requests` に保存し（5 分）、その ID を `__Host-` Cookie に入れて、静的アセットのサインインページを表示する。ページは `/webauthn/auth/options` でチャレンジ（256 bit、5 分、D1 に保存）を受け取り、ブラウザでパスキーの署名を作る。discoverable credential を使うのでこの時点ではユーザーが分からず、チャレンジは Cookie の認可リクエスト（`authorize_request_id_hash`）に紐付けて保存する。
5. `/webauthn/auth/verify` でユーザー検証（UV）必須、origin と RP ID 固定で署名を検証し、チャレンジが同じ Cookie の認可リクエストに紐付いていることを確認してから、チャレンジを原子的に消費する。成功したら古いセッションを破棄して新しいセッションを作り、ページは `/authorize/resume` に移る。
6. `/authorize/resume` は Cookie の ID で `authorize_requests` の行を `DELETE … RETURNING` で一度だけ取り出し、Cookie を消す。行がない、または期限切れならエラーページを返す。client と `redirect_uri` が今も登録どおりか、アクセス可否、`prompt=login` または public client ならセッションの `auth_time` が行の `created_at` 以降か、`max_age` と `id_token_hint` の条件を確認し直してから、手順 3 と同じく認可コードを発行する。
7. RP アプリが `/token` を呼ぶ。クライアント認証（`client_secret_basic`。public client は認証せず `client_id` だけを送る）、PKCE、redirect\_uri、ユーザーの現在のアクセス可否をすべて検証してから、認可コードを原子的に消費し、ID トークンとアクセストークンを返す。
8. `/userinfo` は、`typ` が `at+jwt` で `aud` が issuer のアクセストークンだけを受け付ける。毎回 D1 からユーザーを読み直し、無効化されたユーザーと、トークンの `client_id` を使えなくなったユーザーは拒否する。

**認可エンドポイントのエラーの返し方**

- `client_id` と `redirect_uri` を検証できなかったときだけ、リダイレクトせずエラーページを返す（RFC 6749 §4.1.2.1）。
- 検証が済んだ後のエラーは、すべて検証済みの `redirect_uri` に `error`、`state`（リクエストにあった場合）、`iss` を付けて返す（RFC 6749 §4.1.2.1、OIDC Core §3.1.2.6、RFC 9207）。
- 成功時の認可レスポンスにも、リクエストにあった `state` をそのまま付ける（RFC 6749 §4.1.2）。

**パスキーの登録**

1. 管理者が `idpctl` でユーザーを作成し、登録リンク（`/enroll#<token>`）を発行する。トークンは URL のフラグメントに入れ、サーバーのログに残さない。
2. 登録ページはフラグメントからトークンを読み、`/webauthn/register/options` でチャレンジを受け取る。チャレンジは登録トークンに紐付けて保存する。
3. `/webauthn/register/verify` で、チャレンジとトークンの紐付けを確認してからトークンを消費し、パスキーを `credentials` に保存する。

パスキーを失くした場合は、管理者が新しい登録リンクを発行する。2 本目のパスキー（スマホと PC など）の登録を推奨する。

**サインアウト**

- 利用者は `POST /logout`（同一オリジン確認付き）で IdP のセッションを終了できる。セッション行を削除し、Cookie も消す。
- 管理者は `idpctl` の `session_revoke` で、ユーザーの全セッションを失効させられる。`user_disable` と `passkey_revoke` も、そのユーザーの既存セッションを削除する。
- RP-Initiated Logout などの OIDC のログアウト仕様は、v1 では実装しない。
