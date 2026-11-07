# クライアントの種類

自分のアプリが増えても、作り方に合わせて下の 2 種類のどちらかで登録すれば IdP につながる。種類は RFC 6749 の client type として `clients` に記録し、種類ごとに認証方法と redirect URI の規則を固定する（RFC 8252 §8.4）。

| 種類 | 向いているアプリ | `/token` での認証 | 登録できる redirect URI | IdP のセッションがあるとき |
| --- | --- | --- | --- | --- |
| Web アプリ（confidential） | サーバー側があるアプリ（Grafana、Worker で作るアプリ）、BFF を置いた SPA | `client_secret_basic` | `https` の URI（完全一致） | パスキーを省いてサインインさせる（SSO） |
| ネイティブアプリ・CLI（public） | Go の CLI、デスクトップアプリ、スマホアプリ | なし（`client_id` だけを送り、PKCE で守る） | ループバック（`http://127.0.0.1` と `http://[::1]`、ポートは任意）、逆ドメインのカスタムスキーム、`https` の URI | 毎回パスキーで認証させる |

- **ブラウザだけで動く SPA は登録しない**：RFC 10017 §6 は、ブラウザアプリの構成を安全性の高い順に並べ、トークンをブラウザに出さない BFF を最初に、トークンをブラウザで扱う構成を最後に置いている。SPA を配る Worker に OIDC の処理とセッションを持たせ（BFF）、Web アプリとして登録する。IdP は CORS ヘッダーを返さないので、ブラウザから直接 `/token` を呼ぶこともできない。
- **バックエンドは FaaS / PaaS でもよい**：サーバー側でコードが動き、シークレットをブラウザに出さずに置け、https の redirect URI が固定なら、Workers でも Lambda や Vercel でも Web アプリとして登録できる。ログイン途中の `state`・`nonce`・`code_verifier` は、アプリ側で短命の暗号化 Cookie か KV に置く。プレビュー環境のように毎回変わる URL は、完全一致なので登録できない。静的ファイルだけのホスティングは、関数を 1 つ足して BFF にする。
- **ネイティブアプリは毎回パスキー**：public client は誰でも同じ `client_id` を名乗れる。RFC 8252 §8.6 は、client の身元を保証できない限り、ユーザーの操作なしに認可リクエストを処理しないよう求めている。ここでは例外を設けず、以前に許可したことがあっても毎回パスキーで認証させる。`prompt=none` には `login_required` を返す。
- **再認証の頻度は許容する**：リフレッシュトークンを出さないので、ネイティブアプリ・CLI はトークンが切れるたびにブラウザでのパスキー認証が要る。Secure by Default の方針を優先し、これを許容する。
- **サインインは OS のブラウザで**：ネイティブアプリは WebView などの埋め込みブラウザを使わない（RFC 8252 §8.12）。CLI は既定のブラウザ、スマホは ASWebAuthenticationSession や Custom Tabs を使う。
- **redirect URI の規則**：RFC 8252 §7 の 3 方式をすべて受け付ける。ループバックは IP リテラルだけを登録でき、`localhost` は拒否する（§8.3 で NOT RECOMMENDED）。カスタムスキームは、自分のドメインを逆順にした形（例：`com.example.app:/callback`）に限る（§7.1）。
- **API 向けのトークンは v1 で扱わない**：アクセストークンの `aud` は issuer で、受け付けるのは `/userinfo` だけ（[トークン設計](tokens.md)参照）。別の API を呼ぶ用途（RFC 8707 の `resource` 指定）は、ledger を作るときに足す。

**新しいアプリを足すとき**

1. 上の表で種類を決める。SPA なら BFF を置いて Web アプリにする。
2. `idpctl client create` で登録する。ネイティブアプリなら `--public` を付ける。Web アプリのシークレットは 0600 のファイルに書き出される。
3. `idpctl grant add group:family <client_id>` などで、使える人を決める。
4. アプリに Discovery の URL（`https://<IdP のホスト>/.well-known/openid-configuration`）と `client_id` を設定し、標準の OIDC ライブラリでつなぐ。IdP 専用の SDK は作らない。
