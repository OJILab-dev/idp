# クライアントの種類

自分のアプリが増えても、作り方に合わせて下の 2 種類のどちらかで登録すれば IdP につながる。種類は RFC 6749 の client type として `clients` に記録し、種類ごとに認証方法と redirect URI の規則を固定する（RFC 8252 §8.4）。

| 種類 | 向いているアプリ | `/token` での認証 | 登録できる redirect URI | IdP のセッションがあるとき |
| --- | --- | --- | --- | --- |
| Web アプリ（confidential） | サーバー側があるアプリ（Grafana、Worker で作るアプリ）、BFF を置いた SPA | `client_secret_basic` | `https` の URI（完全一致） | パスキーを省いてサインインさせる（SSO） |
| ネイティブアプリ・CLI（public） | Go の CLI、デスクトップアプリ、スマホアプリ | なし（`client_id` だけを送り、PKCE で守る） | ループバック（`http://127.0.0.1` と `http://[::1]`、ポートは任意）、逆ドメインのカスタムスキーム、`https` の URI | 毎回パスキーで認証させる |

- **ブラウザだけで動く SPA は登録しない**：RFC 10017 §6 は、ブラウザアプリの構成を安全性の高い順に並べ、トークンをブラウザに出さない BFF を最初に、トークンをブラウザで扱う構成を最後に置いている。SPA を配る Worker に OIDC の処理とセッションを持たせ（BFF）、Web アプリとして登録する。IdP は CORS ヘッダーを返さないので、ブラウザから直接 `/token` を呼ぶこともできない（OIDC の SHOULD からの例外。[標準準拠](standards-compliance.md)参照）。
- **バックエンドは FaaS / PaaS でもよい**：サーバー側でコードが動き、シークレットをブラウザに出さずに置け、https の redirect URI が固定なら、Workers でも Lambda や Vercel でも Web アプリとして登録できる。ログイン途中の `state`・`nonce`・`code_verifier` は、アプリ側で短命の暗号化 Cookie か KV に置く。プレビュー環境のように毎回変わる URL は、完全一致なので登録できない。静的ファイルだけのホスティングは、関数を 1 つ足して BFF にする。
- **ネイティブアプリは毎回パスキー**：public client は誰でも同じ `client_id` を名乗れる。RFC 8252 §8.6 は、client の身元を保証できない限り、ユーザーの操作なしに認可リクエストを処理しないよう求めている。ここでは例外を設けず、以前に許可したことがあっても毎回パスキーで認証させる。`prompt=none` には `login_required` を返す。
- **再認証の頻度は許容する**：リフレッシュトークンを出さないので、ネイティブアプリ・CLI はトークン（5 分）が切れるたびにブラウザでのパスキー認証が要る。Secure by Default の方針を優先し、これを許容する。
- **サインインは OS のブラウザで**：ネイティブアプリは WebView などの埋め込みブラウザを使わない（RFC 8252 §8.12）。CLI は既定のブラウザ、スマホは ASWebAuthenticationSession や Custom Tabs を使う。
- **redirect URI の規則**：RFC 8252 §7 の 3 方式をすべて受け付ける。ループバックは IP リテラルだけを登録でき、`localhost` は拒否する（§8.3 で NOT RECOMMENDED）。カスタムスキームは、自分のドメインを逆順にした形（例：`com.example.app:/callback`）に限る（§7.1）。
- **登録の時点で形を 1 つに固定する**：判定は共有コアの共有のモジュールに 1 つだけ置き、管理用の Worker が登録の時点で確かめる。IdP の Worker は、保存された値を同じ判定で確かめ直して壊れた行を拒否できる。テストベクタは `contract/testdata/vectors.json` に置く。
  - 完全一致で比べる（RFC 9700 §2.1）ので、URL の構文解析器が書き直さない正規の形だけを受け付ける。ホストの大文字、既定のポート（`:443`）、パスのない `https://host` などは、書き直された形で登録するよう拒否する。保存した文字列と同じ値を、もう 1 つの書き方で送らせないため。
  - `localhost` は、末尾のドットを付けた形（`localhost.`）と、そのサブドメイン（`*.localhost`。RFC 6761 §6.3 でループバックに解決される）も拒否する。名前の書き方を変えるだけで §8.3 の禁止を迂回させないため。
  - フラグメントを持つ URI（RFC 6749 §3.1.2）、userinfo を持つ URI、ワイルドカードの `*` を含む URI、空白や ASCII 以外の文字をそのまま含む URI、2,000 文字を超える URI は拒否する。
  - ループバックの URI はポートなしで登録する。ポートは実行時にネイティブアプリが選び（RFC 8252 §7.3）、比較でもポートを無視するので、登録した値にポートがあると、そのポートだけが使えるように見えて紛らわしいため。`127.0.0.1` と `[::1]` 以外のループバックのアドレスも拒否する。
  - confidential client は `https` だけを登録できる。1 つの client に登録できるのは 1〜10 個で、同じ URI を重ねて登録できない。
  - redirect URI は個人情報を含まない設定値なので、`client_create` と `client_set_redirects` の監査ログの行に、新しい一覧をそのまま残す（[データモデル](data-model.md)参照）。
- **API 向けのトークンは v1 で扱わない**：アクセストークンの `aud` は issuer で、受け付けるのは `/userinfo` だけ（[トークン設計](tokens.md)参照）。別の API を呼ぶ用途（RFC 8707 の `resource` 指定）は、ledger を作るときに足す。

**新しいアプリを足すとき**

1. 上の表で種類を決める。SPA なら BFF を置いて Web アプリにする。
2. `idpctl client_create` で登録する。client ID は管理者が決め（英小文字、数字、ハイフンの 3〜64 文字。[管理 CLI と管理用の Worker](idpctl.md)参照）、後から変えられず、client を無効化しても再利用されない。ネイティブアプリなら `--public` を付ける。Web アプリのシークレットは 0600 のファイルに書き出される。ID トークンの署名アルゴリズムは既定の `Ed25519` のままにし、RP のライブラリが Ed25519 を検証できないときだけ `--id-token-alg RS256` を選ぶ（RS256 を有効にしたデプロイでだけ登録できる。[トークン設計](tokens.md)参照）。
3. `idpctl grant_add group:<group_id> <client_id>` などで、使える人を決める。
4. アプリに Discovery の URL（`https://<IdP のホスト>/.well-known/openid-configuration`）と `client_id` を設定し、標準の OIDC ライブラリでつなぐ。IdP 専用の SDK は作らない。

アプリを使わなくなったら、`idpctl client_disable` で無効化する。client は削除しない。無効な client の `/authorize` はリダイレクトせずエラーページを返し（登録された redirect URI がもう信頼できないかもしれないため）、`/token` と `/userinfo` も拒否する。
