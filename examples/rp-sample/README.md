# RP のサンプル（rp-sample）

この IdP を使う最小の relying party（RP）を、Cloudflare Worker として実装したサンプルです。サインイン、ログアウト、アカウント情報のページだけを持ち、実際の RP を作るときの参考にします。IdP の Worker と管理用の Worker からは import せず、別の Worker（名前は `rp-sample`）としてデプロイします。

## 置き場所

`apps/` は IdP の Worker と管理用の Worker の置き場所で、デプロイのスクリプトとデプロイのワークフローが対象にします。サンプルはそのどちらにも含めないので、`examples/` に別の pnpm の workspace として置きました。ESLint の規則で、`apps/` と `packages/` から `examples/` への import と、`examples/` から IdP のパッケージへの import の両方を禁止しています。リポジトリの外の RP と同じく、IdP とは HTTP だけでやり取りします。

## 示すこと

| パス | 動作 |
| --- | --- |
| `GET /` | セッションがあれば、`sub`、ID トークンの主なクレーム（`iss`、`aud`、`auth_time`、`iat`、`exp`、`name`）、`/userinfo` の応答とログアウトのボタンを表示する。なければサインインのリンクを表示する。出力はすべてエスケープする |
| `GET /login` | discovery から `authorization_endpoint` を読み、認可コードフローを始める。`scope` は `openid profile`、PKCE は S256、`state` と `nonce` を付ける。`state`、`nonce`、PKCE の verifier は 10 分で切れる `__Host-` Cookie に暗号化して置く |
| `GET /callback` | `state` を確かめ、`iss` パラメータが issuer と一致することを確かめる（RFC 9207 §2.4。IdP は `authorization_response_iss_parameter_supported` を広告するので、`iss` のない応答も拒否する）。confidential client として `client_secret_basic` でコードを交換し、ID トークンを検証してから `/userinfo` を呼び、セッションを作る |
| `POST /logout` | この RP のセッションを消し、RP-Initiated Logout 1.0 で IdP のセッションも終わらせる（下の「ログアウト」）。`Sec-Fetch-Site` が `same-origin` か、それがなければ `Origin` がこの RP のオリジンと一致するリクエストだけを受け付ける |
| `GET /signed-out` | IdP のログアウトの後の戻り先（`post_logout_redirect_uri`）。返ってきた `state` を、ログアウトのときに置いた 1 回だけ使える暗号化した Cookie と比べ、一致したときだけ「IdP からもサインアウトしました」と表示する |

ID トークンの検証は OIDC Core 1.0 §3.1.3.7 に従います（要件ごとの対応は「標準への準拠」の節）。ヘッダーの知らないメンバーは無視し（RFC 7515 §4）、`crit` と鍵を運ぶメンバー（`jwk`、`jku`、`x5u`、`x5c`）は拒否します。`alg` は `Ed25519` だけにし（RFC 9864。`EdDSA` は受け付けない）、JWKS から `kty: OKP`、`crv: Ed25519` の署名用の鍵を 1 つ選んで（`kid` があればその鍵、なければ使える鍵がちょうど 1 つのときだけ）署名を確かめます。そのうえで `iss`（完全一致）、`aud`（client\_id だけ）、`exp`、`iat`（どちらも 60 秒の時刻のずれを許す）、`nonce` を確かめます。`/userinfo` の `sub` が ID トークンの `sub` と違えば使いません（OIDC Core §5.3.2）。

セッションは `__Host-` Cookie（HttpOnly、Secure、SameSite=Lax、Path=/）に、Worker Secret の鍵で AES-256-GCM により暗号化して置きます。Cookie の名前を追加データに含めるので、ログイン途中の Cookie をセッションとして使い回すことはできません。期限は 1 時間で、延長しません。保存するのは、検証した ID トークンそのものと `/userinfo` の応答です。ID トークンはログアウトの `id_token_hint` に使い、画面に出すクレームもそこから読みます（同じ値を 2 回保存しない）。ID トークンは Cookie の中で暗号化したままにします。アクセストークンは保存しません。

## ログアウト（RP-Initiated Logout 1.0）

IdP は OpenID Connect RP-Initiated Logout 1.0 を実装し、discovery に `end_session_endpoint` を載せます（[認証フロー](../../docs/design/authentication.md) の「RP からのログアウト」）。このサンプルのログアウトは次のように進みます。

1. `POST /logout` で、まずこの RP のセッションの Cookie を消す。この後に何が起きても、RP のセッションは残らない。
2. discovery の `end_session_endpoint` に、`id_token_hint`（セッションに保存した ID トークン）、`post_logout_redirect_uri`（`<ORIGIN>/signed-out`）、`state`（新しい乱数）、`client_id` を送る。送り方は、自動で送信するフォームの `POST` にする。§2 は GET と POST の両方を許すが、GET では ID トークンが URL に載り、ブラウザの履歴やアクセスログに残るため。
3. フォームのページの CSP は、送信する 1 行のスクリプトだけをハッシュ（`script-src 'sha256-…'`）で許し、`form-action` を IdP のオリジンとこの RP 自身（IdP が `/signed-out` へリダイレクトで戻すため）に限る。nonce と `'unsafe-inline'` は使わない。スクリプトが動かなくても、ページのボタンで送信できる。ほかのページは、これまでどおりスクリプトを一切許さない。
4. IdP は、hint が今の IdP のセッションのものならそのままセッションを終わらせ、そうでなければ利用者に確認してから終わらせる。そのうえで `<ORIGIN>/signed-out?state=…` に戻す。確認のページで利用者が「サインインしたままにする」を選ぶと、IdP のセッションは残り、利用者は IdP のアカウントページ（`/account`）にとどまって、この RP には戻らない（ログアウトしないまま RP に戻すと、RP はログアウトが済んだと受け取るため。IdP の設計）。この RP のセッションは手順 1 で消えているので、もう一度使うにはサインインする（パスキーは省かれることがある）。
5. `/signed-out` は、返ってきた `state` を、手順 2 で置いた 10 分で切れる暗号化した `__Host-` Cookie と比べ、Cookie を消す（1 回だけ使える）。一致すれば「IdP からもサインアウトしました」と表示し、一致しなければ 400 で「確かめられませんでした」と表示する。確かめる理由は、`/signed-out` へのリンクは誰でも作れるので、確かめないと、IdP のセッションが終わっていないのに終わったと表示できてしまうため。共用の端末では、利用者が信じてよいのはこの表示だけになる。RP のセッションは手順 1 で消してあるので、失敗しても変わるのは表示だけである。

discovery に `end_session_endpoint` がなければ、この RP のセッションを消すだけにして `/` に戻す（ローカルのログアウト）。`end_session_endpoint` が https の URL でないとき（§2.1 の MUST）と、ログアウトのときに discovery が失敗したときは、IdP には送らず、この RP のセッションはすでに終わっていて IdP のセッションは残っているかもしれないことを 502 のページで知らせる。

workers\_dev のモードでは、IdP とこのサンプルは同じサイトなので（下の「IdP と同じアカウントに置くことの注意」）、手順 2 の `POST` にも IdP の SameSite=Lax のセッションの Cookie が付き、hint が今のセッションのものなら確認なしでログアウトできる。IdP と別のサイトにある RP では、サイトをまたぐ `POST` に Lax の Cookie が付かないので、IdP は確認のページを出す（IdP の設計。確認すればログアウトできる）。

ログアウトしても、すでに発行されたアクセストークンは期限（5 分）まで有効です（IdP は失効させず、Back-Channel Logout もありません）。このサンプルはアクセストークンを保存しないので、影響はありません。

## 設定

| 名前 | 種類 | 内容 |
| --- | --- | --- |
| `ISSUER` | 平文の変数 | IdP の issuer。`https://idp.<workers_dev_subdomain>.workers.dev` |
| `CLIENT_ID` | 平文の変数 | `idpctl client_create` で登録した client\_id |
| `ORIGIN` | 平文の変数 | この Worker のオリジン。`https://rp-sample.<workers_dev_subdomain>.workers.dev`。redirect URI はその `/callback` |
| `CLIENT_SECRET` | Worker Secret | `idpctl client_create --secret-out` が書き出したクライアントシークレット |
| `SESSION_KEY` | Worker Secret | Cookie を暗号化する 32 バイトの鍵（base64） |

平文の変数は `cloudflare.config.ts` が、デプロイのスクリプトが設定する環境変数から作ります。秘密はリポジトリに置かず、どこにも書きません。どれかが欠けているか形が違えば、Worker はすべてのリクエストを 500（`The relying party is misconfigured.`）で拒否します（fail-closed）。

## クライアントの登録

`idpctl client_create` で、次の内容の client を登録します。

- client\_id は `rp-sample`（ほかの値でもよく、デプロイのスクリプトに同じ値を渡す）。
- confidential client（`--public` を付けない）。トークンエンドポイントの認証は `client_secret_basic`。
- redirect URI は `https://rp-sample.<workers_dev_subdomain>.workers.dev/callback`（easyidp では `https://rp-sample.easyidp.workers.dev/callback`）。
- ID トークンの署名アルゴリズムは既定の `Ed25519`（`--id-token-alg` を付けない）。
- クライアントシークレットは `--secret-out` で権限 `0600` のファイルに書き出させる。
- ログアウト後の戻り先（`post_logout_redirect_uris`）は `https://rp-sample.<workers_dev_subdomain>.workers.dev/signed-out`。新しく登録するなら `client_create` の `--post-logout-redirect-uri` で、登録済みの client には運用者がデプロイの後に次を実行する（easyidp の場合）。

  `idpctl client_set_post_logout_redirects rp-sample https://rp-sample.easyidp.workers.dev/signed-out`

  登録がなくても、IdP のセッションは終わるが、IdP はこの RP に戻さず自分のサインアウト済みのページを出す（RP-Initiated Logout 1.0 §3）。

サインインできるのは、`grant_add` でこの client を許可したユーザーかグループだけです。

## デプロイ

運用者が、`cf auth login` と `op` のサインインを済ませてから、レビュー済みの main のクリーンなチェックアウトで次の順に実行します。どちらのスクリプトも、アカウント ID をデプロイの設定ファイルが指す 1Password のアイテムから読み、`cf` がそのアカウントに対して動くことを確かめてから変更します。サンプルは workers\_dev のモードのデプロイにだけ置けます。

1. `idpctl client_create` で client を登録し、`grant_add` で使う人を許可する（上の節）。
2. `scripts/deploy-rp-sample.sh <deployment> <client_id>` で、`cf build` と `cf deploy` を実行する。アカウントの workers.dev のサブドメインがデプロイの設定ファイルと一致することを先に確かめ、デプロイの後に、workers.dev が有効でプレビューの URL が無効なことと、ホストの応答を確かめる。新しい Worker の workers.dev のルートが有効になるまでの平文の 404 は、待って再試行する。最初のデプロイでは、秘密がまだないので 500 の設定エラーが返るのが正しい。
3. `scripts/set-rp-sample-secrets.sh <deployment> <client-secret-file>` で、2 つの Worker Secret を設定する。クライアントシークレットは `--secret-out` のファイル（通常のファイルで、本人の所有、権限 `0600` か `0400`）から読み、ファイルの代わりに `-` を渡すと標準入力から読む。引数に秘密そのものは渡さない。`SESSION_KEY` はパイプの中で `openssl rand` が作る。どちらの値も表示しない。このスクリプトは xtrace（`-x`）なしで動く。
4. `--secret-out` のファイルを消す。
5. ログアウト後の戻り先を登録する：`idpctl client_set_post_logout_redirects <client_id> https://rp-sample.<workers_dev_subdomain>.workers.dev/signed-out`（上の節）。

`set-rp-sample-secrets.sh` は実行するたびに `SESSION_KEY` を作り直すので、再実行するとサンプルの全員がサインアウトします。クライアントシークレットを `client_rotate_secret` で替えたときも、このスクリプトをもう一度実行します。

## IdP と同じアカウントに置くことの注意

- workers\_dev のモードでは、IdP（`idp.<sub>.workers.dev`）とこのサンプル（`rp-sample.<sub>.workers.dev`）は同じサイトになる（`workers.dev` は Public Suffix List にあり、`<sub>.workers.dev` が登録可能なドメインになる）。`SameSite` の Cookie の属性はサイトの間の送信しか止めないので、このサンプルは状態を変える `POST` で同一オリジンを確かめ、すべての Cookie を `__Host-` にしてホストに縛る。
- このサンプルの Worker を編集できる人は、同じアカウントの IdP の Worker も編集できる。サンプルを置くことで、IdP を変更できる人が増えないようにする。
- 互換性フラグ `global_fetch_strictly_public` を有効にする（`cloudflare.config.ts`）。最初のデプロイ（2026-11-13、easyidp）では、このフラグがないとサンプルから同じアカウントの IdP の workers.dev のホストへの `fetch` が失敗し、外からは discovery が正常に返るのに、`/login` は 502（「IdP の応答を確かめられませんでした。」）を返した。Cloudflare の文書は、Worker から Worker への `fetch` にはサービスバインディングかこのフラグが要るとしている。フラグを使うと、`fetch` は公開のインターネットを通り、第三者の RP と同じ経路で IdP に届く。
- サービスバインディングは使わない。バインディングの要求は公開のインターネットを通らないので、IdP が接続元の IP（`CF-Connecting-IP`）で数えるレート制限と、`request.cf.tlsVersion` で確かめる TLS の版が、普通のクライアントと同じには働かない。また、参照用の RP が IdP と同じアカウントにあることを前提にしてしまう。
- IdP への `fetch` が失敗すると、Workers Logs にエンドポイントの名前と HTTP のステータス（`fetch` 自体が失敗したときはエラーの種類）だけを記録する。応答の本文、トークン、秘密は記録しない。
- IdP への `fetch` は、すべて `User-Agent: idp-rp-sample/1.0` を名乗る。workers.dev のブラウザの完全性チェックが、ライブラリの既定の User-Agent を Worker に届く前に拒否するため（[ブートストラップ](../../docs/deployment/bootstrap.md)）。
- IdP のレート制限（接続元の IP ごと）は、このサンプルからの `fetch` も数える。サンプルは discovery と JWKS を isolate の中で 5 分キャッシュし、1 回のサインインあたりの IdP への要求を減らす。

## 制限

- 1 つのブラウザで同時に進められるログインは 1 つだけ。別のタブで `/login` を開くと、先のログインの Cookie が置き換わり、先の `/callback` は失敗する。
- リフレッシュトークンはない（IdP が発行しない）。RP のセッションが切れたら、もう一度サインインする。
- セッションの Cookie が名前と値で 4096 オクテット（UTF-8 で数える）を超えるなら、サインインを 502 で失敗にする。ブラウザはそれより大きい Cookie を黙って捨てるため。ログアウトのために保存する ID トークンもこの大きさに数える。
- 1 つのブラウザで同時に進められるログアウトも 1 つだけ（`/signed-out` の Cookie は最後のログアウトのもの）。

## 標準への準拠

実際の RP の参考にするので、RP の側に課される MUST と SHALL はすべて満たし、安く満たせる SHOULD も満たします。下の表は要件ごとに、実装の場所と、それを確かめるテスト（ファイルとテスト名の一部）を示します。ファイルは `src/` と `test/` からの相対パスです。RFC 6265bis は draft-ietf-httpbis-rfc6265bis-22 の節番号で、OIDC Core 1.0 は「OpenID Connect Core 1.0 incorporating errata set 2」の文言です。

### 署名アルゴリズムの名前

IdP は discovery の `id_token_signing_alg_values_supported` に `Ed25519` を広告します。RFC 8037 §3.1 は Ed25519 と Ed448 をまとめた多態の識別子 `EdDSA` を定めましたが、RFC 9864 §2.2 は曲線まで決まる完全指定の識別子 `Ed25519` を定め、§4.1.2 で `EdDSA` を Deprecated にしました。鍵の表現は RFC 8037 §2 と同じ（`kty: OKP`、`crv: Ed25519`、`x`）です（RFC 9864 §5）。このサンプルはヘッダーの `alg` が `Ed25519` のものだけを受け付け、`EdDSA` は受け付けません。IdP は `Ed25519` だけを発行し（[トークン設計](../../docs/design/tokens.md)）、client はそれを登録するので（OIDC Core §3.1.3.7 の 7）、ほかの値を受け入れる理由がなく、受け入れればアルゴリズムの取り違えの余地が増えるからです（RFC 8725 §3.1）。

### 対応表

| 仕様 | 節 | 要件 | 実装 | テスト |
| --- | --- | --- | --- | --- |
| OIDC Core 1.0 | §3.1.2.1 | 認証リクエストに `response_type=code`、`openid` を含む `scope`、`client_id`、`redirect_uri` を入れる。`state` と `nonce` を付ける | `app.ts`（`/login`） | `app.test.ts`「redirects to the discovered authorization endpoint with PKCE S256, state, nonce, and scope openid profile」 |
| OIDC Core 1.0 | §3.1.2.6 | エラー応答の `error` を受け取る。`state` と `iss` を確かめてから扱い、表示は既定の文字だけの `error` に限る（`error_description` は自由記述なので出さない） | `callback.ts`、`app.ts`（`onError`） | `callback.test.ts`「an error from the IdP」「an error with another iss」「keeps the IdP's error code only when it is a plain OAuth error code」、`app.test.ts`「does not show the IdP's error description」 |
| OIDC Core 1.0 | §3.1.2.7 | 認可応答を RFC 6749 §4.1.2 と §10.12 に従って検証する（MUST） | `callback.ts` | 下の RFC 6749 の行 |
| OIDC Core 1.0 | §3.1.3.1 | トークンリクエストで client を認証する（confidential client の `client_secret_basic`） | `idp.ts`（`redeem`、`clientSecretBasic`） | `app.test.ts`「exchanges the code as a confidential client」 |
| OIDC Core 1.0 | §3.1.3.3 | トークン応答の `id_token` は必須 | `idp.ts`（`redeem`） | `app.test.ts`「no id_token (OIDC Core §3.1.3.3)」 |
| OIDC Core 1.0 | §3.1.3.4 | トークンのエラー応答（RFC 6749 §5.2）を失敗として扱う | `idp.ts`（`requestJson`） | `app.test.ts`「a token endpoint error」「logs the token endpoint's error code, never its description」 |
| OIDC Core 1.0 | §3.1.3.5 | トークン応答を RFC 6749 §5.1 に従って検証し、ID トークンを §3.1.3.7 に従って検証する（MUST） | `idp.ts`、`id-token.ts` | 下の行 |
| OIDC Core 1.0 | §3.1.3.7 の 1 | 暗号化した ID トークンは、登録時に暗号化を求めた場合だけ復号する | 暗号化を登録しないので、5 つの部分からなる JWE は形式の誤りとして拒否する（`id-token.ts`） | `id-token.test.ts`「refuses an encrypted ID token」 |
| OIDC Core 1.0 | §3.1.3.7 の 2 | `iss` は discovery の issuer と完全に一致する（MUST） | `id-token.ts` | `id-token.test.ts`「another issuer」「an issuer with a trailing slash」 |
| OIDC Core 1.0 | §3.1.3.7 の 3 | `aud` が client\_id を含み、信頼しない audience を含まないことを確かめる（MUST） | `id-token.ts`（`audienceMatches`。client\_id だけの文字列か、それだけの配列） | `id-token.test.ts`「another audience」「an audience array with another client」「accepts an aud array that holds the client_id alone」 |
| OIDC Core 1.0（errata set 2） | §3.1.3.7 の 4 | ID トークンが複数の audience を持つ、または `azp` を含むなら、その使い方を定める拡張に従って `azp` を検証すべき（SHOULD） | 拡張を使わないので、複数の `aud` はそれ自体を拒否する（3 のとおり、信頼する audience はこの client だけ） | `id-token.test.ts`「an audience array with another client」 |
| OIDC Core 1.0（errata set 2） | §3.1.3.7 の 5 | `azp` があれば、client\_id と一致することを確かめてよい（MAY） | 確かめる。`id-token.ts`（`audienceMatches`） | `id-token.test.ts`「an azp naming another client」「accepts an azp that names this client」 |
| OIDC Core 1.0 | §3.1.3.7 の 6 | 署名を JWS に従い、ヘッダーの `alg` で検証する（TLS で代えてもよい（MAY）が、このサンプルは常に検証する） | `id-token.ts`（JWKS の鍵を 1 つ選び、Ed25519 で検証） | `id-token.test.ts`「refuses a bad signature」「refuses a token whose payload was changed after signing」 |
| OIDC Core 1.0 | §3.1.3.7 の 7 | `alg` は登録した `id_token_signed_response_alg` であるべき（SHOULD） | `id-token.ts`（`Ed25519` だけ） | `id-token.test.ts`「the deprecated EdDSA identifier」「alg none」「RS256 against an Ed25519 key」 |
| OIDC Core 1.0 | §10.1 | JWKS に使える鍵が複数あるときは `kid` が必要。1 つだけなら `kid` なしでよい | `id-token.ts`（`kid` があればその鍵、なければ使える Ed25519 の署名用の鍵がちょうど 1 つのときだけ受け付ける） | `id-token.test.ts`「accepts a token without kid when the JWKS has exactly one usable Ed25519 signing key」「refuses a token without kid when the JWKS has more than one usable key」「an unknown kid」 |
| RFC 7515 | §4 | 理解しないヘッダーのパラメータは無視しなければならない（MUST） | `id-token.ts`（知らないメンバーは無視する） | `id-token.test.ts`「accepts a header with an x5t」「a private member」 |
| RFC 7515 | §4.1.11 | 理解しない拡張を `crit` に挙げた JWS は無効（MUST）。このサンプルは拡張を理解しないので `crit` は常に拒否する | `id-token.ts`（`REFUSED_HEADER_MEMBERS`） | `id-token.test.ts`「refuses a header with crit」 |
| RFC 7515、RFC 8725 | RFC 7515 §4.1.3〜§4.1.6、RFC 8725 §3.1 | 鍵はトークンからでなく IdP の JWKS からだけ取る（鍵の注入への備え）。`jwk`、`jku`、`x5u`、`x5c` を持つヘッダーは拒否する | `id-token.ts`（`REFUSED_HEADER_MEMBERS`） | `id-token.test.ts`「an embedded jwk」「a jku」「an x5u」「an x5c」 |
| RFC 7515、RFC 7519 | RFC 7515 §4.1.9、RFC 7519 §5.1 | `typ` は大文字と小文字を区別せず比べ、`application/` は省略できる。`JWT` か `application/jwt` を受け付ける（省略も可） | `id-token.ts` | `id-token.test.ts`「typ jwt in lower case」「typ application/JWT」「no typ」「another typ」 |
| OIDC Core 1.0 | §3.1.3.7 の 8 | MAC の `alg` なら client\_secret を鍵にする | 該当なし。HS256 などは 7 で拒否する | `id-token.test.ts`「RS256 against an Ed25519 key」（`Ed25519` 以外の拒否） |
| OIDC Core 1.0 | §3.1.3.7 の 9 | 現在時刻は `exp` より前でなければならない（MUST）。小さなずれは許してよい | `id-token.ts`（60 秒） | `id-token.test.ts`「an expired token」「allows a small clock skew on exp and iat」 |
| OIDC Core 1.0 | §3.1.3.7 の 10 | `iat` で、今から離れすぎたトークンを拒否してよい（MAY） | `id-token.ts`（未来は 60 秒まで、過去は 10 分まで） | `id-token.test.ts`「a token issued in the future」「a token issued long ago」 |
| OIDC Core 1.0 | §3.1.3.7 の 11 | 認証リクエストで送った `nonce` と一致しなければならない（MUST） | `id-token.ts`、`app.ts`（`nonce` は暗号化した Cookie に保つ） | `id-token.test.ts`「another nonce」「no nonce」、`app.test.ts`「an ID token with another nonce」 |
| OIDC Core 1.0 | §3.1.3.7 の 12、13 | `acr` と `auth_time` の確認は、それを要求したときだけ | 該当なし。`acr_values` も `max_age` も送らない。`auth_time` は表示だけ | — |
| OIDC Core 1.0 | §3.1.3.6、§3.1.3.8 | `at_hash` は認可コードフローでは OPTIONAL で、検証してもよい（MAY） | 検証しない（意図的）。IdP は発行せず（[トークン設計](../../docs/design/tokens.md)）、アクセストークンはトークンエンドポイントから TLS で直接受け取り、`/userinfo` にだけ使う。あっても無視する | `id-token.test.ts`「ignores at_hash」、`app.test.ts`「a token response with unknown members」 |
| OIDC Core 1.0 | §5.3.1 | UserInfo へはアクセストークンを Bearer で送る（RFC 6750 §2.1 の Authorization ヘッダー） | `idp.ts`（`redeem`） | `app.test.ts`「exchanges the code as a confidential client」（偽の IdP が Bearer を確かめる） |
| OIDC Core 1.0 | §5.3.2 | 応答の `sub` が ID トークンの `sub` と一致しなければ、応答を使ってはならない（MUST NOT）。署名しない応答は `application/json` | `idp.ts`（`redeem`、`isJson`） | `app.test.ts`「a /userinfo response for another user」「a /userinfo response without sub」「a /userinfo response that is not application/json」、`idp.test.ts`「isJson」 |
| OIDC Core 1.0 | §5.3.3、§5.3.4 | UserInfo のエラーを失敗として扱う。応答した OP が意図した OP であることを TLS で確かめる | `idp.ts`（https の endpoint だけ。Workers の `fetch` が証明書を検証する） | `app.test.ts`「exchanges the code as a confidential client」 |
| OIDC Core 1.0 | §15.5.2 | `nonce` は推測できない値にし、ブラウザのセッションに結び付ける | `pkce.ts`（256 bit の乱数）、`app.ts`（暗号化した `__Host-` Cookie） | `pkce.test.ts`「is 32 random bytes」、`app.test.ts`「keeps state, nonce, and the verifier in a short-lived, sealed __Host- cookie」 |
| OIDC Discovery 1.0 | §4.3 | 文書の `issuer` は取得に使った issuer と完全に一致しなければならず、違えば使ってはならない（MUST） | `idp.ts`（`discover`） | `app.test.ts`「refuses an IdP whose discovery names another issuer」 |
| OIDC Discovery 1.0 | §3 | 必要な機能（`code`、S256、`client_secret_basic`、`Ed25519`、`iss` パラメータ）がなければ使わない | `idp.ts`（`discover`） | `app.test.ts`「refuses an IdP that does not support S256」 |
| RFC 6749 | §2.3.1 | `client_secret_basic` は client\_id と secret をそれぞれ `application/x-www-form-urlencoded` で符号化してから Basic にする | `idp.ts`（`clientSecretBasic`。WHATWG の直列化） | `idp.test.ts`「form-urlencodes both halves before Base64」「encodes non-ASCII as UTF-8 percent-escapes」 |
| RFC 6749 | §3.1 | 認可エンドポイントの URI にある query は、パラメータを足すときに保たなければならない（MUST） | `app.ts`（`/login` は `searchParams.set` で 1 つずつ足す） | `app.test.ts`「retains a query already in the authorization endpoint」 |
| RFC 6749 | §3.1 | パラメータを 2 回以上含めてはならない（MUST NOT）。これは送る側の義務で、受け取る側の RP は、使うパラメータ（`state`、`iss`、`code`、`error`）の繰り返しだけを解釈の食い違いへの備えとして拒否する | `callback.ts`（`USED_PARAMETERS`） | `callback.test.ts`「refuses a repeated state」「refuses a repeated iss」 |
| RFC 6749 | §4.1.2 | 認識しない応答のパラメータは無視しなければならない（MUST）。繰り返されていても無視する | `callback.ts` | `callback.test.ts`「ignores a repeated parameter it does not use」 |
| RFC 6749 | §3.1.2.5 | リダイレクトの受け口は第三者のスクリプトを含めず、資格情報を URI から取り出して別の URI へ移すべき（SHOULD） | `app.ts`（`/callback` は 303 で `/` へ）、`index.ts`（CSP、`Referrer-Policy: no-referrer`） | `app.test.ts`「exchanges the code as a confidential client」「sets the security headers on every page」 |
| RFC 6749 | §4.1.2 | 認可応答の `state` は送った値と完全に一致する。`code` は必須 | `callback.ts` | `callback.test.ts`「another state」「no state」「no code」「an empty code」 |
| RFC 6749 | §4.1.2.1 | 認可のエラー応答の `error` を扱う | `callback.ts` | `callback.test.ts`「an error from the IdP」 |
| RFC 6749 | §4.1.3 | トークンリクエストに `grant_type`、`code`、認可リクエストと同じ `redirect_uri` を入れる | `idp.ts`（`redeem`） | `app.test.ts`「exchanges the code as a confidential client」 |
| RFC 6749 | §5.1 | `access_token` と `token_type` は必須。`token_type` は大文字と小文字を区別しない。知らないメンバーは無視しなければならない（MUST）。応答は `application/json` | `idp.ts`（`redeem`、`isJson`） | `app.test.ts`「a lowercase token_type」「unknown members」「no access_token」「no token_type」「a token response that is not application/json」 |
| RFC 6749 | §5.2 | エラー応答の `error` を失敗として扱う | `idp.ts`（`requestJson`） | `app.test.ts`「logs the token endpoint's error code」 |
| RFC 6749 | §7.1 | 理解できない `token_type` のアクセストークンを使ってはならない（MUST NOT） | `idp.ts`（`Bearer` だけ） | `app.test.ts`「another token_type」 |
| RFC 6749 | §10.12 | `state` を推測できない値にし、ブラウザの認証状態に結び付けて CSRF を防ぐ（MUST） | `app.ts`、`callback.ts`（一定時間の比較）、`sealed.ts` | `app.test.ts`「another state」「refuses a callback without the flow cookie」「refuses an expired flow cookie」 |
| RFC 7636 | §4.1 | verifier は 43〜128 文字の unreserved な文字。高いエントロピー（32 オクテット以上を推奨） | `pkce.ts`（32 バイトの乱数の base64url で 43 文字） | `pkce.test.ts`「is a valid PKCE verifier」 |
| RFC 7636 | §4.2、§4.3 | `code_challenge` は S256 で、`code_challenge_method=S256` を送る | `pkce.ts`、`app.ts` | `pkce.test.ts`「RFC 7636 Appendix B test vector」、`app.test.ts`「redirects to the discovered authorization endpoint」 |
| RFC 7636 | §4.5 | トークンリクエストに `code_verifier` を入れる | `idp.ts`（`redeem`） | `app.test.ts`「exchanges the code as a confidential client」（偽の IdP が S256 で照合する） |
| RFC 9207 | §2.4 | `iss` を issuer と単純な文字列比較で確かめ、違えば拒否する（MUST）。メタデータが対応を示すなら `iss` のない応答も拒否する（MUST） | `callback.ts` | `callback.test.ts`「no iss」「another iss (a mix-up)」「an iss with a trailing slash」、`app.test.ts`「no iss (RFC 9207)」 |
| RFC 9700 | §2.1.1、§4.5.3.1 | 認可コードの注入を防がなければならない（MUST）。その仕組みとして、confidential client にも PKCE を推奨し（RECOMMENDED）、`code_challenge_method` は S256 を使うべき（SHOULD）。このサンプルは PKCE S256 と `nonce` の両方を使う | `app.ts`、`idp.ts` | `app.test.ts`「redirects to the discovered authorization endpoint」「an ID token with another nonce」 |
| RFC 9700 | §2.1、§4.4.2.1 | 複数の AS を使う client は mix-up を防ぐ。issuer を使う防御は RFC 9207 の `iss` | `callback.ts`（AS は 1 つだが常に確かめる） | `callback.test.ts`「another iss (a mix-up)」 |
| RFC 9700 | §4.2.4 | 認可応答の URL を Referer で漏らさない | `index.ts`（`Referrer-Policy: no-referrer`）、`app.ts`（`/callback` はすぐに 303） | `app.test.ts`「sets the security headers on every page」 |
| RFC 9700 | §2.1、§4.7.1 | client は CSRF を防がなければならない（MUST）。PKCE、OIDC の `nonce`、1 回だけ使う `state` のどれでもよい（3 つとも使う） | `app.ts`（`/callback` はフローの Cookie を最初に消す） | `app.test.ts`「exchanges the code as a confidential client」（フローの Cookie の `Max-Age=0`）「another state」 |
| RFC 9700 | §2.1、§4.11.1 | client は開いたリダイレクタになってはならない（MUST NOT） | `app.ts`（リダイレクト先は固定か discovery の endpoint だけ） | `app.test.ts`「answers 404 on an unknown path」 |
| RP-Initiated Logout 1.0 | §2.1 | `end_session_endpoint` は discovery から読む。https でなければならない（MUST） | `idp.ts`（`endSessionEndpoint`）、`app.ts`（`/logout`） | `app.test.ts`「posts the logout request to the discovered end_session_endpoint」「refuses an end_session_endpoint that is not https」「falls back to a local logout when discovery has no end_session_endpoint」「clears the RP session and says so when discovery fails during logout」 |
| RP-Initiated Logout 1.0 | §2 | RP は GET か POST で送ってよい（MAY）。POST はフォームの直列化 | `app.ts`、`html.ts`（`logoutFormPage`。ID トークンを URL に載せないため POST） | `app.test.ts`「keeps the ID token out of the URL」、`workerd.test.ts`「signs in end to end」 |
| RP-Initiated Logout 1.0 | §2 | `id_token_hint` は推奨（RECOMMENDED）。IdP が以前にこの RP へ発行した ID トークン | `app.ts`（`/callback` で暗号化したセッションに保存し、`/logout` で送る） | `app.test.ts`「posts the logout request…」（偽の IdP が発行したトークンと一致）「counts the kept ID token (the logout hint) against the 4096-octet limit」「keeps the ID token once」 |
| RP-Initiated Logout 1.0 | §2 | `client_id` を送ってよい。hint と一緒なら、IdP は一致を確かめる（MUST） | `app.ts`（設定の client\_id） | `app.test.ts`「posts the logout request…」 |
| RP-Initiated Logout 1.0 | §2、§3 | `post_logout_redirect_uri` は事前に登録した値でなければならない（MUST）。IdP は完全一致でだけリダイレクトする | `config.ts`（`<ORIGIN>/signed-out`）、登録は運用者の `idpctl client_set_post_logout_redirects`（上の「クライアントの登録」） | `app.test.ts`「posts the logout request…」 |
| RP-Initiated Logout 1.0 | §2、§3 | `state` は RP が状態を保つための値で、IdP はリダイレクトで返す。RP は自分が送った値であることを確かめる | `app.ts`（`/logout` で乱数を暗号化した 1 回だけの `__Host-` Cookie に置き、`/signed-out` で一定時間の比較） | `app.test.ts`「keeps the returned state in a sealed, single-use __Host- cookie」「confirms the IdP logout when the returned state matches」「does not claim an IdP logout for another state」「refuses an expired logout cookie」「refuses a session cookie replayed as the logout cookie」 |
| RP-Initiated Logout 1.0 | §6 | hint のない要求はサービス妨害の手段になる。IdP は確認を求めるべき | 保存した hint を必ず送る。IdP が確認なしで終わらせるのは、hint が今の IdP のセッションのものと分かるときだけで、それには IdP のセッションの Cookie が要る。workers\_dev のモードでは IdP と同じサイトなので Cookie が付くが、IdP と別のサイトにある RP では、サイトをまたぐ `POST` に SameSite=Lax の Cookie が付かず、hint があっても IdP は確認のページを出す。hint を持たない古いセッションでは送らず、IdP が確認を求める（`app.ts`） | `app.test.ts`「posts the logout request…」「sends no id_token_hint for a session sealed before the hint was kept」 |
| CSP Level 3 | `script-src` のハッシュ、`form-action` | 自動送信のスクリプトだけをハッシュで許し、フォームの送り先を IdP とこの RP に限る | `html.ts`（`logoutContentSecurityPolicy`、`AUTO_SUBMIT_SCRIPT_SHA256`）、`index.ts`（ほかのページはスクリプトなし） | `app.test.ts`「allows exactly the auto-submit script by hash」「pins the script hash constant to the script」「sets the security headers on every page」 |
| RFC 6265bis（-22） | §4.1.3.2 | `__Host-` の Cookie は Secure、`Path=/`、Domain なし | `app.ts`（`COOKIE_OPTIONS`） | `app.test.ts`「keeps state, nonce, and the verifier in a short-lived, sealed __Host- cookie」「exchanges the code as a confidential client」 |
| RFC 6265bis（-22） | §4.1.2.7、§5.6.7.1、§8.8.2 | `SameSite=Lax` の Cookie は、サイトをまたぐトップレベルの安全な遷移（IdP から `/callback` への GET）には付き、サイトをまたぐ POST には付かない | `app.ts`（`COOKIE_OPTIONS`） | 同上 |
| RFC 6265bis（-22） | §5.6 | 名前と値が 4096 オクテットを超える Cookie はブラウザが捨てる | `app.ts`（`MAX_COOKIE_OCTETS`） | `app.test.ts`「refuses a sign-in whose session would exceed 4096 octets」 |
| RFC 9864、RFC 8037 | RFC 9864 §2.2、§4.1.2、§5、RFC 8037 §2 | `Ed25519` を受け付け、Deprecated の `EdDSA` は受け付けない。鍵は `kty: OKP`、`crv: Ed25519` | `id-token.ts`（`isEd25519SigningKey`） | `id-token.test.ts`「the deprecated EdDSA identifier」「refuses a JWKS entry that is not an Ed25519 signing key」 |

### 意図して実装しないもの

| 項目 | 根拠 | 理由 |
| --- | --- | --- |
| `at_hash` の検証 | OIDC Core §3.1.3.8（MAY） | 上の表のとおり。IdP は発行せず、Ed25519 で `at_hash` に使うハッシュは OIDC Core が定めていない（§3.1.3.6 は `alg` のハッシュの左半分とするが、`Ed25519` はハッシュを名前に含まない） |
| Front-Channel Logout、Back-Channel Logout | OpenID Connect Front-Channel Logout 1.0、Back-Channel Logout 1.0 | IdP が実装しない。IdP 側で始まったサインアウトは、この RP には届かない |
| `logout_hint`、`ui_locales` のログアウトの要求 | RP-Initiated Logout 1.0 §2（OPTIONAL） | `id_token_hint` で利用者を示すので `logout_hint` は要らない。画面は IdP の既定の言語の決め方に任せる |
| リフレッシュトークン | RFC 6749 §6 | IdP が発行しない |
| `prompt`、`max_age`、`acr_values`、`claims` | OIDC Core §3.1.2.1、§5.5（OPTIONAL） | 最小のサンプルなので送らない。送らないので §3.1.3.7 の 12、13 も該当しない |
| 署名または暗号化した UserInfo（`application/jwt`） | OIDC Core §5.3.2 | 登録しないので、`application/json` 以外の応答は拒否する |

### IdP との食い違い

RP の振る舞いを曲げずに、次の点を IdP 側の事項として記録します。

- RFC 9700 §2.5 は、クライアント認証に非対称の方式（`private_key_jwt`、mTLS）を推奨します（RECOMMENDED）。IdP が confidential client に提供するのは `client_secret_basic` だけなので、このサンプルはそれを使います。MUST の違反ではありません。
- OIDC Core §15.1 と OIDC Discovery §3 は OP に RS256 を求めます（MUST）が、IdP は既定で RS256 を提供しません。IdP の設計が例外として記録済みです（[トークン設計](../../docs/design/tokens.md)）。このサンプルは `Ed25519` を登録して使うので影響はありません。
- MUST に関わる IdP との食い違いは、この監査では見つかりませんでした。

## テスト

`pnpm run check` に含まれます。`test/` のテストは、PKCE、`state` と `iss` の確認、ID トークンの検証（正しいトークン、別の `iss`、`aud`、`nonce`、期限切れ、不正な署名、ヘッダーの改変）、暗号化した Cookie（改ざん、期限切れ、別の Cookie や鍵）、偽の IdP を相手にしたルート全体を確かめます。`workerd.test.ts` は、`cf` と同じ形にバンドルしたサンプルを Miniflare（workerd）で動かします。デプロイのスクリプトは `scripts/test/rp-sample.test.sh` が `cf`、`op`、`curl`、`openssl` のスタブで確かめます。どのテストもネットワークに出ません。
