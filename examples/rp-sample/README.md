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
| `POST /logout` | この RP のセッションだけを消す。`Sec-Fetch-Site` が `same-origin` か、それがなければ `Origin` がこの RP のオリジンと一致するリクエストだけを受け付ける |

ID トークンの検証は OIDC Core 1.0 §3.1.3.7 に従います。ヘッダーは `typ`、`alg`、`kid` だけを受け付け、`alg` は `Ed25519` だけにし（RFC 9864。`EdDSA` は受け付けない）、JWKS から `kid` で `kty: OKP`、`crv: Ed25519` の署名用の鍵を 1 つ選んで署名を確かめます。そのうえで `iss`（完全一致）、`aud`（client\_id だけ）、`exp`、`iat`（どちらも 60 秒の時刻のずれを許す）、`nonce` を確かめます。`/userinfo` の `sub` が ID トークンの `sub` と違えば使いません（OIDC Core §5.3.2）。

セッションは `__Host-` Cookie（HttpOnly、Secure、SameSite=Lax、Path=/）に、Worker Secret の鍵で AES-256-GCM により暗号化して置きます。Cookie の名前を追加データに含めるので、ログイン途中の Cookie をセッションとして使い回すことはできません。期限は 1 時間で、延長しません。保存するのは画面に出す ID トークンのクレームと `/userinfo` の応答だけで、トークンそのものは保存しません。

## ログアウトはこの RP だけ

IdP は RP-Initiated Logout などの OIDC のログアウト仕様を v1 では実装しません（[認証フロー](../../docs/design/authentication.md) の「サインアウト」、[スコープ](../../docs/design/scope.md)）。discovery にも `end_session_endpoint` はありません。IdP の `POST /logout` は IdP 自身のページからの同一オリジンのリクエストだけを受け付けるので、RP からは呼べません。

そのため、このサンプルのログアウトは RP のセッションを消すだけです。IdP のセッション（サインインから 1 時間）は残り、その間にもう一度サインインすると、パスキーの操作なしで戻ってくることがあります。IdP からもサインアウトするには、IdP のアカウントページでサインアウトします。

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

サインインできるのは、`grant_add` でこの client を許可したユーザーかグループだけです。

## デプロイ

運用者が、`cf auth login` と `op` のサインインを済ませてから、レビュー済みの main のクリーンなチェックアウトで次の順に実行します。どちらのスクリプトも、アカウント ID をデプロイの設定ファイルが指す 1Password のアイテムから読み、`cf` がそのアカウントに対して動くことを確かめてから変更します。サンプルは workers\_dev のモードのデプロイにだけ置けます。

1. `idpctl client_create` で client を登録し、`grant_add` で使う人を許可する（上の節）。
2. `scripts/deploy-rp-sample.sh <deployment> <client_id>` で、`cf build` と `cf deploy` を実行する。アカウントの workers.dev のサブドメインがデプロイの設定ファイルと一致することを先に確かめ、デプロイの後に、workers.dev が有効でプレビューの URL が無効なことと、ホストの応答を確かめる。新しい Worker の workers.dev のルートが有効になるまでの平文の 404 は、待って再試行する。最初のデプロイでは、秘密がまだないので 500 の設定エラーが返るのが正しい。
3. `scripts/set-rp-sample-secrets.sh <deployment> <client-secret-file>` で、2 つの Worker Secret を設定する。クライアントシークレットは `--secret-out` のファイル（通常のファイルで、本人の所有、権限 `0600` か `0400`）から読み、ファイルの代わりに `-` を渡すと標準入力から読む。引数に秘密そのものは渡さない。`SESSION_KEY` はパイプの中で `openssl rand` が作る。どちらの値も表示しない。このスクリプトは xtrace（`-x`）なしで動く。
4. `--secret-out` のファイルを消す。

`set-rp-sample-secrets.sh` は実行するたびに `SESSION_KEY` を作り直すので、再実行するとサンプルの全員がサインアウトします。クライアントシークレットを `client_rotate_secret` で替えたときも、このスクリプトをもう一度実行します。

## IdP と同じアカウントに置くことの注意

- workers\_dev のモードでは、IdP（`idp.<sub>.workers.dev`）とこのサンプル（`rp-sample.<sub>.workers.dev`）は同じサイトになる（`workers.dev` は Public Suffix List にあり、`<sub>.workers.dev` が登録可能なドメインになる）。`SameSite` の Cookie の属性はサイトの間の送信しか止めないので、このサンプルは状態を変える `POST` で同一オリジンを確かめ、すべての Cookie を `__Host-` にしてホストに縛る。
- このサンプルの Worker を編集できる人は、同じアカウントの IdP の Worker も編集できる。サンプルを置くことで、IdP を変更できる人が増えないようにする。
- Cloudflare は、Worker から同じアカウントの workers.dev のホストへの `fetch` を拒否することがある（エラー 1042）。そうなると discovery、トークンエンドポイント、JWKS、`/userinfo` に届かず、サインインは 502 で失敗する。実際に起きるかは、最初のデプロイで確かめる（未確認）。今は回避の仕組みを持たない。
- IdP への `fetch` は、すべて `User-Agent: idp-rp-sample/1.0` を名乗る。workers.dev のブラウザの完全性チェックが、ライブラリの既定の User-Agent を Worker に届く前に拒否するため（[ブートストラップ](../../docs/deployment/bootstrap.md)）。
- IdP のレート制限（接続元の IP ごと）は、このサンプルからの `fetch` も数える。サンプルは discovery と JWKS を isolate の中で 5 分キャッシュし、1 回のサインインあたりの IdP への要求を減らす。

## 制限

- 1 つのブラウザで同時に進められるログインは 1 つだけ。別のタブで `/login` を開くと、先のログインの Cookie が置き換わり、先の `/callback` は失敗する。
- リフレッシュトークンはない（IdP が発行しない）。RP のセッションが切れたら、もう一度サインインする。
- `/userinfo` の応答が Cookie に収まらない大きさなら、サインインを失敗にする。

## テスト

`pnpm run check` に含まれます。`test/` のテストは、PKCE、`state` と `iss` の確認、ID トークンの検証（正しいトークン、別の `iss`、`aud`、`nonce`、期限切れ、不正な署名、ヘッダーの改変）、暗号化した Cookie（改ざん、期限切れ、別の Cookie や鍵）、偽の IdP を相手にしたルート全体を確かめます。`workerd.test.ts` は、`cf` と同じ形にバンドルしたサンプルを Miniflare（workerd）で動かします。デプロイのスクリプトは `scripts/test/rp-sample.test.sh` が `cf`、`op`、`curl`、`openssl` のスタブで確かめます。どのテストもネットワークに出ません。
