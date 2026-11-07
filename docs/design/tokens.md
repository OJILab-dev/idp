# トークン設計

トークンはすべて短命にし、リフレッシュトークンは発行しない。アプリは IdP のセッションを使ったリダイレクトで、新しいトークンを取り直す。盗まれても長く使えるトークンを作らないための、Secure by Default の中心となる決定。

| 種類 | 形式 | 主な中身 | 有効期限 |
| --- | --- | --- | --- |
| ID トークン | JWT（`typ: JWT`、RS256） | 常に `iss`、`sub`、`aud`（client\_id）、`exp`、`iat`、`auth_time`、`nonce`（要求時）。スコープに応じて `email` と `email_verified`（email）、`name`（profile） | 10 分程度 |
| アクセストークン | JWT（`typ: at+jwt`、RS256） | `iss`、`sub`、`aud`（issuer）、`client_id`、`scope`、`exp`、`iat`、`jti` | 5〜10 分 |
| 認可コード | 不透明な値（ハッシュ保存） | client、redirect\_uri、PKCE、nonce に紐付け | 60 秒 |
| セッション | `__Host-` Cookie（ハッシュ保存） | ユーザー、`auth_time` | 未決（[未決事項](open-questions.md)参照） |
| リフレッシュトークン | 発行しない | — | — |

- `sub` は不変のランダム ID で、メールアドレスは使わない。将来 ledger などの外部サービスと結合するときのキー（`iss` + `sub`）になる。
- アクセストークンの `aud` は issuer にする。RFC 9068 §3 では `resource` の指定がなければ既定のリソースを `aud` に入れ、v1 でアクセストークンを受け取るのは IdP の `/userinfo` だけなので、既定のリソースを issuer とする。IdP の中で issuer あてのアクセストークンを受け付けるのは `/userinfo` だけにする。
- 複数の client が同じ IdP を使っても、どの client 向けのトークンかは `client_id` クレームで表す。`/userinfo` はこれを使って、その client に対するアクセス可否を判定する。
- 将来 API（認可レベル 3）を足すときは、resource ごとに登録した URI を `aud` にし、issuer あてのトークンでは API を呼べないようにする。
- クレームは要求されたスコープの分だけ返し、ID トークンにも同じ範囲だけを入れる。独自のクレーム（グループなど）は v1 では発行しない。
- メールアドレスは任意。持たないユーザーには、`email` スコープが要求されても `email` と `email_verified` を返さない（null や空文字を入れずにクレームごと省く。OIDC Core §5.3.2）。
- `email_verified` は既定で `false`。管理者が本人のアドレスであることを確認し、`idpctl` で明示的に指定したときだけ `true` にし、監査ログに記録する。OIDC の定義では、`true` は「OP がそのアドレスを本人が管理していることを確認する手段をとった」ことを意味するため。
- 課金やプランに関する情報はクレームに一切入れない。
- 署名鍵は RS256 の JWK を Worker Secret に置き、インポートした鍵はモジュールスコープでキャッシュする。ローテーションは current と previous の 2 つの Secret で行い、JWKS には両方の公開鍵を載せる。新しい鍵を署名に使う前に JWKS へ載せる手順と、鍵の生成・バックアップは未決（[未決事項](open-questions.md)参照）。
