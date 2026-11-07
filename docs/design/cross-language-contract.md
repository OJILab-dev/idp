# TypeScript と Go の契約

Go が書いた値を TypeScript が読むので、両者の間の取り決めを実装より先に `contract.md` とテストベクタで固める。どれか 1 つでもずれると、たとえば Go で登録したクライアントシークレットのハッシュが一致せず、認証が通らなくなる。

| 項目 | 取り決め |
| --- | --- |
| スキーマ | D1 のマイグレーション（SQL）を唯一の正とする |
| アクセス判定 | `effective_access` ビューで定義し、Worker と `idpctl` が同じビューを読む |
| トークン・シークレット | 32 バイトの乱数を base64url（パディングなし）にする |
| ハッシュ | SHA-256 のダイジェストを base64url（パディングなし）にする。仕様で決まっている形ではないが、トークン・シークレット、PKCE の S256（RFC 7636）、署名鍵の `kid`（RFC 7638）と揃える |
| ID | 利用者の ID（`users.id`、OIDC の `sub`）は UUIDv4（RFC 9562）を小文字のハイフン区切りで書く。OIDC Core §2 は `sub` の形式を定めず（発行者の中で一意、再割り当てしない、255 文字以内の ASCII、大文字と小文字を区別）、RFC 9562 §8 はセキュリティに関わる用途の UUID には v4 を使うべき（SHOULD）としている。グループの ID（`groups.id`）も同じ形にし、`principals.id` で利用者の ID と同じ名前空間を共有する。client ID と WebAuthn の credential ID はこの対象外 |
| 時刻 | UNIX 秒の整数 |
| JSON カラム | redirect URI は JSON 配列の文字列で持つ。グループの所属はテーブル（`group_members`）で持つ |
| メールアドレスの検索キー | ASCII の小文字化 |
| パスキー | WebAuthn 仕様どおりの値（COSE 公開鍵の生バイトなど） |
| 署名鍵 | JWK で Worker Secret に置く。運用者が生成し、Worker が読む |
| 署名鍵の種類 | RS256 用の RSA 鍵で、モジュラスは 2048 bit。RFC 7518 §3.3 は 2048 bit 以上を求めており、無料枠の CPU 時間に収めるため下限の 2048 bit にする |
| 署名鍵の `kid` | RFC 7638 の JWK thumbprint（SHA-256、base64url でパディングなし） |
| 秘密鍵の JWK | `alg: RS256` と `use: sig` を持たせる |
| JWKS に載せる値 | 公開鍵のメンバー（`kty`、`n`、`e`）と、`kid`、`alg`、`use` だけ |
| トークンのクレーム | `contract.md` に一覧として明記する |
| 監査ログ | `idpctl` が書く。`actor` は `cli` か `mcp`、`idpctl_version` は書き込んだバイナリのバージョン、`operation` は `idpctl` の操作名、`target` は `user:<id>`・`client:<id>`・`group:<id>` のどれか、`result` は `success` か `failure`、`detail_json` は JSON オブジェクトの文字列。セッション ID、トークン、シークレット、登録トークンは書かない（[データモデル](data-model.md)参照） |

- `contract/testdata/vectors.json` に共通のテストベクタ（入力とハッシュ結果など）を置き、TypeScript と Go の両方のテストで検証する。
- 入力の検証（redirect URI の形式、グループ名など）は書き込みを行う Go 側だけで行う。Worker は保存された値と完全一致で比べ、壊れた行は拒否する。
- Worker を将来 Rust で書き直しても、この契約が変わらなければ `idpctl` は影響を受けない。
