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
| パスキー | WebAuthn 仕様どおりの値（COSE 公開鍵の生バイトなど） |
| 署名鍵 | JWK で Worker Secret に置く。運用者が生成し、Worker が読む |
| 署名鍵の種類 | RS256 用の RSA 鍵で、モジュラスは 2048 bit。RFC 7518 §3.3 は 2048 bit 以上を求めており、無料枠の CPU 時間に収めるため下限の 2048 bit にする |
| 署名鍵の `kid` | RFC 7638 の JWK thumbprint（SHA-256、base64url でパディングなし） |
| 秘密鍵の JWK | `alg: RS256` と `use: sig` を持たせる |
| JWKS に載せる値 | 公開鍵のメンバー（`kty`、`n`、`e`）と、`kid`、`alg`、`use` だけ |
| トークンのクレーム | `contract.md` に一覧として明記する |
| パスキーの上限 | 1 人あたりのパスキーの上限を、名前の付いた共有の値 `max_passkeys_per_user` として 1 か所で定める。今の値は 10。Worker の本人による追加と登録リンクによる登録の確認、`idpctl` の `enroll_link_issue` の確認は、どれもこの値を使う。仕様が定める値ではない（NIST SP 800-63B-4 §4.1.2.1 は複数の認証器の結び付けを許可しなければならない（SHALL）とするが、上限は定めていない）ので、暫定の値として扱う。ほかのドキュメントは数を書かず、この行を参照する |
| 監査ログ | 管理操作は `idpctl` が、本人のパスキー操作は Worker が書くので、両者で同じ形にする。`actor` は `cli`・`mcp`（`idpctl`）か `user`（Worker）、`writer_version` は書き込んだ `idpctl` か Worker のバージョン、`operation` は操作名（`idpctl` の操作名か、`passkey_enroll`・`passkey_add`・`passkey_self_revoke`）、`target` は `user:<id>`・`client:<id>`・`group:<id>` のどれか、`result` は `success` か `failure`（Worker は `success` だけを書く）、`detail_json` は JSON オブジェクトの文字列。セッション ID、トークン、シークレット、登録トークンは書かない（[データモデル](data-model.md)参照） |

- `contract/testdata/vectors.json` に共通のテストベクタ（入力とハッシュ結果など）を置き、TypeScript と Go の両方のテストで検証する。パスキーの上限の値もここに置き、両方のテストで同じ値を使っていることを確かめる。
- パスキーの上限を変えるときは、この契約の値を変え、Worker と `idpctl` を同時に更新する。下げても既存のパスキーは消さない。新しい上限を超えているユーザーは今のパスキーをそのまま使え、それ以上の追加と登録リンクの発行は拒否され、失効は（最後の 1 本は失効できない規則のもとで）これまでどおりできる。上げるときはマイグレーションが要らない。
- 入力の検証（redirect URI の形式、グループ名など）は書き込みを行う Go 側だけで行う。Worker は保存された値と完全一致で比べ、壊れた行は拒否する。
- Worker を将来 Rust で書き直しても、この契約が変わらなければ `idpctl` は影響を受けない。
