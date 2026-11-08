# 実装に依存しない契約

D1 に保存する値の形と、管理 API の形を、どの実装からも独立した契約として実装より先に固める。サーバー側の実装は今は TypeScript の共有コア 1 つだが、この契約は次のもののためにある。

- 将来 IdP の Worker を Rust で書き直すとき（[Rust 移行計画](rust-migration.md)参照）に、新しい実装が同じ値を読み書きできることを確かめる。
- 実装言語に依存しない e2e テスト（Playwright）が、外から観測できる値を検証する。
- Go の `idpctl` と TypeScript の管理用の Worker が、管理 API の仕様だけでつながる。

どれか 1 つでもずれると、たとえば片方の実装で登録したクライアントシークレットのハッシュがもう片方で一致せず、認証が通らなくなる。

| 項目 | 取り決め |
| --- | --- |
| スキーマ | D1 のマイグレーション（SQL）を唯一の正とする |
| アクセス判定 | `effective_access` ビューで定義し、IdP の Worker と管理用の Worker が同じビューを読む |
| トークン・シークレット | 32 バイトの乱数を base64url（パディングなし）にする |
| ハッシュ | SHA-256 のダイジェストを base64url（パディングなし）にする。仕様で決まっている形ではないが、トークン・シークレット、PKCE の S256（RFC 7636）、署名鍵の `kid`（RFC 7638）と揃える |
| ID | 利用者の ID（`users.id`、OIDC の `sub`）は UUIDv4（RFC 9562）を小文字のハイフン区切りで書く。OIDC Core §2 は `sub` の形式を定めず（発行者の中で一意、再割り当てしない、255 文字以内の ASCII、大文字と小文字を区別）、RFC 9562 §8 はセキュリティに関わる用途の UUID には v4 を使うべき（SHOULD）としている。グループの ID（`groups.id`）も同じ形にし、`principals.id` で利用者の ID と同じ名前空間を共有する。client ID と WebAuthn の credential ID はこの対象外 |
| 時刻 | UNIX 秒の整数 |
| JSON カラム | redirect URI は JSON 配列の文字列で持つ。グループの所属はテーブル（`group_members`）で持つ |
| パスキー | WebAuthn 仕様どおりの値（COSE 公開鍵の生バイトなど） |
| 署名鍵 | JWK で Worker Secret に置く。リポジトリの生成スクリプトで生成し、IdP の Worker が読む。鍵の種類ごとに current と previous を持つ（[トークン設計](tokens.md)参照） |
| 署名鍵の種類 | Ed25519 の鍵（`kty: OKP`、`crv: Ed25519`）を常に持つ。RS256 を有効にするときだけ、RSA の鍵を足す。RSA のモジュラスは 4096 bit。RFC 7518 §3.3 は 2048 bit 以上を求めている（MUST）。NIST SP 800-57 Part 1 Rev. 5 §5.6.1.1 の Table 2 では、RSA の 2048 bit のセキュリティ強度は 112 bit、3072 bit は 128 bit で、4096 bit は表にない（3072 bit と 192 bit に当たる 7680 bit の間にあり、128 bit 以上）。RSA の署名は Ed25519 より重いが、RSA を使うのは `RS256` を登録した client の ID トークンだけなので、その分の CPU 時間だけを受け入れる（[未決事項](open-questions.md)で実測する） |
| 署名鍵の `kid` | RFC 7638 の JWK thumbprint（SHA-256、base64url でパディングなし）。必須のメンバーは、Ed25519 では `crv`、`kty`、`x`（RFC 8037 §2）、RSA では `e`、`kty`、`n`（RFC 7638 §3.2） |
| 秘密鍵の JWK | `use: sig` と、Ed25519 の鍵には `alg: Ed25519`、RSA の鍵には `alg: RS256` を持たせる。`alg: EdDSA` の鍵は不正として拒否する |
| JWKS に載せる値 | 鍵ごとに、公開鍵のメンバー（Ed25519 は `kty`、`crv`、`x`（RFC 8037 §2）、RSA は `kty`、`n`、`e`）と、`kid`、`alg`、`use` だけ。秘密鍵のメンバー（`d` など）は載せない |
| ID トークンの署名アルゴリズム | `clients.id_token_signed_response_alg` に `Ed25519` か `RS256` のどちらかを必ず持つ。省略時の既定（OIDC Dynamic Client Registration 1.0 §2 では RS256）には頼らない。アクセストークンは常に `Ed25519` |
| トークンのクレーム | [トークン設計](tokens.md)の表と「クレームの一覧」を唯一の一覧とし、テストベクタで照らし合わせる |
| 有効・無効 | ユーザー、client、グループの有効・無効は、追記だけの出来事の表の最新の行で決まる。値は `enabled` か `disabled`。行がなければ無効（[データモデル](data-model.md)参照） |
| client ID | 英小文字、数字、ハイフンからなる 3〜64 文字で、先頭と末尾は英小文字か数字。管理者が決め、不変で、再利用しない |
| UI の言語 | BCP 47 の言語タグで、対応する言語（今は `en` と `ja`）のどれか。`authorize_requests.locale` とサインインページの `lang` クエリが同じ値を使う |
| 管理 API のエラー | RFC 9457 の problem details。`type` は `urn:ojilab:idp:problem:<kind>` で、`kind` の一覧は共有コアで定義し OpenAPI の仕様に載せる（[管理 CLI と管理用の Worker](idpctl.md)参照） |
| Idempotency-Key | トークン・シークレットと同じ形（32 バイトの乱数の base64url）。それ以外の形は拒否する |
| 一覧のカーソル | 向き（次か前か）と境界の行の並びのキー（次はページの最後の行、前はページの最初の行）を base64url（パディングなし）にしたもの。署名しない。共有コアが検証する |
| パスキーの上限 | 1 人あたりのパスキーの上限を、名前の付いた共有の値 `max_passkeys_per_user` として 1 か所で定める。今の値は 10。IdP の Worker の本人による追加と登録リンクによる登録の確認、管理用の Worker の `enroll_link_issue` の確認は、どれもこの値を使う。仕様が定める値ではない（NIST SP 800-63B-4 §4.1.2.1 は複数の認証器の結び付けを許可しなければならない（SHALL）とするが、上限は定めていない）ので、暫定の値として扱う。ほかのドキュメントは数を書かず、この行を参照する |
| 監査ログ | 管理操作は管理用の Worker が、本人のパスキー操作は IdP の Worker が書くので、両者で同じ形にする。`actor` は `admin`（管理用の Worker）か `user`（IdP の Worker）か `break_glass`（基盤の権限で手で書く行）。`admin` の行は、許可リストで確定した管理者の名前を `admin_name` に、使われたクライアント証明書の SHA-256 フィンガープリントを `admin_cert_sha256` に必ず持ち、`user` と `break_glass` の行はどちらも持たない。`writer_version` は書き込んだ Worker のバージョン、`operation` は操作名（`idpctl` の操作名か、`passkey_enroll`・`passkey_add`・`passkey_self_revoke`）、`target` は `user:<id>`・`client:<id>`・`group:<id>`・`schema`・`none` のどれか、`result` は `success` か `failure`（`user` と `break_glass` の行は `success` だけ）、`detail_json` は JSON オブジェクトの文字列で、ID、列挙値、数値、時刻、個人情報を含まない設定値だけを持ち、名前と自由記述を持たない。セッション ID、トークン、シークレット、登録トークンは書かない（[データモデル](data-model.md)参照） |
| 管理 API | 管理用の Worker の HTTPS API。仕様（OpenAPI など）は共有コアの入力のスキーマから生成し、`idpctl` の Go の型はその仕様から生成する。生成物は手で編集せず、仕様と生成物のずれは CI で検出する。これが Go と TypeScript の間の唯一の契約になる（[管理 CLI と管理用の Worker](idpctl.md)参照） |

- D1 のマイグレーションは `contract/migrations/` に置く。SQL は実装の言語に依存しない契約なので、TypeScript の workspace の外に置き、将来の Rust の実装も同じファイルを使う。`0001_init.sql` は[データモデル](data-model.md)の SQL のブロックと同じ内容にし、ずれはテストで検出する。
- `contract/testdata/vectors.json` に共通のテストベクタ（入力とハッシュ結果など）を置き、共有コアのテストで検証する。パスキーの上限の値もここに置き、コアが同じ値を使っていることを確かめる。将来 Rust の実装を足すときは、同じテストベクタをその実装のテストでも検証する。
- パスキーの上限を変えるときは、この契約の値を変え、共有コアを更新する。下げても既存のパスキーは消さない。新しい上限を超えているユーザーは今のパスキーをそのまま使え、それ以上の追加と登録リンクの発行は拒否され、失効は（最後の 1 本は失効できない規則のもとで）これまでどおりできる。上げるときはマイグレーションが要らない。
- 入力の検証（redirect URI の形式、グループ名など）は、書き込みを行う共有コアだけで行う。`idpctl` は検証せず、管理用の Worker が返すエラーを表示する。IdP の Worker は保存された値と完全一致で比べ、壊れた行は拒否する。
- 管理 API は HTTP の契約なので、サーバー側の実装言語を変えても `idpctl` は影響を受けない。
