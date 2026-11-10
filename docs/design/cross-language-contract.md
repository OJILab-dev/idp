# 実装に依存しない契約

D1 に保存する値の形と、管理 API の形を、どの実装からも独立した契約として実装より先に固める。サーバー側の実装は今は TypeScript の共有コア 1 つだが、この契約は次のもののためにある。

- 将来 IdP の Worker を Rust で書き直すとき（[Rust 移行計画](rust-migration.md)参照）に、新しい実装が同じ値を読み書きできることを確かめる。
- 実装言語に依存しない e2e テスト（Playwright）が、外から観測できる値を検証する。
- Go の `idpctl` と TypeScript の管理用の Worker が、管理 API の仕様と管理者の署名の形だけでつながる。

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
| 秘密鍵の JWK | `use: sig` と、Ed25519 の鍵には `alg: Ed25519`、RSA の鍵には `alg: RS256` を持たせる。`alg: EdDSA` の鍵は不正として拒否する。Ed25519 の `d` は 32 バイト（RFC 8032 §5.1.5）。RSA の鍵は `d` と CRT のメンバー（`p`、`q`、`dp`、`dq`、`qi`。RFC 7518 §6.3.2）をすべて持つ。`kid` のメンバーを持つ場合は、JWK thumbprint と一致しなければならない |
| JWKS に載せる値 | 鍵ごとに、公開鍵のメンバー（Ed25519 は `kty`、`crv`、`x`（RFC 8037 §2）、RSA は `kty`、`n`、`e`）と、`kid`、`alg`、`use` だけ。秘密鍵のメンバー（`d` など）は載せない |
| ID トークンの署名アルゴリズム | `clients.id_token_signed_response_alg` に `Ed25519` か `RS256` のどちらかを必ず持つ。省略時の既定（OIDC Dynamic Client Registration 1.0 §2 では RS256）には頼らない。アクセストークンは常に `Ed25519` |
| トークンのクレーム | [トークン設計](tokens.md)の表と「クレームの一覧」を唯一の一覧とし、テストベクタで照らし合わせる |
| 有効・無効 | ユーザー、client、グループの有効・無効は、追記だけの出来事の表の最新の行で決まる。値は `enabled` か `disabled`。行がなければ無効（[データモデル](data-model.md)参照） |
| client ID | 英小文字、数字、ハイフンからなる 3〜64 文字で、先頭と末尾は英小文字か数字。管理者が決め、不変で、再利用しない |
| UI の言語 | BCP 47 の言語タグで、対応する言語（今は `en` と `ja`）のどれか。`authorize_requests.locale` とサインインページの `lang` クエリが同じ値を使う |
| 管理 API のエラー | RFC 9457 の problem details。`type` は `urn:ojilab:idp:problem:<kind>` で、`kind` の一覧は共有コアで定義し OpenAPI の仕様に載せる（[管理 CLI と管理用の Worker](idpctl.md)参照） |
| Idempotency-Key | トークン・シークレットと同じ形（32 バイトの乱数の base64url）。それ以外の形は拒否する |
| 一覧のカーソル | 向き（次か前か）と境界の行の並びのキー（次はページの最後の行、前はページの最初の行）を base64url（パディングなし）にしたもの。中身は UTF-8 の JSON のオブジェクトで、メンバーは向きの `d`（`next` か `prev`）と、並びのキーの値を列の順に並べた配列の `k` の 2 つだけ。署名しない。共有コアが、メンバー、向き、キーの数と型を一覧ごとに検証する。`idpctl` には不透明な値で、中身を解釈しない |
| パスキーの上限 | 1 人あたりのパスキーの上限を、名前の付いた共有の値 `max_passkeys_per_user` として 1 か所で定める。今の値は 10。IdP の Worker の本人による追加と登録リンクによる登録の確認、管理用の Worker の `enroll_link_issue` の確認は、どれもこの値を使う。仕様が定める値ではない（NIST SP 800-63B-4 §4.1.2.1 は複数の認証器の結び付けを許可しなければならない（SHALL）とするが、上限は定めていない）ので、暫定の値として扱う。ほかのドキュメントは数を書かず、この行を参照する |
| 監査ログ | 管理操作は管理用の Worker が、本人のパスキー操作は IdP の Worker が書くので、両者で同じ形にする。`actor` は `admin`（管理用の Worker）か `user`（IdP の Worker）か `break_glass`（基盤の権限で手で書く行）。`admin` の行は、許可リストで確定した管理者の名前を `admin_name` に、管理者の資格情報の SHA-256 を `admin_cert_sha256` に必ず持ち、`user` と `break_glass` の行はどちらも持たない。`admin_cert_sha256` の意味は資格情報の種類で決まり、前の設計（mTLS）の行ではクライアント証明書の DER の SHA-256、署名の行では署名を検証した鍵の `keyid`（SPKI の DER の SHA-256）になる。種類を区別する列 `admin_credential`（`certificate` か `signing-key`）は、[ホスティングのモード](hosting-modes.md)の 3.9 のとおり `0004` のマイグレーションで足す。列の名前は、変えると表の作り直しが要るので残す。`writer_version` は書き込んだ Worker のバージョン、`operation` は操作名（`idpctl` の操作名か、`passkey_enroll`・`passkey_add`・`passkey_self_revoke`）、`target` は `user:<id>`・`client:<id>`・`group:<id>`・`schema`・`none` のどれか、`result` は `success` か `failure`（`user` と `break_glass` の行は `success` だけ）、`detail_json` は JSON オブジェクトの文字列で、ID、列挙値、数値、時刻、個人情報を含まない設定値だけを持ち、名前と自由記述を持たない。セッション ID、トークン、シークレット、登録トークンは書かない（[データモデル](data-model.md)参照） |
| 管理者の署名 | `idpctl`（Go）が作り、管理用の Worker（TypeScript）が検証する RFC 9421 の署名。形の正本は[ホスティングのモード](hosting-modes.md)の 3.2 から 3.7。`Signature-Input` と `Signature` はちょうど 1 つのメンバーを持ち、ラベルが一致する。対象のコンポーネントは順に `"@method"`、`"@target-uri"`、`"@authority"`、`"content-digest"`、本文を持つ要求（`POST` と `PUT`）だけ `"content-type"`、`Idempotency-Key` を持つ要求だけ `"idempotency-key"`。パラメーターは `created`、`nonce`、`keyid`、`tag` の 4 つだけで、`alg` と `expires` は持たない。署名の基底は RFC 9421 §2.5 のとおり組み立てる |
| 管理者の署名のアルゴリズム | ECDSA P-384 と SHA-384（RFC 9421 §3.3.5 の `ecdsa-p384-sha384`）。署名の値は r と s を 48 バイトずつのビッグエンディアンにして連結した 96 バイトで、それ以外の長さは拒否する。アルゴリズムは許可リストの鍵から決め、要求の申告を受け付けない。ローカルの workerd で検証できることをテストベクタで確かめた。本物の Workers で検証できなければ Ed25519（§3.3.6）に変える（[ホスティングのモード](hosting-modes.md)の 3.3） |
| 管理者の署名のラベル | `sig1` に固定する。`Signature-Input` と `Signature` のメンバーの名前で、管理用の Worker は名前を解釈せず、2 つのヘッダーで一致することだけを求める |
| 管理者の鍵の `keyid` | 公開鍵の SubjectPublicKeyInfo（SPKI）の DER の SHA-256 を、小文字の 16 進 64 文字で書いた値。1Password のアイテムの `public_key_sha256` と同じ値。`idpctl` は秘密鍵の公開鍵から計算し、管理用の Worker は許可リストの `public_key` から計算して `keyid` と一致することを確かめる |
| 署名の `nonce` | トークン・シークレットと同じ形（32 バイトの乱数の base64url）で、厳格な base64url の規則で検証する。管理用の Worker は、署名の検証を通った後で D1 の `admin_request_nonces` に一意に挿入し、2 回目をリプレイとして拒否する |
| 署名の `created` | 整数の UNIX 秒。管理用の Worker の今の時刻の 60 秒前から 60 秒後までだけを受け付ける |
| 署名の `tag` | 固定の文字列 `idp-admin` |
| `Content-Digest` | RFC 9530 の Dictionary で、メンバーはちょうど `sha-256` の 1 つ。値は本文のバイト列の SHA-256 の 32 バイトのバイト列（構造化フィールドのバイト列なので、base64 でパディングあり、コロンで囲む）。本文のない要求は空のバイト列のダイジェストを付ける |
| 管理 API | 管理用の Worker の HTTPS API。仕様（OpenAPI など）は共有コアの入力のスキーマから生成し、`idpctl` の Go の型はその仕様から生成する。生成物は手で編集せず、仕様と生成物のずれは CI で検出する。上の管理者の署名の取り決めと合わせて、これが Go と TypeScript の間の契約になる（[管理 CLI と管理用の Worker](idpctl.md)参照） |

- D1 のマイグレーションは `contract/migrations/` に置く。SQL は実装の言語に依存しない契約なので、TypeScript の workspace の外に置き、将来の Rust の実装も同じファイルを使う。番号順のマイグレーションのファイルは、[データモデル](data-model.md)の SQL のブロックと出てくる順に 1 対 1 で同じ内容にし、ずれはテストで検出する。
- base64url の復号は厳格にする。パディング、URL セーフでない文字（`+`、`/`、空白を含む）、長さを 4 で割った余りが 1 のもの、末尾の余りのビットが 0 でないもの（RFC 4648 §3.5）を拒否し、同じバイト列の書き方を 1 つに限る。署名鍵の JWK では、必須のメンバーがこの形の文字列であることと、Ed25519 の `x` が 32 バイト（RFC 8032 §5.1.5）であることも確かめ、合わなければ `kid` を計算せずに拒否する。
- `contract/testdata/vectors.json` に共通のテストベクタ（入力とハッシュ結果など）を置き、共有コアのテストで検証する。パスキーの上限の値もここに置き、コアが同じ値を使っていることを確かめる。将来 Rust の実装を足すときは、同じテストベクタをその実装のテストでも検証する。
- 管理者の署名のテストベクタ（署名の基底の文字列、`Content-Digest`、`keyid`、正しい署名と否定の署名、`nonce` の形）も同じファイルに置き、TypeScript の検証器と Go の `idpctl` の両方のテストが同じベクタを満たす（[ホスティングのモード](hosting-modes.md)の 3.12）。RFC 9421 の付録の例が当てはまるものはそれを使い、それ以外の鍵はテストの実行時に作る。公開された例の鍵のほかは、秘密鍵をコミットしない。
- 管理者の署名のベクタ（`admin_signature`）は、次の部分からなる。
  - `profile`：ラベル（`sig1`）、`tag`、アルゴリズム、署名の長さ、`created` の窓、`nonce` の長さ、対象のコンポーネントとパラメーターの並び。
  - `content_digest`、`keyid`、`nonce`：それぞれ受け付ける値と、理由を付けた拒否する値。`Content-Digest` の正しい値には RFC 9530 の付録 B.1 の例を含む。
  - `signature_base`：署名する側が満たすもの。要求と、`created`、`nonce`、`keyid` を与えたとき、`idpctl` が作る `Signature-Input` と署名の基底が、ベクタの値と 1 文字ずつ一致しなければならない。
  - `interop`：固定の署名。テストのための使い捨ての P-384 の鍵（秘密鍵は捨て、公開鍵と署名だけを置く）の署名と、RFC 9421 の付録 B.2.6 の Ed25519 の例。どの実装も、これを検証できなければならない。
  - `verify`：検証する側が満たすもの。固定の時刻 `now` と管理用のホスト名で、`valid` を受け付け、`invalid` をすべて `forbidden` で拒否し、`replay` の 2 回目を拒否する。要求の `{keyid}`（許可リストに載せた、テストの実行時に作った鍵の `keyid`）、`{keyid_upper}`（その大文字）、`{other_keyid}`（許可リストにない 2 つ目の鍵の `keyid`）、`{signature}`（置き換えた後の `signature_base` へのテストの鍵の署名の base64）は、テストが置き換える。`signature_base` を持たないケースは署名を付けない。`key` が `other` のケースは 2 つ目の鍵で署名し、`signature_tamper` のケースは署名した後に署名のバイト列を変える。拒否のケースの多くは、形の誤りだけで落ちることを確かめるため、誤った形のまま正しく署名してある。
- パスキーの上限を変えるときは、この契約の値を変え、共有コアを更新する。下げても既存のパスキーは消さない。新しい上限を超えているユーザーは今のパスキーをそのまま使え、それ以上の追加と登録リンクの発行は拒否され、失効は（最後の 1 本は失効できない規則のもとで）これまでどおりできる。上げるときはマイグレーションが要らない。
- 入力の検証（redirect URI の形式、グループ名など）は、書き込みを行う共有コアだけで行う。`idpctl` は検証せず、管理用の Worker が返すエラーを表示する。IdP の Worker は保存された値と完全一致で比べ、壊れた行は拒否する。
- 管理 API は HTTP の契約なので、サーバー側の実装言語を変えても `idpctl` は影響を受けない。
