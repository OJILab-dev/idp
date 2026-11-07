# TypeScript と Go の契約

Go が書いた値を TypeScript が読むので、両者の間の取り決めを実装より先に `contract.md` とテストベクタで固める。どれか 1 つでもずれると、たとえば Go で登録したクライアントシークレットのハッシュが一致せず、認証が通らなくなる。

| 項目 | 取り決め |
| --- | --- |
| スキーマ | D1 のマイグレーション（SQL）を唯一の正とする |
| アクセス判定 | `effective_access` ビューで定義し、Worker と `idpctl` が同じビューを読む |
| トークン・シークレット | 32 バイトの乱数を base64url（パディングなし）にする |
| ハッシュ | SHA-256。hex か base64url かは未決 |
| ID | UUIDv7 か ULID かは未決 |
| 時刻 | UNIX 秒の整数 |
| JSON カラム | redirect URI やグループは JSON 配列の文字列で持つ |
| メールアドレスの検索キー | ASCII の小文字化 |
| パスキー | WebAuthn 仕様どおりの値（COSE 公開鍵の生バイトなど） |
| 署名鍵 | JWK で Worker Secret に置く |
| トークンのクレーム | `contract.md` に一覧として明記する |

- `contract/testdata/vectors.json` に共通のテストベクタ（入力とハッシュ結果など）を置き、TypeScript と Go の両方のテストで検証する。
- 入力の検証（redirect URI の形式、グループ名など）は書き込みを行う Go 側だけで行う。Worker は保存された値と完全一致で比べ、壊れた行は拒否する。
- Worker を将来 Rust で書き直しても、この契約が変わらなければ `idpctl` は影響を受けない。
