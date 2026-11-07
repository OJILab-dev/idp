# 技術選定

IdP 本体の Worker は TypeScript、手元の管理ツールは Go で作る。両者は SQL とエンコーディングの契約だけでつながる。

| 構成要素 | 選択 | 理由 |
| --- | --- | --- |
| IdP 本体（Worker） | TypeScript + Hono | SimpleWebAuthn と jose（WebCrypto）が成熟しており、無料枠の CPU とサイズに収まる |
| 管理 CLI / MCP | Go（単一バイナリ `idpctl`） | 手元で動き、MCP 公式 Go SDK と標準の暗号ライブラリが使える |
| データベース | D1 | `DELETE … RETURNING` で使い捨て値を原子的に消費でき、無料枠で足りる |
| トークン署名 | RS256（WebCrypto） | OIDC Discovery で RS256 のサポートが必須。 |
| e2e テスト | Playwright（ブラックボックス） | HTTP とブラウザ操作で IdP を外から叩くので実装言語に依存せず、Rust に移行しても同じテストを流せる。仮想オーセンティケータでパスキーの操作を自動化できる |
| ストレージに使わないもの | KV | 結果整合で使い捨て値に向かず、無料枠の書き込みが 1 日 1,000 件と少ない |

**今 Rust を採らない理由**

- 実績のある WebAuthn ライブラリ webauthn-rs は OpenSSL 依存で、Workers の Wasm 環境では動かない。
- 純 Rust の `rsa` クレートは Marvin Attack（RUSTSEC-2023-0071）が未修正で、ネット越しに署名を叩ける IdP では使えない。
- 結果として、IdP で最も危険な部分を自前で書くことになる。移行の条件は[Rust 移行計画](rust-migration.md)にまとめる。

**検討して外した候補**

- Gleam：書き味は Rust に近く JS ライブラリも使えるが、FFI の型を自分で保証する必要がある。
- Go（syumai/workers）：通常の Go はバイナリが大きく無料枠に載らず、TinyGo ではライブラリの互換性が不安。
- Python Workers：無料枠の CPU 10 ms と起動 1 秒の上限に対して重い。
