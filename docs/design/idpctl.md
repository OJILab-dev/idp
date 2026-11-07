# 管理 CLI / MCP（idpctl）

管理操作はすべて手元の Go 製バイナリ `idpctl` から、D1 を直接操作して行う。今は CLI だけを作り、MCP は同じ ops 層を包む形で後から足す。

**構成**

- 1 つのバイナリに、`idpctl user add …` などのサブコマンドと、`idpctl mcp`（stdio の MCP サーバー）を同居させる。どちらも同じ ops パッケージを呼ぶ。
- 各操作の入力は Go の struct で定義し、`Validate()` を持たせる。MCP 公式 Go SDK では、この struct に `jsonschema` タグを付けるとツールの入力スキーマになる。
- D1 へは REST API（`/query` や `/raw`）で接続する。1 つの操作は 1 回のバッチにまとめる。
- Cloudflare の API トークンは D1 の編集権限だけに絞り、有効期限を付けて OS のキーチェーンに保存する。このトークンが実質的な管理者権限になるので、IdP 専用のアカウントで発行する（[デプロイと設定](deployment.md)参照）。
- issuer は Worker と同じ値を設定として持ち、登録リンクの組み立てに使う。
- MCP サーバーは手元の stdio で動かし、IdP 側にリモートの管理エンドポイントは置かない。
- MCP 経由で使うときは、書き込みの操作を Claude Code の permissions で毎回人間の確認が必要な設定にする（[参考資料](references.md)参照）。AI が読んだ外部の文章にプロンプトインジェクションが仕込まれていても、確認なしに管理操作が実行されないようにするため。

**操作の一覧**

- 読み取り：`users_list`、`user_get`、`clients_list`、`grants_list`、`access_check`、`audit_tail`
- 書き込み：`user_create`、`user_disable`、`enroll_link_issue`、`passkey_revoke`、`session_revoke`、`client_create`（public client は `--public`）、`client_set_redirects`、`client_rotate_secret`、`grant_add`、`grant_remove`
- 鍵の生成：`signing_key_generate`（RS256 の鍵ペアを作り、秘密鍵の JWK を下の「秘密の扱い」と同じくファイルに書き出す。D1 には書かない。保存と登録の手順は[トークン設計](tokens.md)参照）
- CLI 専用（MCP には出さない）：ユーザーの完全削除など、取り返しのつかない操作

`access_check(user, client)` は、許可か拒否かに加えて、どの grant にマッチしたか（または何が足りないか）を返す。

`grant_add` で `group:<name>` を指定したとき、そのグループに属するユーザーが 0 人なら警告を出す。グループ名の打ち間違いで、誰にもマッチしない grant が黙って作られるのを防ぐため。

**秘密の扱い**

- シークレットや登録トークンは `crypto/rand` で生成し、D1 にはハッシュだけを書く。
- 平文は戻り値に含めず、権限 `0600` のファイルに書き出してパスだけを返す。MCP 化しても、秘密が AI のコンテキストに流れない。
- 監査ログには管理操作だけを記録し、操作者（`cli` か `mcp`）を残す。操作者は `idpctl` の自己申告で、API トークンを持つ人は任意の行を書けるため、改ざんの検知はできない。家族規模の運用では、この限界を受け入れる。
