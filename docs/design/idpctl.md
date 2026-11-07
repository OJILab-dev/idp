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

書き込みの操作は、[認可](authorization.md)の管理の関心事で分類する。基盤の操作（署名鍵、API トークン、デプロイ）は `idpctl` の対象外。

- 読み取り：`users_list`、`user_get`、`clients_list`、`groups_list`、`grants_list`、`access_check`、`audit_tail`
- ユーザーの管理：`user_create`、`user_disable`、`enroll_link_issue`、`passkey_revoke`、`session_revoke`、`group_create`、`group_delete`、`group_member_add`、`group_member_remove`
- RP の管理：`client_create`（public client は `--public`）、`client_set_redirects`、`client_rotate_secret`
- アクセスの管理：`grant_add`、`grant_remove`

**MCP に出す範囲**

AI は操作している人の代理として扱い、役割では区別しない。MCP に出すかどうかは、操作の性質と[操作とリスク](operations-and-risks.md)の影響の広さで決める。

- 書き込みは、すべて毎回人間の確認を必要とする（上記）。
- 取り返しのつかない操作（ユーザーの完全削除など）は CLI 専用にする。
- 本人性を確定させる操作（`enroll_link_issue`）は CLI 専用にする。1 人のユーザーとしてその人の全 RP に入れる強さを持つうえ、登録リンクは対面で渡すので操作する人間はその場にいて、AI に任せる利点がない。
- 読み取りは MCP に出す。IdP が持つ個人情報は表示名だけで、メールアドレスは持たない（[トークン設計](tokens.md)参照）。

`audit_tail` は監査ログを新しい順に返し、対象（`user:<id>` など）で絞り込める。管理者はこれで、本人によるパスキーの追加を含む出来事をいつでも確認できる。

`user_get` は、ユーザーのパスキーの一覧（credential ID、作成日時、最終使用日時、追加の経路、同期型かどうか）を返す。`passkey_revoke` はパスキーを 1 本ずつ失効させる（[認証フロー](authentication.md)の復旧を参照）。

`access_check(user, client)` は、許可か拒否かに加えて、どの grant にマッチしたか（直接付与か、どのグループ経由か。または何が足りないか）を返す。

ユーザーとグループは同じ主体として扱う（[認可](authorization.md)参照）。

- `grant_add(principal, client)` と `grant_remove(principal, client)` は、主体を `user:<id>` か `group:<name>` で受け取る。どちらも同じ操作で、`idpctl` が主体の ID に解決してから `client_access` に書く。
- `grant_add` と `group_member_add` で存在しない主体やグループを指定すると、解決の段階か外部キーの制約で失敗する。打ち間違えた名前で、誰にもマッチしない grant が黙って作られることはない。
- `grant_add` と `group_member_add` は、新たに使えるようになるユーザーと client の組を結果に含める。グループへの grant やメンバーの追加は複数の人の権限をまとめて広げるので、MCP 経由の確認でも影響の範囲が見えるようにするため。
- `group_create` は、メンバーと grant が 0 件のグループを作れる。`groups_list` は、グループごとにメンバーと client の一覧を返す。
- ユーザーとグループの削除は `principals` の行を消し、外部キーの連鎖で所属と grant も消す。

**秘密の扱い**

- シークレットや登録トークンは `crypto/rand` で生成し、D1 にはハッシュだけを書く。
- 平文は戻り値に含めず、権限 `0600` のファイルに書き出してパスだけを返す。MCP 化しても、秘密が AI のコンテキストに流れない。
- 登録リンクは発行から 10 分で切れるので、管理者は本人に渡すその場で `enroll_link_issue` を実行し、メールではなく対面など信頼できる経路で渡す（[認証フロー](authentication.md)参照）。
- 監査ログには管理操作を記録し、操作者（`cli` か `mcp`）を残す。パスキーの結び付け（登録リンクによる登録と本人による追加）は Worker が同じ表に書く。セッション ID、トークン、シークレット、登録トークンは書かない（スキーマは[データモデル](data-model.md)参照）。操作者は `idpctl` の自己申告で、API トークンを持つ人は任意の行を書けるため、改ざんの検知はできない。家族規模の運用では、この限界を受け入れる。
