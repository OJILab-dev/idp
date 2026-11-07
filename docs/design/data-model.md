# データモデル

状態はすべて D1 に置く。下の 12 テーブルと、管理操作を記録する監査ログのテーブル 1 つ（末尾を参照）からなり、アクセス可否の判定は `effective_access` ビュー 1 つに集約する。Worker と `idpctl` は同じビューを読むので、判定結果が食い違わない。

```sql
-- 付与の主体。user と group の共通の親で、grant はどちらにも同じ形（principal × client）で付ける。
-- (id, kind) の複合外部キーで、1 つの ID が user と group の両方になることを防ぐ。
-- 子（users、groups）の行だけを消すと親が残るので、削除は principals の行に対して行い、外部キーの連鎖で子と grant を消す
CREATE TABLE principals (
  id   TEXT PRIMARY KEY,                -- UUIDv4。user なら users.id、group なら groups.id と同じ値
  kind TEXT NOT NULL CHECK (kind IN ('user', 'group')),
  UNIQUE (id, kind)                     -- 子からの複合外部キーの参照先
);

-- 利用者とパスキー
CREATE TABLE users (
  id             TEXT PRIMARY KEY,        -- 不変のランダム ID（OIDC の sub）。UUIDv4 で、再利用しない
  kind           TEXT NOT NULL DEFAULT 'user' CHECK (kind = 'user'),
  user_handle    BLOB NOT NULL UNIQUE,    -- WebAuthn の user.id。64 バイトの乱数で、個人情報を含めない
  name           TEXT NOT NULL,           -- 表示名。本名でなくてよい。メールアドレスなどの個人情報は持たない
  disabled       INTEGER NOT NULL DEFAULT 0,
  created_at     INTEGER NOT NULL,        -- UNIX 秒
  FOREIGN KEY (id, kind) REFERENCES principals (id, kind) ON DELETE CASCADE
);
CREATE TABLE credentials (             -- WebAuthn 仕様どおりの値をそのまま保存
  id              TEXT PRIMARY KEY,    -- credential ID（base64url）。全ユーザーで一意
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key      BLOB NOT NULL,       -- COSE 形式の公開鍵の生バイト（アルゴリズムもここに含まれる）
  sign_count      INTEGER NOT NULL,
  backup_eligible INTEGER NOT NULL, backup_state INTEGER NOT NULL,
  created_at      INTEGER NOT NULL, last_used_at INTEGER,
  created_via     TEXT NOT NULL CHECK (created_via IN ('enroll', 'self'))  -- 登録リンクか、サインイン中の本人による追加か
);

-- クライアントとアクセス可否（PKCE は全クライアントで必須。認証方法は client_type で決まる）
CREATE TABLE clients (
  id                 TEXT PRIMARY KEY,
  name               TEXT NOT NULL,
  client_type        TEXT NOT NULL CHECK (client_type IN ('confidential', 'public')),  -- RFC 6749 の client type
  secret_hash        TEXT,             -- SHA-256。confidential のときだけ持つ
  redirect_uris_json TEXT NOT NULL,    -- 完全一致で比較する URI の配列（ループバックはポート以外を比較）
  CHECK ((client_type = 'confidential') = (secret_hash IS NOT NULL))
);
-- グループは 0 人以上のユーザーの集合で、ネストしない（メンバーは users だけを参照する）。
-- 空のグループは誰にも許可を出さないので、安全側に倒れる
CREATE TABLE groups (
  id         TEXT PRIMARY KEY,         -- UUIDv4。名前を変えても grant と所属は ID でつながったまま
  kind       TEXT NOT NULL DEFAULT 'group' CHECK (kind = 'group'),
  name       TEXT NOT NULL UNIQUE,     -- idpctl で指定する名前（group:<name>）。形式は idpctl が検証する
  created_at INTEGER NOT NULL,
  FOREIGN KEY (id, kind) REFERENCES principals (id, kind) ON DELETE CASCADE
);
CREATE TABLE group_members (
  user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, group_id)      -- アクセス判定はユーザーから引くので user_id を先にする
);
CREATE TABLE client_access (
  principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,  -- user か group
  client_id    TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  PRIMARY KEY (principal_id, client_id)
);

-- 使い捨ての値（すべて DELETE … RETURNING で消費する。トークンとコードはハッシュで保存する。
-- チャレンジはセレモニーが終わるまでサーバー側に一時保存し、タイムアウトの推奨上限と同程度（10 分）有効にする（WebAuthn §13.4.3）。
-- チャレンジは秘密ではないので、ハッシュにせずそのまま保存する。
-- 期限切れの行は、新しい値を発行するときの同じバッチで削除する）
CREATE TABLE enroll_tokens (token_hash TEXT PRIMARY KEY,
                            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                            expires_at INTEGER NOT NULL);  -- 発行から 10 分。1 回だけ使える
-- チャレンジは用途ごとに発行元へ紐付ける。登録は登録トークン、サインインは認可リクエスト（Cookie）、
-- 本人による追加（直前の再認証と登録の両方）と失効はセッション。失効はさらに対象の credential ID にも紐付ける。
-- サインインは discoverable credential を使うので、options の時点ではユーザーが分からない
CREATE TABLE challenges    (challenge TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
                            purpose TEXT NOT NULL,
                            enroll_token_hash TEXT,          -- 登録のときだけ持つ
                            authorize_request_id_hash TEXT,  -- サインインのときだけ持つ（authorize_requests.id_hash）
                            session_token_hash TEXT,         -- 本人による追加と失効のときだけ持つ（sessions.token_hash）
                            target_credential_id TEXT,       -- 本人による失効のときだけ持つ（失効させる credentials.id）
                            expires_at INTEGER NOT NULL);
CREATE TABLE sessions      (token_hash TEXT PRIMARY KEY,
                            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                            auth_time INTEGER NOT NULL, expires_at INTEGER NOT NULL);  -- auth_time から 1 時間。延長しない
CREATE TABLE auth_codes    (code_hash TEXT PRIMARY KEY,
                            client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
                            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                            redirect_uri TEXT NOT NULL, code_challenge TEXT NOT NULL, nonce TEXT, scope TEXT,
                            auth_time INTEGER NOT NULL, expires_at INTEGER NOT NULL);
-- サインインを挟む間だけ保持する、検証済みの認可リクエスト（15 分。チャレンジの 10 分より先に切れないようにする）。ID は __Host- Cookie でブラウザに渡す
CREATE TABLE authorize_requests (id_hash TEXT PRIMARY KEY,
                            client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
                            redirect_uri TEXT NOT NULL,
                            state TEXT, nonce TEXT, code_challenge TEXT NOT NULL, scope TEXT NOT NULL,
                            prompt_login INTEGER NOT NULL, max_age INTEGER, id_token_hint_sub TEXT,
                            created_at INTEGER NOT NULL,  -- prompt=login の再認証は auth_time >= created_at で判定する
                            expires_at INTEGER NOT NULL);

-- 期限切れの行を消すバッチが、テーブル全体を走査しないようにする（D1 は走査した行数を読み取りとして数える）
CREATE INDEX enroll_tokens_expires_at      ON enroll_tokens (expires_at);
CREATE INDEX challenges_expires_at         ON challenges (expires_at);
CREATE INDEX sessions_expires_at           ON sessions (expires_at);
CREATE INDEX auth_codes_expires_at         ON auth_codes (expires_at);
CREATE INDEX authorize_requests_expires_at ON authorize_requests (expires_at);

-- ユーザー単位の削除（session_revoke、user_disable、passkey_revoke）も、テーブル全体を走査しないようにする（理由は上と同じ）
CREATE INDEX sessions_user_id    ON sessions (user_id);
CREATE INDEX credentials_user_id ON credentials (user_id);

-- アクセス判定の唯一の定義
CREATE VIEW effective_access AS
-- ユーザー自身の principal に付いた grant と、所属するグループの principal に付いた grant の和集合
SELECT u.id AS user_id, a.client_id
FROM users u
JOIN client_access a ON a.principal_id = u.id
WHERE u.disabled = 0
UNION
SELECT u.id AS user_id, a.client_id
FROM users u
JOIN group_members m ON m.user_id = u.id
JOIN client_access a ON a.principal_id = m.group_id
WHERE u.disabled = 0;

-- 監査ログ（OWASP Logging Cheat Sheet の when / where / who / what）。管理操作は idpctl が、
-- 本人のパスキー操作（登録リンクによる登録、本人による追加と失効）は Worker が書く
-- セッション ID、トークン、シークレット、登録トークンは、平文もハッシュも記録しない
CREATE TABLE audit_log (
  id             INTEGER PRIMARY KEY,     -- D1 が採番する。同じ秒の行も書き込んだ順に並ぶ
  occurred_at    INTEGER NOT NULL,        -- UNIX 秒（when）
  actor          TEXT NOT NULL CHECK (actor IN ('cli', 'mcp', 'user')),  -- 操作者（who）。cli と mcp は idpctl の自己申告、user は Worker が書く本人の操作
  writer_version TEXT NOT NULL,           -- 書き込んだ idpctl か Worker のバージョン（where）
  operation      TEXT NOT NULL,           -- 操作名（user_create、passkey_add など。what）
  target         TEXT NOT NULL,           -- 'user:<id>' | 'client:<id>' | 'group:<id>'
  result         TEXT NOT NULL CHECK (result IN ('success', 'failure')),
  detail_json    TEXT NOT NULL DEFAULT '{}'  -- 操作ごとの補足（変更した値、失敗の理由など）を JSON オブジェクトで持つ
);
CREATE INDEX audit_log_occurred_at ON audit_log (occurred_at);  -- audit_tail で新しい順に読む
CREATE INDEX audit_log_target      ON audit_log (target, occurred_at);  -- audit_tail を対象で絞り込む
```

上の 12 テーブルのほかに監査ログ用のテーブル `audit_log` を 1 つ置き、管理操作と本人のパスキー操作を記録する。カラムは OWASP Logging Cheat Sheet の「いつ、どこで、誰が、何を」に対応させ、値の形は [TypeScript と Go の契約](cross-language-contract.md)で固定する。管理者は `idpctl` の `audit_tail` で、いつでも新しい順に読める。

- 記録するのは書き込みの操作で、読み取りの操作（`users_list`、`audit_tail` など）は記録しない。
- Worker が書くのは、本人のパスキー操作だけにする。登録リンクによる登録は `passkey_enroll`、本人による追加は `passkey_add`、本人による失効は `passkey_self_revoke` とし、`actor` は `user`、`target` は `user:<id>`、`detail_json` に credential ID を入れる。本人への通知の代わりに、認証器が増えたり減ったりしたことを管理者が監査ログで確認できるようにする（[認証フロー](authentication.md)参照）。
- 成功した操作は、操作と同じバッチで 1 行を書く。失敗した操作は、バッチが丸ごとロールバックされるので、その後に別の書き込みで `failure` の行を書く。
- グループは名前を変えられるので、`target` には ID（`group:<id>`）を入れ、操作時点の名前を `detail_json` に残す。
- 対象が 2 つある操作は、`grant_add` などでは client を、`group_member_add` などではグループを `target` に入れ、もう一方（`user:<id>` や `group:<id>`）を `detail_json` に入れる。
- 権限を広げる操作（`grant_add`、`group_member_add`）は、新たに使えるようになったユーザーと client の組を `detail_json` に残す。
- 外部キーの連鎖で所属や grant も消える操作（`group_delete`、ユーザーの完全削除）は、消えた行を `detail_json` に残し、監査ログから元に戻せるようにする。
- OWASP の「記録から除くデータ」に従い、セッション ID、トークン、シークレット、登録トークンは書かない。`detail_json` にも入れず、登録リンクの発行では有効期限だけを残す。
- 行は削除しない。家族規模の件数なら、無料枠の DB サイズ（500 MB）に対して十分小さい。

サインインのたびに D1 へは書かず、Worker のログに任せる。期限切れの行は発行時に片付けるので、Cron は使わない。有効かどうかは取り出すときに必ず `expires_at` で判定するので、片付けが遅れても安全性は変わらない（容量にだけ影響する）。
