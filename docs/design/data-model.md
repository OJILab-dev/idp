# データモデル

状態はすべて D1 に置く。下の 9 テーブルと、管理操作を記録する監査ログのテーブル 1 つ（末尾を参照）からなり、アクセス可否の判定は `effective_access` ビュー 1 つに集約する。Worker と `idpctl` は同じビューを読むので、判定結果が食い違わない。

```sql
-- 利用者とパスキー
CREATE TABLE users (
  id             TEXT PRIMARY KEY,        -- 不変のランダム ID（OIDC の sub）。再利用しない
  user_handle    BLOB NOT NULL UNIQUE,    -- WebAuthn の user.id。64 バイトの乱数で、個人情報を含めない
  email          TEXT,                    -- 任意。管理者だけが設定する
  email_key      TEXT UNIQUE,             -- ASCII 小文字化した検索キー。NULL 同士は重複とみなさない
  email_verified INTEGER NOT NULL DEFAULT 0, -- 管理者が明示的に確認したときだけ 1
  name           TEXT NOT NULL,
  groups_json    TEXT NOT NULL DEFAULT '[]',
  disabled       INTEGER NOT NULL DEFAULT 0,
  created_at     INTEGER NOT NULL,        -- UNIX 秒
  CHECK ((email IS NULL) = (email_key IS NULL)),
  CHECK (email_verified = 0 OR email IS NOT NULL)  -- アドレスのない「確認済み」を作らない
);
CREATE TABLE credentials (             -- WebAuthn 仕様どおりの値をそのまま保存
  id              TEXT PRIMARY KEY,    -- credential ID（base64url）。全ユーザーで一意
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key      BLOB NOT NULL,       -- COSE 形式の公開鍵の生バイト（アルゴリズムもここに含まれる）
  sign_count      INTEGER NOT NULL,
  backup_eligible INTEGER NOT NULL, backup_state INTEGER NOT NULL,
  created_at      INTEGER NOT NULL, last_used_at INTEGER
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
CREATE TABLE client_access (
  client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  subject   TEXT NOT NULL,             -- 'user:<id>' | 'group:<name>'
  PRIMARY KEY (client_id, subject)
);

-- 使い捨ての値（すべて DELETE … RETURNING で消費する。トークンとコードはハッシュで保存する。
-- チャレンジはセレモニーが終わるまでサーバー側に一時保存し、タイムアウトの推奨上限と同程度（10 分）有効にする（WebAuthn §13.4.3）。
-- チャレンジは秘密ではないので、ハッシュにせずそのまま保存する。
-- 期限切れの行は、新しい値を発行するときの同じバッチで削除する）
CREATE TABLE enroll_tokens (token_hash TEXT PRIMARY KEY,
                            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                            expires_at INTEGER NOT NULL);
-- チャレンジは用途ごとに発行元へ紐付ける。登録は登録トークン、サインインは認可リクエスト（Cookie）。
-- サインインは discoverable credential を使うので、options の時点ではユーザーが分からない
CREATE TABLE challenges    (challenge TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
                            purpose TEXT NOT NULL,
                            enroll_token_hash TEXT,          -- 登録のときだけ持つ
                            authorize_request_id_hash TEXT,  -- サインインのときだけ持つ（authorize_requests.id_hash）
                            expires_at INTEGER NOT NULL);
CREATE TABLE sessions      (token_hash TEXT PRIMARY KEY,
                            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                            auth_time INTEGER NOT NULL, expires_at INTEGER NOT NULL);
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
SELECT DISTINCT u.id AS user_id, a.client_id
FROM users u
JOIN client_access a
  ON a.subject = 'user:' || u.id
  OR a.subject IN (SELECT 'group:' || value FROM json_each(u.groups_json))
WHERE u.disabled = 0;
```

上の 9 テーブルのほかに監査ログ用のテーブルを 1 つ置き、管理操作だけを記録する（操作者が `cli` か `mcp` か）。スキーマは他のテーブルと同じくマイグレーションを正とする契約（[TypeScript と Go の契約](cross-language-contract.md)）の一部なので、実装前に決める（[未決事項](open-questions.md)参照）。サインインのたびに D1 へは書かず、Worker のログに任せる。期限切れの行は発行時に片付けるので、Cron は使わない。有効かどうかは取り出すときに必ず `expires_at` で判定するので、片付けが遅れても安全性は変わらない（容量にだけ影響する）。
