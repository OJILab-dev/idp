# データモデル

状態はすべて D1 に置く。下の 16 テーブルと、管理操作と本人のパスキー操作を記録する監査ログのテーブル 1 つ（末尾を参照）と、管理者の署名の `nonce` を置くテーブル 1 つ（`0003`）からなる。アクセス可否の判定は `effective_access` ビュー 1 つに集約し、ユーザー、client、グループの今の有効・無効は、追記だけの出来事の表から導く 3 つのビュー（`user_enablement`、`client_enablement`、`group_enablement`）で読む。IdP の Worker と管理用の Worker は、共有コアの同じ SQL でこれらのビューを読むので、判定結果が食い違わない。

```sql
-- 付与の主体。user と group の共通の親で、grant はどちらにも同じ形（principal × client）で付ける。
-- (id, kind) の複合外部キーで、1 つの ID が user と group の両方になることを防ぐ。
-- principals、users、clients、groups の行は削除しない（末尾のトリガーで拒否する）。止めるのは無効化で行う。
-- 外部キーの ON DELETE CASCADE は、break-glass でトリガーを外して行を消すとき（下記）にだけ働く。
-- 出来事の表は ON DELETE なしで参照するので、主体や client を消す前に、その出来事の行を先に消す必要がある
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
  created_at     INTEGER NOT NULL,        -- UNIX 秒
  FOREIGN KEY (id, kind) REFERENCES principals (id, kind) ON DELETE CASCADE
);
-- 有効・無効は users の列ではなく、追記だけの出来事の表で持つ（下の user_enablement_events）
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
  id                 TEXT PRIMARY KEY,  -- 管理者が決める ID（grafana など）。不変で、行を消さないので再利用されない。形式は共有コアで検証する
  name               TEXT NOT NULL,     -- 表示名。変えられる
  client_type        TEXT NOT NULL CHECK (client_type IN ('confidential', 'public')),  -- RFC 6749 の client type
  secret_hash        TEXT,             -- SHA-256。confidential のときだけ持つ
  redirect_uris_json TEXT NOT NULL,    -- 完全一致で比較する URI の配列（ループバックはポート以外を比較）
  -- ID トークンの署名アルゴリズム。登録の仕様の省略時の既定（RS256）に頼らず、必ず明示して持つ。
  -- RS256 は RSA の署名鍵を設定したデプロイでだけ登録できる（tokens.md 参照）
  id_token_signed_response_alg TEXT NOT NULL CHECK (id_token_signed_response_alg IN ('Ed25519', 'RS256')),
  created_at         INTEGER NOT NULL,  -- UNIX 秒。clients_list の並び順に使う
  CHECK ((client_type = 'confidential') = (secret_hash IS NOT NULL))
);
-- グループは 0 人以上のユーザーの集合で、ネストしない（メンバーは users だけを参照する）。
-- 空のグループは誰にも許可を出さないので、安全側に倒れる
CREATE TABLE groups (
  id         TEXT PRIMARY KEY,         -- UUIDv4。名前を変えても grant と所属は ID でつながったまま
  kind       TEXT NOT NULL DEFAULT 'group' CHECK (kind = 'group'),
  name       TEXT NOT NULL UNIQUE,     -- 表示用の名前。変えられるので、管理操作では ID（group:<id>）で指定する。形式は共有コアの入力の検証で確かめる
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
  created_at   INTEGER NOT NULL,       -- UNIX 秒。grants_list の並び順に使う
  PRIMARY KEY (principal_id, client_id)
);

-- 有効・無効の出来事。ユーザー、client、グループのそれぞれで、今の状態の唯一の正とする。
-- 行は追記だけで、更新も削除もしない（末尾のトリガーで拒否する）。id は書き込んだ順で、最大の id の行が今の状態になる。
-- 行を削除しないので、INTEGER PRIMARY KEY の採番が過去の値に戻ることはない。
-- 作成の操作（user_create、client_create、group_create）は、同じバッチで最初の 'enabled' の行を書く。
-- 行が 1 つもない主体や client は、無効として扱う（fail-closed）。
-- 状態を変える行は、今の状態と違う値のときだけ、同じ文の条件（INSERT … SELECT … WHERE）で追記する。
-- 同じ値への変更は行を足さず、共有コアがエラーとして拒否する。
-- 理由の列は持たない（自由記述の個人情報を持たないため）。誰が変えたかは audit_log に同じバッチで書き、理由はどこにも記録しない
CREATE TABLE user_enablement_events (
  id          INTEGER PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id),
  enablement  TEXT NOT NULL CHECK (enablement IN ('enabled', 'disabled')),
  occurred_at INTEGER NOT NULL          -- UNIX 秒
);
CREATE TABLE client_enablement_events (
  id          INTEGER PRIMARY KEY,
  client_id   TEXT NOT NULL REFERENCES clients(id),
  enablement  TEXT NOT NULL CHECK (enablement IN ('enabled', 'disabled')),
  occurred_at INTEGER NOT NULL
);
CREATE TABLE group_enablement_events (
  id          INTEGER PRIMARY KEY,
  group_id    TEXT NOT NULL REFERENCES groups(id),
  enablement  TEXT NOT NULL CHECK (enablement IN ('enabled', 'disabled')),
  occurred_at INTEGER NOT NULL
);
-- 最新の行を主体ごとに引くので、(主体, id) の索引で走査を避ける
CREATE INDEX user_enablement_events_user_id     ON user_enablement_events (user_id, id);
CREATE INDEX client_enablement_events_client_id ON client_enablement_events (client_id, id);
CREATE INDEX group_enablement_events_group_id   ON group_enablement_events (group_id, id);

-- 今の状態。主体ごとに id が最大の行だけを返す。行のない主体はビューに現れない
CREATE VIEW user_enablement AS
SELECT e.user_id, e.enablement, e.occurred_at
FROM user_enablement_events e
WHERE e.id = (SELECT MAX(x.id) FROM user_enablement_events x WHERE x.user_id = e.user_id);
CREATE VIEW client_enablement AS
SELECT e.client_id, e.enablement, e.occurred_at
FROM client_enablement_events e
WHERE e.id = (SELECT MAX(x.id) FROM client_enablement_events x WHERE x.client_id = e.client_id);
CREATE VIEW group_enablement AS
SELECT e.group_id, e.enablement, e.occurred_at
FROM group_enablement_events e
WHERE e.id = (SELECT MAX(x.id) FROM group_enablement_events x WHERE x.group_id = e.group_id);

-- 使い捨ての値（すべて DELETE … RETURNING で消費する。トークンとコードはハッシュで保存する。
-- チャレンジはセレモニーが終わるまでサーバー側に一時保存し、タイムアウトの推奨上限と同程度（10 分）有効にする（WebAuthn §13.4.3）。
-- チャレンジは秘密ではないので、ハッシュにせずそのまま保存する。
-- 期限切れの行は、新しい値を発行するときの同じバッチで削除する）
CREATE TABLE enroll_tokens (token_hash TEXT PRIMARY KEY,
                            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                            expires_at INTEGER NOT NULL);  -- 発行から 10 分。1 回だけ使える
-- セッションの根拠はサインインに使ったパスキーなので、パスキーを失効させるとセッションも連鎖で消える。
-- 認可コードは発行したセッションに紐付け、セッションが消えれば未使用のコードも連鎖で消える（authentication.md 参照）
CREATE TABLE sessions      (token_hash TEXT PRIMARY KEY,
                            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                            credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,  -- サインインに使ったパスキー
                            auth_time INTEGER NOT NULL, expires_at INTEGER NOT NULL);  -- auth_time から 1 時間。延長しない
CREATE TABLE auth_codes    (code_hash TEXT PRIMARY KEY,
                            client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
                            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                            session_token_hash TEXT NOT NULL REFERENCES sessions(token_hash) ON DELETE CASCADE,  -- 発行の根拠になったセッション
                            redirect_uri TEXT NOT NULL, code_challenge TEXT NOT NULL, nonce TEXT, scope TEXT NOT NULL,
                            auth_time INTEGER NOT NULL, expires_at INTEGER NOT NULL);
-- サインインを挟む間だけ保持する、検証済みの認可リクエスト（15 分。チャレンジの 10 分より先に切れないようにする）。ID は __Host- Cookie でブラウザに渡す
CREATE TABLE authorize_requests (id_hash TEXT PRIMARY KEY,
                            client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
                            redirect_uri TEXT NOT NULL,
                            state TEXT, nonce TEXT, code_challenge TEXT NOT NULL, scope TEXT NOT NULL,
                            prompt_login INTEGER NOT NULL, max_age INTEGER, id_token_hint_sub TEXT,
                            locale TEXT NOT NULL,         -- /authorize で決めた UI の言語（BCP 47 の言語タグ。対応する言語のどれか。authentication.md 参照）
                            created_at INTEGER NOT NULL,  -- prompt=login の再認証は auth_time >= created_at で判定する
                            expires_at INTEGER NOT NULL);
-- チャレンジは用途ごとに発行元へ紐付ける。登録は登録トークン、サインインは認可リクエスト（Cookie）、
-- 本人による追加（直前の再認証と登録の両方）と失効はセッション。失効はさらに対象の credential ID にも紐付ける。
-- 用途ごとに持つ紐付けの列を CHECK で固定し、足りない列や余計な列を持つ行は作れない。
-- 紐付け先の行が消えれば、チャレンジも外部キーの連鎖で消える。そのため、チャレンジは紐付け先より先に消費する
-- （登録トークンや失効させるパスキーを先に消すと、チャレンジが連鎖で消えて消費に失敗する）。
-- サインインは discoverable credential を使うので、options の時点ではユーザーが分からず、user_id を持たない。
-- purpose は enroll（登録リンクによる登録）、sign_in（サインイン）、add_reauth（本人による追加の直前の再認証）、
-- add_register（本人による追加の登録）、revoke（本人による失効の直前の再認証）のどれか
CREATE TABLE challenges (
  challenge                 TEXT PRIMARY KEY,
  purpose                   TEXT NOT NULL CHECK (purpose IN ('enroll', 'sign_in', 'add_reauth', 'add_register', 'revoke')),
  user_id                   TEXT REFERENCES users(id) ON DELETE CASCADE,                           -- sign_in 以外で持つ
  enroll_token_hash         TEXT REFERENCES enroll_tokens(token_hash) ON DELETE CASCADE,          -- enroll だけが持つ
  authorize_request_id_hash TEXT REFERENCES authorize_requests(id_hash) ON DELETE CASCADE,        -- sign_in だけが持つ
  session_token_hash        TEXT REFERENCES sessions(token_hash) ON DELETE CASCADE,               -- add_reauth、add_register、revoke だけが持つ
  target_credential_id      TEXT REFERENCES credentials(id) ON DELETE CASCADE,                    -- revoke だけが持つ（失効させるパスキー）
  expires_at                INTEGER NOT NULL,
  CHECK ((user_id IS NULL) = (purpose = 'sign_in')),
  CHECK ((enroll_token_hash IS NOT NULL) = (purpose = 'enroll')),
  CHECK ((authorize_request_id_hash IS NOT NULL) = (purpose = 'sign_in')),
  CHECK ((session_token_hash IS NOT NULL) = (purpose IN ('add_reauth', 'add_register', 'revoke'))),
  CHECK ((target_credential_id IS NOT NULL) = (purpose = 'revoke'))
);

-- 管理 API の作成・追記の POST の Idempotency-Key（idpctl.md 参照）。24 時間だけ持ち、期限切れの行は
-- 新しいキーを書くときの同じバッチで削除する。行は操作と同じバッチで書くので、操作と保存した応答は一緒に確定する。
-- キーは管理者ごとの名前空間に置き、別の管理者の応答を再生させない。
-- 秘密を返す操作（client_create の confidential、client_rotate_secret、enroll_link_issue）の応答は保存せず、
-- replayable = 0 の行だけを書く。再生の要求には secret-not-replayable を返す
CREATE TABLE idempotency_keys (
  admin_name      TEXT NOT NULL,        -- 許可リストで確定した管理者の名前
  idempotency_key TEXT NOT NULL,
  operation       TEXT NOT NULL,        -- 共有コアの操作名（user_enable など）。OpenAPI の operationId ではない
  request_hash    TEXT NOT NULL,        -- 要求の本文の SHA-256（base64url、パディングなし）
  replayable      INTEGER NOT NULL CHECK (replayable IN (0, 1)),
  response_status INTEGER,              -- replayable = 1 のときだけ持つ
  response_json   TEXT,                 -- replayable = 1 のときだけ持つ。秘密を含めない
  expires_at      INTEGER NOT NULL,     -- 書いてから 24 時間
  PRIMARY KEY (admin_name, idempotency_key),
  CHECK ((replayable = 1) = (response_status IS NOT NULL)),
  CHECK ((replayable = 1) = (response_json IS NOT NULL))
);

-- 期限切れの行を消すバッチが、テーブル全体を走査しないようにする（D1 は走査した行数を読み取りとして数える）
CREATE INDEX enroll_tokens_expires_at      ON enroll_tokens (expires_at);
CREATE INDEX challenges_expires_at         ON challenges (expires_at);
CREATE INDEX sessions_expires_at           ON sessions (expires_at);
CREATE INDEX auth_codes_expires_at         ON auth_codes (expires_at);
CREATE INDEX authorize_requests_expires_at ON authorize_requests (expires_at);
CREATE INDEX idempotency_keys_expires_at   ON idempotency_keys (expires_at);

-- 管理 API の一覧（作成順のカーソルページング。idpctl.md 参照）も、読み飛ばす行を作らないようにする
CREATE INDEX users_created_at         ON users (created_at, id);
CREATE INDEX clients_created_at       ON clients (created_at, id);
CREATE INDEX groups_created_at        ON groups (created_at, id);
CREATE INDEX client_access_created_at ON client_access (created_at, principal_id, client_id);
-- グループに付いた grant と client ごとの grant を引く（effective_access と grants_list の絞り込み）
CREATE INDEX client_access_client_id  ON client_access (client_id);
CREATE INDEX group_members_group_id   ON group_members (group_id);

-- ユーザー単位のセッションの削除（session_revoke、user_disable）と、ユーザーのパスキーの数え上げ
-- （パスキーの上限、最後の 1 本の確認、user_get とアカウントページの一覧）も、テーブル全体を走査しないようにする（理由は上と同じ）
CREATE INDEX sessions_user_id    ON sessions (user_id);
CREATE INDEX credentials_user_id ON credentials (user_id);
-- 外部キーの連鎖（パスキーの失効 → セッション → 認可コードとチャレンジ、紐付け先 → チャレンジ）も、
-- テーブル全体を走査しないようにする
CREATE INDEX sessions_credential_id                ON sessions (credential_id);
CREATE INDEX auth_codes_session_token_hash         ON auth_codes (session_token_hash);
CREATE INDEX challenges_enroll_token_hash          ON challenges (enroll_token_hash);
CREATE INDEX challenges_authorize_request_id_hash  ON challenges (authorize_request_id_hash);
CREATE INDEX challenges_session_token_hash         ON challenges (session_token_hash);
CREATE INDEX challenges_target_credential_id       ON challenges (target_credential_id);

-- アクセス判定の唯一の定義
CREATE VIEW effective_access AS
-- ユーザー自身の principal に付いた grant と、所属するグループの principal に付いた grant の和集合。
-- 数えるのは、今の状態が 'enabled' のユーザーと client、グループ経由なら 'enabled' のグループだけ。
-- 出来事の行がない主体や client はビューに現れないので、内部結合で除かれる（fail-closed）
SELECT u.id AS user_id, a.client_id
FROM users u
JOIN user_enablement ue   ON ue.user_id = u.id AND ue.enablement = 'enabled'
JOIN client_access a      ON a.principal_id = u.id
JOIN client_enablement ce ON ce.client_id = a.client_id AND ce.enablement = 'enabled'
UNION
SELECT u.id AS user_id, a.client_id
FROM users u
JOIN user_enablement ue   ON ue.user_id = u.id AND ue.enablement = 'enabled'
JOIN group_members m      ON m.user_id = u.id
JOIN group_enablement ge  ON ge.group_id = m.group_id AND ge.enablement = 'enabled'
JOIN client_access a      ON a.principal_id = m.group_id
JOIN client_enablement ce ON ce.client_id = a.client_id AND ce.enablement = 'enabled';

-- 監査ログ（OWASP Logging Cheat Sheet の when / where / who / what）。管理操作は管理用の Worker が、
-- 本人のパスキー操作（登録リンクによる登録、本人による追加と失効）は IdP の Worker が書く
-- セッション ID、トークン、シークレット、登録トークンは、平文もハッシュも記録しない
CREATE TABLE audit_log (
  id             INTEGER PRIMARY KEY,     -- D1 が採番する。同じ秒の行も書き込んだ順に並ぶ
  occurred_at    INTEGER NOT NULL,        -- UNIX 秒（when）
  actor          TEXT NOT NULL CHECK (actor IN ('admin', 'user', 'break_glass')),  -- 操作者の種類（who）。admin は管理用の Worker が書く管理操作、user は IdP の Worker が書く本人の操作、break_glass は基盤の権限で手で書く行
  admin_name     TEXT,                    -- 管理者の名前。管理用の Worker が、許可リストでクライアント証明書のフィンガープリントから解決した値（自己申告ではない）
  admin_cert_sha256 TEXT,                 -- 操作に使ったクライアント証明書の SHA-256 フィンガープリント。同じ管理者の証明書のどれが使われたかを追える
  writer_version TEXT NOT NULL,           -- 書き込んだ Worker（IdP か管理用）のバージョン（where）
  operation      TEXT NOT NULL,           -- 操作名（user_create、passkey_add など。what）
  target         TEXT NOT NULL,           -- 'user:<id>' | 'client:<id>' | 'group:<id>' | 'schema' | 'none'（下記）
  result         TEXT NOT NULL CHECK (result IN ('success', 'failure')),
  detail_json    TEXT NOT NULL DEFAULT '{}',  -- 操作ごとの補足を JSON オブジェクトで持つ。値は ID、列挙値、数値、時刻だけで、名前と自由記述は入れない（下記）
  -- 管理操作の行は管理者の名前と証明書を必ず持ち、本人の操作と break-glass の行は持たない
  CHECK ((actor = 'admin' AND admin_name IS NOT NULL AND admin_cert_sha256 IS NOT NULL)
      OR (actor IN ('user', 'break_glass') AND admin_name IS NULL AND admin_cert_sha256 IS NULL)),
  CHECK (actor = 'admin' OR result = 'success')  -- IdP の Worker と break-glass は成功の行だけを書く（下記）
);
-- audit_tail は id の新しい順に読む（主キーの順なので索引は要らない）
CREATE INDEX audit_log_target      ON audit_log (target, id);       -- 対象で絞り込む
CREATE INDEX audit_log_operation   ON audit_log (operation, id);    -- 操作名で絞り込む
CREATE INDEX audit_log_occurred_at ON audit_log (occurred_at);      -- since と until で絞り込む

-- 追記だけの表と、削除しない表をトリガーで守る。共有コアの誤りや手で流した SQL でも、更新と削除は D1 が拒否する。
-- 緊急に行を消す必要があるときは、基盤の権限（break-glass）で先にトリガーを外す（idpctl.md 参照）
CREATE TRIGGER user_enablement_events_no_update BEFORE UPDATE ON user_enablement_events
BEGIN SELECT RAISE(ABORT, 'user_enablement_events is append-only'); END;
CREATE TRIGGER user_enablement_events_no_delete BEFORE DELETE ON user_enablement_events
BEGIN SELECT RAISE(ABORT, 'user_enablement_events is append-only'); END;
CREATE TRIGGER client_enablement_events_no_update BEFORE UPDATE ON client_enablement_events
BEGIN SELECT RAISE(ABORT, 'client_enablement_events is append-only'); END;
CREATE TRIGGER client_enablement_events_no_delete BEFORE DELETE ON client_enablement_events
BEGIN SELECT RAISE(ABORT, 'client_enablement_events is append-only'); END;
CREATE TRIGGER group_enablement_events_no_update BEFORE UPDATE ON group_enablement_events
BEGIN SELECT RAISE(ABORT, 'group_enablement_events is append-only'); END;
CREATE TRIGGER group_enablement_events_no_delete BEFORE DELETE ON group_enablement_events
BEGIN SELECT RAISE(ABORT, 'group_enablement_events is append-only'); END;
CREATE TRIGGER principals_no_delete BEFORE DELETE ON principals
BEGIN SELECT RAISE(ABORT, 'principals are never deleted'); END;
CREATE TRIGGER users_no_delete BEFORE DELETE ON users
BEGIN SELECT RAISE(ABORT, 'users are never deleted'); END;
CREATE TRIGGER clients_no_delete BEFORE DELETE ON clients
BEGIN SELECT RAISE(ABORT, 'clients are never deleted'); END;
CREATE TRIGGER groups_no_delete BEFORE DELETE ON groups
BEGIN SELECT RAISE(ABORT, 'groups are never deleted'); END;
```

マイグレーションは `contract/migrations/` に番号順に置き、各ファイルはこのドキュメントの SQL のブロックと、出てくる順に 1 対 1 で同じ内容にする（ずれはテストで検出する）。適用済みのマイグレーションは書き換えず、変更は次の番号のファイルとして足す。最初のブロックが `0001_init.sql`、2 つ目のブロックが `0002_audit_log_append_only.sql`、3 つ目のブロックが `0003_admin_request_nonces.sql` である。

`0002_audit_log_append_only.sql` は、監査ログを出来事の表と同じく追記だけの表にする。`0001` の時点では監査ログの更新と削除を拒否するトリガーがなく、「行は削除しない」が共有コアの規律だけに頼っていた。本人による失効の条件のように、監査ログの行があることを前提にする書き込みもあるので、D1 の側で強制する。`REPLACE`（`INSERT OR REPLACE` を含む）は衝突した行を消すときに DELETE のトリガーを起こさない（SQLite「The ON CONFLICT Clause」の REPLACE の説明。DELETE のトリガーは recursive triggers が有効なときだけ起こる）ので、既にある `id` を名指しする挿入も拒否する。共有コアは `id` を名指しせず、D1 の採番に任せる。

```sql
-- 監査ログは追記だけの表にする。更新と削除は、共有コアの誤りや手で流した SQL でも D1 が拒否する。
-- 本人による失効の条件など、監査ログの行があることに頼る書き込みがあるため、0001 の出来事の表と同じ形で守る。
-- REPLACE は衝突した行を消すときに DELETE のトリガーを起こさない（recursive_triggers が無効のため）ので、
-- 既にある id を名指しする INSERT も拒否する。共有コアは id を D1 の採番に任せ、名指ししない。
-- break-glass でも監査ログの行は消さない（idpctl.md 参照）
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER audit_log_no_replace BEFORE INSERT ON audit_log
WHEN NEW.id IS NOT NULL AND EXISTS (SELECT 1 FROM audit_log WHERE id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
```

`0003_admin_request_nonces.sql` は、管理者の RFC 9421 の署名の `nonce` を置く表を足す（[ホスティングのモード](hosting-modes.md)の 3.6）。管理用の Worker は、署名の検証と本文のダイジェストの確認がすべて通った要求の `nonce` だけを、管理操作の書き込みより前の別の文で挿入し、主キーの一意制約で 2 回目をリプレイとして拒否する。`expires_at` は `created` に 60 秒を足した UNIX 秒で、期限切れの行は挿入と同じバッチで消す（cron は置かない）。`expires_at` を過ぎた `nonce` を持つ要求は `created` の窓で必ず拒否されるので、行を消してもリプレイを通さない。管理者の名前は持たない（`nonce` はすべての管理者で一意であればよい）。この表は既存の表を参照も変更もしないので、管理用の Worker が使い始める前に適用しても、今の書き込みに影響しない。

```sql
-- 管理者の RFC 9421 の署名の nonce。署名の検証を通った要求の nonce だけを挿入し、主キーの一意制約で
-- 2 回目の要求をリプレイとして拒否する（hosting-modes.md 3.6）。管理者の名前は持たない。
-- expires_at は created に 60 秒を足した UNIX 秒。期限切れの行は挿入と同じバッチで消す
CREATE TABLE admin_request_nonces (
  nonce      TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
CREATE INDEX admin_request_nonces_expires_at ON admin_request_nonces (expires_at);
```

上の 16 テーブルのほかに監査ログ用のテーブル `audit_log` を 1 つ置き、管理操作と本人のパスキー操作を記録する。カラムは OWASP Logging Cheat Sheet の「いつ、どこで、誰が、何を」に対応させ、値の形は [実装に依存しない契約](cross-language-contract.md)で固定する。管理者は `idpctl` の `audit_tail` で、いつでも新しい順に読める。

- 管理操作の行の操作者は、管理用の Worker が許可リストで解決した管理者の名前で、操作する側の自己申告ではない（[管理 CLI と管理用の Worker](idpctl.md)参照）。上の SQL のコメントは前の設計（mTLS のクライアント証明書のフィンガープリント）のままで、マイグレーションと 1 対 1 なので書き換えない。署名に切り替えた後の `admin_cert_sha256` は、署名を検証した鍵の `keyid`（SPKI の DER の SHA-256）になり、種類を区別する `admin_credential` の列とトリガーは `0004` のマイグレーションで足す。署名の `nonce` を置く `admin_request_nonces` は `0003` で足した（上のブロック）。`0004` の SQL は、マイグレーションを足す PR でこの文書に書く（[ホスティングのモード](hosting-modes.md)の 3.6、3.9）。
- 記録するのは書き込みの操作で、読み取りの操作（`users_list`、`audit_tail` など）は記録しない。
- IdP の Worker が書くのは、本人のパスキー操作だけにする。登録リンクによる登録は `passkey_enroll`、本人による追加は `passkey_add`、本人による失効は `passkey_self_revoke` とし、`actor` は `user`、`target` は `user:<id>`、`detail_json` に credential ID を入れる。本人への通知の代わりに、認証器が増えたり減ったりしたことを管理者が監査ログで確認できるようにする（[認証フロー](authentication.md)参照）。
- 成功した操作は、操作と同じバッチで 1 行を書く。管理用の Worker は、失敗した操作も記録する。バッチが丸ごとロールバックされるので、その後に別の書き込みで `failure` の行を書く。失敗の行を書くのは、許可リストで管理者が確定した後の失敗だけにする。署名の検証や許可リストで拒否したリクエストは、監査ログではなく管理用の Worker のログに残す。
- IdP の Worker は `success` の行だけを書き、失敗や拒否は IdP の Worker のログに任せる。IdP の Worker のエンドポイントは認証前のリクエストからも呼べるので、失敗の行を書くと、誰でも D1 の 1 日の書き込み上限を監査ログの行で消費させられるため（[無料枠](free-tier.md)参照）。
- IdP の Worker の行は、`credentials` への書き込みと同じ条件を付けて、同じバッチに置く。登録と追加は、挿入と同じ条件（`user_enablement` でユーザーが `enabled`、パスキーの本数が[上限](cross-language-contract.md)未満）を付けた `INSERT … SELECT` で書く。本人による失効は、削除と同じ条件（対象がそのユーザーのパスキーで、2 本以上ある）を付けた `INSERT … SELECT` を削除の直前の文に置く。条件が成り立たず書き込みが起きなければ、監査ログの行も書かれない。拒否されたのに成功の行が残ることはない。
- `target` と `detail_json` には、ID、列挙値、数値、時刻と、個人情報を含まない設定値（redirect URI、署名アルゴリズム）だけを入れる。ユーザーの表示名、グループ名、client の表示名と、自由記述（理由など）は入れない。監査ログの行は削除しないので、ここに入った個人情報は、`user_rename` で表示名を中立にしても、break-glass で `users` の行を消しても残り続けるため（設計原則 7）。名前は、`target` の ID から今の行を引いて表示する。
- `detail_json` に入れてよいメンバーは、共有コアの監査ログの行の組み立てが持つ許可表で 1 か所に固定する。表はメンバーごとに値の形（UUIDv4、client ID、`user:<id>` か `group:<id>`、credential ID、列挙値、UNIX 秒、件数など）を持ち、組み立ては表にないメンバーや形の合わない値を、文を作る前に拒否する。名前は ID の形にも列挙値にも合わないので、ここで止まる。新たな操作がメンバーを足すときは、この表に形の判定と一緒に足す。新たに使えるようになった組（`newly_enabled`）と消したセッションの数（`sessions_deleted`）は、書き込みと同じバッチの SQL で数えて、同じ文の中で `detail_json` に入れる。値は ID の列と件数だけから作るので、名前が入らない。
- 失敗の行の `detail_json` は、問題の種類（`problem`。[管理 CLI と管理用の Worker](idpctl.md)の `kind`）だけを持つ。拒否された入力の値は入れない。ID の欄に打ち間違えた名前が、そのまま残らないようにするため。
- 対象が 2 つある操作は、`grant_add` などでは client を、`group_member_add` などではグループを `target` に入れ、もう一方（`user:<id>` や `group:<id>`）を `detail_json` に入れる。
- 権限を広げる操作（`grant_add`、`group_member_add`）は、新たに使えるようになったユーザーと client の組（どちらも ID）を `detail_json` に残す。
- 有効化と無効化（`user_enable`、`user_disable`、`client_enable`、`client_disable`、`group_enable`、`group_disable`）は、出来事の行と同じバッチで監査ログに 1 行を書く。理由は受け取らず、記録しない。状態の正は出来事の表で、アクセスの判定は監査ログを読まない。
- 名前の変更（`user_rename`、`group_rename`、`client_rename`）は、変更したことだけを残し、変更前と変更後の名前は残さない。
- 失敗の行の `target` は、入力の検証を通った対象の ID にする。存在しない ID を指定した失敗（`not-found`）も、検証を通った ID をそのまま入れる。ID がまだ採番されていない作成の失敗や、ID の形式が不正な失敗は `none` にし、形式が不正な値そのものは書かない。
- break-glass で手で書く行（[管理 CLI と管理用の Worker](idpctl.md)の break-glass を参照）は、`actor` を `break_glass`、`result` を `success` とし、管理者の列を持たない。基盤の権限の API トークンでは管理者を確かめられないので、名前や証明書を自己申告で書かない。トリガーの付け外しの行は `target` を `schema` にし、外したトリガーの名前を `detail_json` に入れる。
- OWASP の「記録から除くデータ」に従い、セッション ID、トークン、シークレット、登録トークンは書かない。`detail_json` にも入れず、登録リンクの発行では有効期限だけを残す。
- 行は更新も削除もしない（`0002_audit_log_append_only.sql` のトリガーで拒否する）。家族規模の件数なら、無料枠の DB サイズ（500 MB）に対して十分小さい。

サインインは監査ログに書かず、IdP の Worker のログに任せる（サインイン自体はチャレンジ、セッション、sign count を D1 に書く）。パスキーで署名を検証するセレモニー（サインインと、本人による追加と失効の直前の再認証）は、どれも検証に成功したときに `sign_count` と `last_used_at` を同じバッチで更新し、sign count の後退の検知（[標準準拠](standards-compliance.md)参照）も同じ規則で行う。期限切れの行は発行時に片付けるので、Cron は使わない。有効かどうかは取り出すときに必ず `expires_at` で判定するので、片付けが遅れても安全性は変わらない（容量にだけ影響する）。

**有効・無効と削除しない行**

- ユーザー、client、グループの今の有効・無効は、それぞれの出来事の表（`user_enablement_events` など）の最新の行だけで決まる。`users` などの列にも、監査ログにも持たない。状態の正を 1 つにし、表どうしの食い違いを構造的に起こさないため（[唯一の事実源](../philosophy/system-design/single-source-of-truth.md)）。
- 作成の操作は、同じバッチで最初の `enabled` の行を書く。行が 1 つもない主体や client は、`effective_access` にも、ほかの「有効か」の確認にも通らない（設計原則 4）。
- 無効化と有効化は、今の状態と違う値のときだけ行を足す。条件は追記と同じ文（`INSERT … SELECT … WHERE`）に置き、確認と追記の間に別の変更が入っても、同じ値の行が 2 つ続くことはない。同じ値への変更は行を足さず、共有コアがエラー（`state-conflict`。[管理 CLI と管理用の Worker](idpctl.md)参照）として拒否し、成功の監査ログの行も書かない。監査ログの行は、同じ条件を付けた `INSERT … SELECT` を追記の直前の文に置き、追記が起きたときだけ残す（本人による失効と同じ形）。
- 出来事の表の更新と削除、`principals`、`users`、`clients`、`groups` の削除は、トリガーで常に拒否する。ユーザーや RP を終わらせるのは無効化で、行は残す。そのため client ID は主キーとして二度と使われず、再利用による取り違え（古い grant や監査ログの行が新しい RP を指すこと）が起きない。
- 削除するのは、関係の行（所属は `group_member_remove`、grant は `grant_remove`）と、使い捨ての短命の行（セッション、認可コード、チャレンジ、登録トークン、`authorize_requests`、`idempotency_keys`）だけである。ユーザーの無効化でも、そのユーザーのセッションは削除する。
- 無効化したユーザーの行は、表示名とパスキーの公開鍵を持ったまま残る。設計原則 7（必要な分しか持たない）との関係では、残すのは本人を指す最小限の値で、表示名は `user_rename` で中立な値に変えられる。パスキーの公開鍵は秘密ではないが、本人の認証器を指すので、不要なら管理者が `passkey_revoke` で最後の 1 本を除いて消せる。
- 緊急に行を消す必要があるとき（誤って個人情報を表示名に入れたなど）は、基盤の権限の break-glass で、先にトリガーを外してから消し、終わったらトリガーを戻す。出来事の表は ON DELETE なしで参照し、自分の削除を拒否するトリガーも持つので、出来事の表のトリガーも外して出来事の行を先に消す。外すトリガーと消す順番は[管理 CLI と管理用の Worker](idpctl.md)の break-glass にまとめる。共有コアにはこの経路を置かない。監査ログは名前を持たないので、この作業で監査ログの行を消す必要はない。
- D1 がトリガー（`CREATE TRIGGER` と `RAISE(ABORT, …)`）をマイグレーションで受け付け、実行時に効くことは、実装の前に確かめる（[未決事項](open-questions.md)参照）。D1 のドキュメントは SQLite のクエリエンジンを使うとだけ書き、トリガーの可否を明記していない（Cloudflare「SQL statements」）。外部キーは D1 で常に有効で、SQLite の `PRAGMA foreign_keys = on` と同じに働く（Cloudflare「Define foreign keys」）。
