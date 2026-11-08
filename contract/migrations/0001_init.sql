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
