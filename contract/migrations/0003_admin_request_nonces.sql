-- 管理者の RFC 9421 の署名の nonce。署名の検証を通った要求の nonce だけを挿入し、主キーの一意制約で
-- 2 回目の要求をリプレイとして拒否する（hosting-modes.md 3.6）。管理者の名前は持たない。
-- expires_at は created に 60 秒を足した UNIX 秒。期限切れの行は挿入と同じバッチで消す
CREATE TABLE admin_request_nonces (
  nonce      TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
CREATE INDEX admin_request_nonces_expires_at ON admin_request_nonces (expires_at);
