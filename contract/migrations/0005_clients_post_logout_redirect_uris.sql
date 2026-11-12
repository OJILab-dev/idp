-- RP-Initiated Logout 1.0 §3.1 の post_logout_redirect_uris。完全一致で比べる https の URI の JSON の配列で、
-- 形は redirect_uris_json と同じく共有コアが書き込みのときに検証する。今の Worker の挿入はこの列を名指ししないので
-- 既定の空の配列（ログアウト後のリダイレクトなし）で入り、適用の前後どちらの Worker でも同じに動く
ALTER TABLE clients ADD COLUMN post_logout_redirect_uris_json TEXT NOT NULL DEFAULT '[]';
