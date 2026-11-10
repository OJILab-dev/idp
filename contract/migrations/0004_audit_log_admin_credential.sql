-- 管理操作の行の資格情報の種類。admin_cert_sha256 の意味はこの値で決まり、signing-key では署名を検証した鍵の
-- keyid（SPKI の DER の SHA-256）になる（hosting-modes.md 3.9）。CHECK を変えるには表の作り直しが要るので、
-- 列は ADD COLUMN で足し、規則は挿入のトリガーで強制する。管理者の認証は署名だけなので、admin の行は
-- signing-key だけを持ち、certificate は拒否する。user と break_glass の行は持たない。
-- 0004 より前の行は admin_credential を持たず、admin の行はすべて証明書の行である。更新は 0002 のトリガーが拒否する
ALTER TABLE audit_log ADD COLUMN admin_credential TEXT;
CREATE TRIGGER audit_log_admin_credential BEFORE INSERT ON audit_log
WHEN (NEW.actor = 'admin' AND (NEW.admin_credential IS NULL OR NEW.admin_credential <> 'signing-key'))
  OR (NEW.actor <> 'admin' AND NEW.admin_credential IS NOT NULL)
BEGIN SELECT RAISE(ABORT, 'audit_log.admin_credential does not match the actor'); END;
