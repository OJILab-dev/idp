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
