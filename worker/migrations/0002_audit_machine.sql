-- N7：audit 加 machine_id（CLI 送上嚟嘅 16-hex 機械指紋；唔存硬件原值）
ALTER TABLE audit ADD COLUMN machine_id TEXT;
CREATE INDEX IF NOT EXISTS idx_audit_machine ON audit (machine_id, id);
