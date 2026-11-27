-- 0004_nonce.sql — 重放保護改用 D1（唯一鍵），KV 只做後備
-- 原因：KV 同 key 每秒限一寫；突發 claim 會令 nonce 寫入被 429 → 變成 503 fail-closed，
-- 攻擊者可以藉此拖低可用性（雖然唔會洩密）。D1 唯一鍵跨 isolate 一致，適合做 replay 判定。
CREATE TABLE IF NOT EXISTS nonce (
  agent TEXT NOT NULL,
  nonce TEXT NOT NULL,
  ts    INTEGER NOT NULL,
  PRIMARY KEY (agent, nonce)
);
CREATE INDEX IF NOT EXISTS idx_nonce_ts ON nonce (ts);
