-- N4：audit log 落 D1（每行一次 claim / 一次 admin 寫操作）
CREATE TABLE IF NOT EXISTS audit (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          TEXT    NOT NULL,   -- ISO8601 UTC
  kind        TEXT    NOT NULL,   -- claim | admin
  agent_id    TEXT,               -- claim 的 agent；admin 操作目標放 details
  actor       TEXT,               -- admin:current | admin:prev | agent
  action      TEXT,               -- agent_put / secret_put / reencrypt / auth_failed …
  wants       TEXT,               -- JSON 陣列（claim）
  result      TEXT,               -- ok / failed / partial / not_entitled / replay / rate_limited …
  status      INTEGER,            -- HTTP status
  ip_hash     TEXT,               -- SHA-256(IP) 前 16 hex，唔存原文
  ua          TEXT,
  latency_ms  INTEGER,
  details     TEXT                -- JSON（delivered 清單等，唔可以含 secret 值）
);
CREATE INDEX IF NOT EXISTS idx_audit_ts   ON audit (ts);
CREATE INDEX IF NOT EXISTS idx_audit_kind ON audit (kind, id);
