-- 0003_rate_limit.sql — 限流權威計數（跨 isolate 一致）
-- 背景：KV 同一個 key 每秒只可寫一次，突發請求會撞上限；Worker 之前降級用 isolate 內存，
-- 但 Cloudflare 可以為每個請求開新 isolate，內存計數唔共享 → 限流形同虛設。
-- 改用 D1（單一寫入點）做權威計數，KV 只做快速路徑。
CREATE TABLE IF NOT EXISTS rate_limit (
  scope   TEXT NOT NULL,
  subject TEXT NOT NULL,
  window  INTEGER NOT NULL,
  used    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (scope, subject, window)
);
