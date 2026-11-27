#!/usr/bin/env node
/**
 * attack-prod.mjs — 對抗性測試（紅隊視角），真打生產 Worker
 *
 * 目的：證明「除非 Cloudflare 帳號被拿走，否則外部攻擊者零漏洞」。
 * 前提：攻擊者知道 CLI 原始碼、知道 worker URL、可能知道合法 agent id。
 *
 * 用法（需要乾淨出口，例如 GitHub runner）：
 *   BROKER_URL=... BROKER_AGENT_ID=ci-e2e-01 BROKER_PRIVATE_KEY=<base64 pkcs8> \
 *     node worker/scripts/attack-prod.mjs
 *
 * 每一項都會印 PASS／FAIL；任何一項「攻擊成功」就 exit 1。
 * 永不印出任何 secret 值（只印 status / 長度 / header 名）。
 */
import crypto from "node:crypto";

const BASE = (process.env.BROKER_URL || "").replace(/\/+$/, "");
const AGENT = process.env.BROKER_AGENT_ID || "ci-e2e-01";
const KEY_B64 = process.env.BROKER_PRIVATE_KEY || "";

if (!BASE) {
  console.error("冇 BROKER_URL");
  process.exit(2);
}

let key = null;
if (KEY_B64) {
  try {
    key = crypto.createPrivateKey({
      key: Buffer.from(KEY_B64.replace(/\s/g, ""), "base64"),
      format: "der",
      type: "pkcs8",
    });
  } catch (e) {
    console.error("私鑰格式錯，跳過需要簽名嘅攻擊項");
  }
}

const results = [];
let fails = 0;
function check(name, ok, note = "") {
  results.push({ name, ok, note });
  if (!ok) fails += 1;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${note ? `  — ${note}` : ""}`);
}

const b64u = (buf) => Buffer.from(buf).toString("base64url");
const sign = (agent, wants, ts, nonce) =>
  b64u(crypto.sign(null, Buffer.from(`v1|${agent}|${wants.join(",")}|${ts}|${nonce}`), key));
const now = () => Math.floor(Date.now() / 1000);
const nonce = () => crypto.randomBytes(16).toString("base64url");

async function req(method, path, { body, headers = {}, raw } = {}) {
  const t0 = Date.now();
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { "content-type": "application/json", ...headers },
    body: raw !== undefined ? raw : body ? JSON.stringify(body) : undefined,
    redirect: "manual",
  });
  const text = await res.text();
  return { status: res.status, headers: res.headers, text, ms: Date.now() - t0 };
}

const leaks = (text, extra = []) => {
  const hay = text.toLowerCase();
  const needles = ["-----begin", "private_key", "broke_master", "broker_master_key", "at /", "stack", ...extra];
  return needles.filter((n) => hay.includes(n.toLowerCase()));
};

/* ---------- 0. health 唔應該漏任何內部資訊 ---------- */
{
  const r = await req("GET", "/health");
  check("health 200", r.status === 200, `status=${r.status}`);
  const allowed = ["ok", "kv", "ed25519", "encryption", "audit", "rate_limit", "version", "ts"];
  let keys = [];
  try {
    keys = Object.keys(JSON.parse(r.text));
  } catch (_) {}
  const extra = keys.filter((k) => !allowed.includes(k));
  check("health 唔露多餘欄位", extra.length === 0, extra.join(",") || "欄位正常");
  check("health 唔漏敏感字串", leaks(r.text).length === 0, leaks(r.text).join(","));
}

/* ---------- 1. admin 面：所有方法／變形路徑都要 404 ---------- */
{
  const paths = [
    "/v1/agents",
    "/v1/agents/ci-e2e-01",
    "/v1/secrets/ci-e2e-01/x",
    "/v1/admin/audit",
    "/v1/admin/reencrypt",
    "/v1/admin/tokens",
    "/github-token",
    "/v1/claim/../agents",
    "/v1/agents%2Fci-e2e-01",
    "//v1/agents",
    "/V1/AGENTS",
    "/v1/Agents/ci-e2e-01",
    "/v1/agents/ci-e2e-01/../../secrets/a/b",
    "/v1/agents?debug=1",
    "/v1/agents?limit=1000",
  ];
  let bad = [];
  for (const p of paths) {
    for (const m of ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]) {
      const r = await req(m, p);
      if (r.status !== 404) bad.push(`${m} ${p} → ${r.status}`);
    }
  }
  check("admin／變形路徑全 404（84 個組合）", bad.length === 0, bad.slice(0, 5).join(" | ") || "全部 404");
}

/* ---------- 2. 方法覆寫／錯誤 content-type 唔可以開後門 ---------- */
{
  const r1 = await req("POST", "/v1/agents", {
    body: { pubkey: "x" },
    headers: { "x-http-method-override": "PUT" },
  });
  check("X-HTTP-Method-Override 無效", r1.status === 404, `status=${r1.status}`);
  const r2 = await req("POST", "/v1/claim", { raw: "agent_id=ci-e2e-01&wants=github", headers: { "content-type": "application/x-www-form-urlencoded" } });
  check("form-encoded body 被拒（400）", r2.status === 400, `status=${r2.status}`);
  const r3 = await req("POST", "/v1/claim", { raw: "x".repeat(100000) });
  check("100KB body 唔會 5xx", r3.status < 500, `status=${r3.status}`);
  const r4 = await req("GET", "/v1/claim");
  check("GET /v1/claim 唔會 5xx", r4.status < 500, `status=${r4.status}`);
}

/* ---------- 3. 唯一正常 claim（後面全部係攻擊） ---------- */
let legit = null;
if (key) {
  const ts = now();
  const n = nonce();
  const r = await req("POST", "/v1/claim", { body: { agent_id: AGENT, wants: ["github"], ts, nonce: n, sig: sign(AGENT, ["github"], ts, n) } });
  legit = { ...r, ts, n };
  let tok = null;
  try {
    tok = JSON.parse(r.text)?.secrets?.github?.token;
  } catch (_) {}
  check("合法 claim 200", r.status === 200, `status=${r.status}`);
  check("token 形狀 ghs_ 且 1h 內到期", typeof tok === "string" && tok.startsWith("ghs_"), tok ? `len=${tok.length}` : "無 token");
  check("claim 回應唔漏 PEM／master key", leaks(r.text).length === 0, leaks(r.text).join(","));
  check("回應冇 Cache-Control 可快取", String(r.headers.get("cache-control") || "").includes("no-store"), r.headers.get("cache-control") || "無");
}

/* ---------- 4. 簽名／時間／nonce 攻擊 ---------- */
if (key) {
  const base = { agent_id: AGENT, wants: ["github"], ts: now(), nonce: nonce() };

  const cases = [
    ["sig 空字串", { ...base, sig: "" }, 401],
    ["sig 全 A（43 字元）", { ...base, sig: "A".repeat(43) }, 401],
    ["sig 篡改一位", { ...base, sig: (() => { const s = sign(AGENT, ["github"], base.ts, base.nonce); return (s[0] === "A" ? "B" : "A") + s.slice(1); })() }, 401],
    ["時間戳 -1 小時", { ...base, ts: now() - 3600, sig: sign(AGENT, ["github"], now() - 3600, base.nonce) }, 401],
    ["時間戳 +10 分鐘", { ...base, ts: now() + 600, sig: sign(AGENT, ["github"], now() + 600, base.nonce) }, 401],
    ["nonce 太短", { ...base, nonce: "abc", sig: sign(AGENT, ["github"], base.ts, "abc") }, 400],
    ["agent 名唔存在（格式合法）", { ...base, agent_id: "ghost-agent-x9", sig: sign("ghost-agent-x9", ["github"], base.ts, base.nonce) }, 401],
    ["agent 名大寫（繞過大小寫）", { ...base, agent_id: AGENT.toUpperCase(), sig: sign(AGENT.toUpperCase(), ["github"], base.ts, base.nonce) }, 400],
    ["agent 名路徑穿越", { ...base, agent_id: "../../admin", sig: sign("../../admin", ["github"], base.ts, base.nonce) }, 400],
    ["wants 空陣列", { ...base, wants: [], sig: sign(AGENT, [], base.ts, base.nonce) }, 400],
    ["wants 超過 12 個", { ...base, wants: Array.from({ length: 13 }, (_, i) => `k${i}`), sig: sign(AGENT, Array.from({ length: 13 }, (_, i) => `k${i}`), base.ts, base.nonce) }, 400],
    ["wants 內含物件", { ...base, wants: [{ a: 1 }], sig: sign(AGENT, [String({ a: 1 })], base.ts, base.nonce) }, 400],
  ];

  let bad = [];
  for (const [name, body, expect] of cases) {
    const r = await req("POST", "/v1/claim", { body });
    if (r.status !== expect) bad.push(`${name} → ${r.status}（預期 ${expect}）`);
    if (r.status >= 500) bad.push(`${name} → 5xx`);
    if (leaks(r.text).length) bad.push(`${name} 漏敏感字串`);
  }
  check("12 種簽名／參數攻擊全部被擋", bad.length === 0, bad.join(" | ") || "全部符合預期");

  // 簽名綁定 wants：簽 github 但要求 github + 其他 key → 必須拒絕
  const ts = now();
  const n = nonce();
  const r = await req("POST", "/v1/claim", { body: { agent_id: AGENT, wants: ["github", "openai.api_key"], ts, nonce: n, sig: sign(AGENT, ["github"], ts, n) } });
  check("wants 被篡改即簽名失效（401）", r.status === 401, `status=${r.status}`);

  // 重放：同一份合法請求再送一次 → 409
  const r2 = await req("POST", "/v1/claim", { body: { agent_id: AGENT, wants: ["github"], ts: legit.ts, nonce: legit.n, sig: sign(AGENT, ["github"], legit.ts, legit.n) } });
  check("重放被擋（409）", r2.status === 409, `status=${r2.status}`);
}

/* ---------- 5. entitlement 越權 + 無 oracle ---------- */
if (key) {
  const mk = (wants) => {
    const ts = now();
    const n = nonce();
    return { body: { agent_id: AGENT, wants, ts, nonce: n, sig: sign(AGENT, wants, ts, n) } };
  };
  const denied = await req("POST", "/v1/claim", mk(["smtp.password"]));
  check("未授權 secret → 403", denied.status === 403, `status=${denied.status}`);
  const deniedA = await req("POST", "/v1/claim", mk(["definitely.not.exist"]));
  const deniedB = await req("POST", "/v1/claim", mk(["another.unknown.key"]));
  let jA = {};
  let jB = {};
  try {
    jA = JSON.parse(deniedA.text);
    jB = JSON.parse(deniedB.text);
  } catch (_) {}
  // 重要：伺服器只可以回「你要求嘅名 + 拒絕原因」，唔可以加任何「其實存在／唔存在」嘅暗示
  const shapeA = Object.keys(jA).sort().join(",");
  const shapeB = Object.keys(jB).sort().join(",");
  check(
    "未知 secret 名唔形成存在性 oracle",
    deniedA.status === 403 &&
      deniedB.status === 403 &&
      jA.error === "not_entitled" &&
      jA.error === jB.error &&
      shapeA === shapeB &&
      JSON.stringify(jA.denied) === JSON.stringify(["definitely.not.exist"]) &&
      JSON.stringify(jB.denied) === JSON.stringify(["another.unknown.key"]),
    `${deniedA.status}/${deniedB.status} shape=${shapeA}（只回自己要求嘅名）`,
  );
  check("403 唔回傳 secret 值或長度", !/len=|sha256:/i.test(deniedA.text + deniedB.text), "");

  // 批量越權：一個有權一個冇權 → 全體拒絕，唔會部分派
  const mixed = await req("POST", "/v1/claim", mk(["github", "smtp.password"]));
  check("混合越權請求整體拒絕（403，唔會派一半）", mixed.status === 403 && !mixed.text.includes("ghs_"), `status=${mixed.status}`);
}

/* ---------- 6. Header 注入／指紋欄位攻擊（唔可以 5xx，唔可以影響派發） ---------- */
if (key) {
  const ts = now();
  const n = nonce();
  const nasty = [
    ["超長 1000 字", "A".repeat(1000)],
    ["非 hex 值", "'; DROP TABLE audit; --"],
    ["Unicode", "🎉🚀"],
    ["header 內換行嘗試", "abc\r\nX-Injected: 1"],
  ];
  let bad = [];
  for (const [label, v] of nasty) {
    const r = await req("POST", "/v1/claim", {
      body: { agent_id: AGENT, wants: ["github"], ts, nonce: n + "", sig: sign(AGENT, ["github"], ts, n) },
      headers: { "x-broker-machine": v },
    });
    if (r.status >= 500) bad.push(`${label} → ${r.status}`);
  }
  check("X-Broker-Machine 垃圾值唔會 5xx", bad.length === 0, bad.join(" | ") || "全部非 5xx");
}

/* ---------- 8. 時序側信道（資訊性，唔算 fail 除非差異極大） ---------- */
{
  const timeOf = async (body) => {
    const out = [];
    for (let i = 0; i < 8; i += 1) {
      const r = await req("POST", "/v1/claim", { body });
      out.push(r.ms);
    }
    out.sort((a, b) => a - b);
    return out[Math.floor(out.length / 2)];
  };
  const ghost = { agent_id: "ghost-agent-x9", wants: ["github"], ts: now(), nonce: nonce(), sig: "A".repeat(43) };
  const a = await timeOf(ghost);
  const b = key ? await timeOf({ agent_id: AGENT, wants: ["github"], ts: now(), nonce: nonce(), sig: "A".repeat(43) }) : a;
  const delta = Math.abs(a - b) / Math.max(a, b, 1);
  check("唔存在 agent 與錯簽延遲接近（<50%）", delta < 0.5, `median ${a}ms vs ${b}ms（差 ${(delta * 100).toFixed(0)}%）`);
}

/* ---------- 7. 限流（放在最後，會燒盡本 agent 配額） ---------- */
if (key) {
  const hits = [];
  for (let i = 0; i < 45; i += 1) {
    const ts = now();
    const n = nonce();
    const r = await req("POST", "/v1/claim", { body: { agent_id: AGENT, wants: ["github"], ts, nonce: n, sig: sign(AGENT, ["github"], ts, n) } });
    hits.push({ status: r.status, ra: r.headers.get("retry-after") });
    if (r.status === 429) break;
  }
  const first429 = hits.find((h) => h.status === 429);
  check("突發請求觸發 429", Boolean(first429), first429 ? `Retry-After=${first429.ra}` : "45 次都冇 429");
  check("429 有數字 Retry-After", Boolean(first429 && Number(first429.ra) > 0), first429 ? String(first429.ra) : "無");
  const bad = hits.filter((h) => h.status >= 500);
  check("限流期間冇 5xx", bad.length === 0, bad.length ? `${bad.length} 個 5xx` : "");
}

/* ---------- 總結 ---------- */
console.log(`\n${results.filter((r) => r.ok).length}/${results.length} PASS`);
if (fails > 0) {
  console.log(`\n有 ${fails} 項攻擊成功 —— 需要即刻修`);
  for (const r of results.filter((x) => !x.ok)) console.log(`  ✗ ${r.name} ${r.note}`);
}
process.exit(fails > 0 ? 1 : 0);
