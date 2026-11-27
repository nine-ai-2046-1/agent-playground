#!/usr/bin/env node
/**
 * contract-test.mjs — Secret Broker 契約測試（自帶 mock KV，唔需要 wrangler、唔需要網絡）
 *
 * 用法：node worker/scripts/contract-test.mjs
 * 要求：Node >= 20（用 crypto.subtle 同 Ed25519）
 *
 * 覆蓋：health、admin 認證、claim 驗簽（未知 agent／錯簽／ts 過期／重放／無 entitlement）、
 *       靜態 secret、撤銷、no-store 標頭、舊 /github-token 默認下架。
 * 退出碼：0 全部 PASS；1 有 FAIL。
 */

import crypto from "node:crypto";
import worker from "../src/index.js";

const ADMIN = "test-admin-token";
const AGENT = "ct-agent";
const OTHER = "ct-other";

/** 最小 KV 模擬（get/put/delete/list），行為貼近 Cloudflare KV 的 JSON/text 讀取 */
function makeKV() {
  const store = new Map();
  return {
    async get(key, type) {
      if (!store.has(key)) return null;
      const value = store.get(key);
      return type === "json" ? JSON.parse(value) : value;
    },
    async put(key, value) {
      store.set(key, value);
    },
    async delete(key) {
      store.delete(key);
    },
    async list({ prefix = "" } = {}) {
      return { keys: [...store.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name })) };
    },
    _raw: store,
  };
}

/** 最小 D1 模擬：只覆蓋 audit INSERT 同 audit SELECT */
function makeD1() {
  const rows = [];
  return {
    prepare(sql) {
      const stmt = {
        params: [],
        bind(...args) {
          this.params = args;
          return this;
        },
        async run() {
          if (sql.includes("INSERT INTO audit")) {
            const [ts, kind, agent_id, actor, action, wants, result, status, ip_hash, ua, latency_ms, details] =
              this.params;
            rows.push({ ts, kind, agent_id, actor, action, wants, result, status, ip_hash, ua, latency_ms, details });
          }
          return { success: true };
        },
        async all() {
          const limit = this.params[this.params.length - 1];
          const kind = sql.includes("WHERE kind = ?") ? this.params[0] : null;
          const out = rows.filter((r) => !kind || r.kind === kind).slice().reverse().slice(0, limit);
          return { results: out };
        },
      };
      return stmt;
    },
    _rows: rows,
  };
}

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function keypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const rawPub = publicKey.export({ format: "der", type: "spki" }).subarray(-32); // Ed25519 SPKI 尾 32 bytes = raw
  return { rawPub: b64url(rawPub), privateKey };
}

function sign(privateKey, agentId, wants, ts, nonce) {
  const canonical = `v1|${agentId}|${wants.join(",")}|${ts}|${nonce}`;
  return b64url(crypto.sign(null, Buffer.from(canonical), privateKey));
}

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? `  — ${detail}` : ""}`);
}

async function main() {
  const kv = makeKV();
  const d1 = makeD1();
  const pending = [];
  const ctx = { waitUntil: (p) => pending.push(Promise.resolve(p).catch(() => {})) };
  // N3：測試用 master key（32 bytes → base64url）
  const MASTER = Buffer.from("0123456789abcdef0123456789abcdef").toString("base64url");
  const env = {
    BROKER_KV: kv,
    AGENT_TOKEN: ADMIN,
    BROKER_MASTER_KEY: MASTER,
    AUDIT_DB: d1,
    AGENT_TOKEN_PREV: "test-admin-token-prev",
    GITHUB_APP_ID: "123",
    GITHUB_APP_PEM_BASE64: "unused-in-contract-test",
  };

  const A = keypair();
  const B = keypair();

  const call = async (path, init = {}) => {
    const res = await worker.fetch(new Request(`https://broker.test${path}`, init), env, ctx);
    return res;
  };
  const jsonCall = (path, method, body, token) =>
    call(path, {
      method,
      headers: {
        "content-type": "application/json",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });

  /* 1. health */
  const health = await call("/health");
  const healthBody = await health.json();
  check(
    "health 公開、無 auth、no-store",
    health.status === 200 && healthBody.ok === true && health.headers.get("cache-control") === "no-store",
    `status=${health.status} cache=${health.headers.get("cache-control")}`,
  );

  /* 2. 管理 API 無 token */
  const noTok = await call("/v1/agents");
  check(
    "管理 API 無 token → 401 + no-store",
    noTok.status === 401 && noTok.headers.get("cache-control") === "no-store",
    `status=${noTok.status} cache=${noTok.headers.get("cache-control")}`,
  );

  /* 3. 註冊兩個 agent（用 admin） */
  const putA = await jsonCall(`/v1/agents/${AGENT}`, "PUT",
    { pubkey: A.rawPub, entitlements: ["static.key", "github"], github: { installation_id: 1, repositories: ["r1"] } }, ADMIN);
  const putB = await jsonCall(`/v1/agents/${OTHER}`, "PUT",
    { pubkey: B.rawPub, entitlements: ["other.key"] }, ADMIN);
  check("admin 可註冊 agent", putA.status === 201 && putB.status === 201, `A=${putA.status} B=${putB.status}`);

  /* 4. 存一個靜態 secret */
  const putSec = await jsonCall(`/v1/secrets/${AGENT}/static.key`, "PUT", { value: "s3cr3t-value" }, ADMIN);
  check("admin 可存靜態 secret", putSec.status === 201, `status=${putSec.status}`);

  /* 5. 未知 agent → 401 plain */
  const ts0 = Math.floor(Date.now() / 1000);
  const ghost = JSON.stringify({
    agent_id: "no-such-agent", wants: ["static.key"], ts: ts0, nonce: "nonce00000001",
    sig: sign(A.privateKey, "no-such-agent", ["static.key"], ts0, "nonce00000001"),
  });
  const ghostRes = await call("/v1/claim", { method: "POST", headers: { "content-type": "application/json" }, body: ghost });
  check("未知 agent → 401（唔講原因）+ no-store",
    ghostRes.status === 401 && (await ghostRes.text()) === "Unauthorized" && ghostRes.headers.get("cache-control") === "no-store",
    `status=${ghostRes.status}`);

  /* 6. ts 過期 → 401 JSON */
  const staleTs = ts0 - 120;
  const stale = JSON.stringify({
    agent_id: AGENT, wants: ["static.key"], ts: staleTs, nonce: "nonce00000002",
    sig: sign(A.privateKey, AGENT, ["static.key"], staleTs, "nonce00000002"),
  });
  const staleRes = await call("/v1/claim", { method: "POST", headers: { "content-type": "application/json" }, body: stale });
  const staleBody = await staleRes.json();
  check("ts 過期 → 401 stale_or_skewed_timestamp",
    staleRes.status === 401 && staleBody.error === "stale_or_skewed_timestamp", `error=${staleBody.error}`);

  /* 7. 錯簽名 → 401 */
  const badTs = Math.floor(Date.now() / 1000);
  const bad = JSON.stringify({
    agent_id: AGENT, wants: ["static.key"], ts: badTs, nonce: "nonce00000003",
    sig: sign(B.privateKey, AGENT, ["static.key"], badTs, "nonce00000003"),
  });
  const badRes = await call("/v1/claim", { method: "POST", headers: { "content-type": "application/json" }, body: bad });
  check("錯簽名 → 401", badRes.status === 401, `status=${badRes.status}`);

  /* 8. 無 entitlement → 403 + denied */
  const unTs = Math.floor(Date.now() / 1000);
  const un = JSON.stringify({
    agent_id: AGENT, wants: ["other.key"], ts: unTs, nonce: "nonce00000004",
    sig: sign(A.privateKey, AGENT, ["other.key"], unTs, "nonce00000004"),
  });
  const unRes = await call("/v1/claim", { method: "POST", headers: { "content-type": "application/json" }, body: un });
  const unBody = await unRes.json();
  check("無 entitlement → 403 not_entitled",
    unRes.status === 403 && unBody.error === "not_entitled" && Array.isArray(unBody.denied), `error=${unBody.error}`);

  /* 9. 正常 claim 靜態 secret → 200，值正確 */
  const okTs = Math.floor(Date.now() / 1000);
  const okNonce = "nonce00000005";
  const okBody = JSON.stringify({
    agent_id: AGENT, wants: ["static.key"], ts: okTs, nonce: okNonce,
    sig: sign(A.privateKey, AGENT, ["static.key"], okTs, okNonce),
  });
  const okRes = await call("/v1/claim", { method: "POST", headers: { "content-type": "application/json" }, body: okBody });
  const okJson = await okRes.json();
  check("正常 claim → 200 且值正確",
    okRes.status === 200 && okJson.secrets?.["static.key"]?.value === "s3cr3t-value",
    `status=${okRes.status}`);

  /* 10. 重放同一 nonce → 409 */
  const replayRes = await call("/v1/claim", { method: "POST", headers: { "content-type": "application/json" }, body: okBody });
  const replayBody = await replayRes.json();
  check("nonce 重用 → 409 replay_detected",
    replayRes.status === 409 && replayBody.error === "replay_detected", `error=${replayBody.error}`);

  /* 11. 撤銷後 → 401 */
  const del = await jsonCall(`/v1/agents/${AGENT}`, "DELETE", undefined, ADMIN);
  const afterTs = Math.floor(Date.now() / 1000);
  const after = JSON.stringify({
    agent_id: AGENT, wants: ["static.key"], ts: afterTs, nonce: "nonce00000006",
    sig: sign(A.privateKey, AGENT, ["static.key"], afterTs, "nonce00000006"),
  });
  const afterRes = await call("/v1/claim", { method: "POST", headers: { "content-type": "application/json" }, body: after });
  check("撤銷後 claim → 401", del.status === 200 && afterRes.status === 401, `delete=${del.status} claim=${afterRes.status}`);

  /* 12. 不存在的 secret（有 entitlement）→ 404 */
  const putB2 = await jsonCall(`/v1/agents/${AGENT}`, "PUT",
    { pubkey: A.rawPub, entitlements: ["ghost.key"] }, ADMIN);
  const gTs = Math.floor(Date.now() / 1000);
  const ghostKey = JSON.stringify({
    agent_id: AGENT, wants: ["ghost.key"], ts: gTs, nonce: "nonce00000007",
    sig: sign(A.privateKey, AGENT, ["ghost.key"], gTs, "nonce00000007"),
  });
  const ghostKeyRes = await call("/v1/claim", { method: "POST", headers: { "content-type": "application/json" }, body: ghostKey });
  const ghostKeyBody = await ghostKeyRes.json();
  check("entitlement 有但 secret 唔存在 → 404",
    putB2.status === 201 && ghostKeyRes.status === 404 && ghostKeyBody.error === "claim_failed",
    `status=${ghostKeyRes.status}`);

  /* 13. audit log 無 secret 值（檢查 mock KV 內冇 log；呢項由 grep stdout 補） */
  check("KV 內 nonce 有寫入（重放保護實際生效）",
    [...kv._raw.keys()].some((k) => k.startsWith("nonce:")), `${[...kv._raw.keys()].filter((k) => k.startsWith("nonce:")).length} 個 nonce key`);

  /* 14. 舊 /github-token 默認下架 → 404 */
  const legacy = await jsonCall("/github-token", "POST", { installation_id: 1 }, ADMIN);
  check("舊 /github-token 默認 → 404（已下架）", legacy.status === 404, `status=${legacy.status}`);

  /* 15. 舊 flow 開啟但冇 allowlist → 403 */
  const legacyEnv = { ...env, LEGACY_BEARER_ENABLED: "true" };
  const legacyRes = await worker.fetch(
    new Request("https://broker.test/github-token", {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${ADMIN}` },
      body: JSON.stringify({ installation_id: 1 }),
    }), legacyEnv, ctx);
  const legacyBody = await legacyRes.json();
  check("舊 flow 開啟但冇 repo allowlist → 403",
    legacyRes.status === 403 && legacyBody.error === "legacy_repo_allowlist_missing", `error=${legacyBody.error}`);

  /* 16. 所有回應都有 no-store（抽查 status 分佈） */
  const probes = [
    await call("/health"),
    await call("/v1/agents"),
    await call("/nope"),
    await jsonCall("/v1/claim", "POST", { bad: true }),
  ];
  check("所有抽查回應都有 Cache-Control: no-store",
    probes.every((r) => r.headers.get("cache-control") === "no-store"),
    probes.map((r) => r.status).join(","));

  /* 17. N3：KV 內靜態 secret 必須係密文（唔可以見明文） */
  const storedRaw = kv._raw.get(`sec:${AGENT}:static.key`) || "";
  let envelopeOk = false;
  try {
    const env0 = JSON.parse(storedRaw);
    envelopeOk = env0.v === 1 && env0.alg === "A256GCM" && typeof env0.ct === "string" && env0.iv.length > 0;
  } catch (_) {
    envelopeOk = false;
  }
  check("KV 內 sec:* 為密文信封（無明文）",
    envelopeOk && !storedRaw.includes("s3cr3t-value"),
    `envelope=${envelopeOk} 明文出現=${storedRaw.includes("s3cr3t-value")}`);

  /* 18. 舊明文 secret 可讀（legacy 兼容） */
  await jsonCall(`/v1/agents/${OTHER}`, "PUT",
    { pubkey: B.rawPub, entitlements: ["other.key", "legacy.key"] }, ADMIN);
  await kv.put(`sec:${OTHER}:legacy.key`, "legacy-plaintext-value");
  const lgTs = Math.floor(Date.now() / 1000);
  const lgNonce = "nonce00000008";
  const lgRes = await call("/v1/claim", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      agent_id: OTHER, wants: ["legacy.key"], ts: lgTs, nonce: lgNonce,
      sig: sign(B.privateKey, OTHER, ["legacy.key"], lgTs, lgNonce),
    }),
  });
  const lgBody = await lgRes.json();
  check("舊明文 secret 仍可 claim（遷移兼容）",
    lgRes.status === 200 && lgBody.secrets?.["legacy.key"]?.value === "legacy-plaintext-value",
    `status=${lgRes.status}`);

  /* 19. reencrypt 把舊明文就地改寫成密文 */
  const re = await jsonCall("/v1/admin/reencrypt", "POST", {}, ADMIN);
  const reBody = await re.json();
  const lgRawAfter = kv._raw.get(`sec:${OTHER}:legacy.key`) || "";
  const lgTs2 = Math.floor(Date.now() / 1000);
  const lgNonce2 = "nonce00000009";
  const lgRes2 = await call("/v1/claim", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      agent_id: OTHER, wants: ["legacy.key"], ts: lgTs2, nonce: lgNonce2,
      sig: sign(B.privateKey, OTHER, ["legacy.key"], lgTs2, lgNonce2),
    }),
  });
  const lgBody2 = await lgRes2.json();
  check("reencrypt 後 KV 為密文、claim 仍正確",
    re.status === 200 && reBody.migrated >= 1 && !lgRawAfter.includes("legacy-plaintext-value") &&
      lgRes2.status === 200 && lgBody2.secrets?.["legacy.key"]?.value === "legacy-plaintext-value",
    `migrated=${reBody.migrated} claim=${lgRes2.status}`);

  /* 20. 未設 master key → 存 secret 503（fail closed，唔會偷偷存明文） */
  const noKeyEnv = { ...env, BROKER_MASTER_KEY: undefined };
  const noKeyPut = await worker.fetch(
    new Request(`https://broker.test/v1/secrets/${OTHER}/no-key`, {
      method: "PUT",
      headers: { "content-type": "application/json", authorization: `Bearer ${ADMIN}` },
      body: JSON.stringify({ value: "x" }),
    }), noKeyEnv, ctx);
  check("未設 BROKER_MASTER_KEY → 存 secret 回 503", noKeyPut.status === 503, `status=${noKeyPut.status}`);

  /* ================= N2 / N4 ================= */
  await Promise.all(pending);
  pending.length = 0;

  /* 21. prev admin token 重疊期可用；錯 token 401 */
  const prevAuth = await call("/v1/agents", { headers: { authorization: "Bearer test-admin-token-prev" } });
  const badAuth = await call("/v1/agents", { headers: { authorization: "Bearer totally-wrong-token" } });
  check("N2：prev admin token 仍可通過（輪替重疊期）", prevAuth.status === 200, `status=${prevAuth.status}`);
  check("N2：錯 admin token → 401", badAuth.status === 401, `status=${badAuth.status}`);

  /* 22. D1 audit：有 claim + admin 記錄、無 secret 明文、actor 有標記 */
  await Promise.all(pending);
  pending.length = 0;
  const allRows = JSON.stringify(d1._rows);
  check("N4：D1 有 claim 同 admin 記錄",
    d1._rows.some((r) => r.kind === "claim") && d1._rows.some((r) => r.kind === "admin"),
    `claim=${d1._rows.filter((r) => r.kind === "claim").length} admin=${d1._rows.filter((r) => r.kind === "admin").length}`);
  check("N4：D1 內無 secret 明文",
    !allRows.includes("s3cr3t-value") && !allRows.includes("legacy-plaintext-value"),
    `rows=${d1._rows.length}`);
  check("N4：admin 寫操作帶 actor + action",
    d1._rows.some((r) => r.actor === "admin:current" && r.action === "secret_put"),
    "搵 secret_put / admin:current");
  check("N4：IP 只存 hash（唔存原文）",
    d1._rows.every((r) => r.ip_hash === null || /^[0-9a-f]{16}$/.test(r.ip_hash)), "ip_hash 格式");

  /* 23. GET /v1/admin/audit 需要 admin；有 D1 就回 rows */
  const auditRead = await jsonCall("/v1/admin/audit?limit=5", "GET", undefined, ADMIN);
  const auditBody = await auditRead.json();
  const auditNoAuth = await call("/v1/admin/audit?limit=5");
  check("N4：GET /v1/admin/audit 回 rows（admin）",
    auditRead.status === 200 && Array.isArray(auditBody.rows) && auditBody.rows.length > 0,
    `status=${auditRead.status} rows=${auditBody.rows ? auditBody.rows.length : "n/a"}`);
  check("N4：audit 讀取無 admin → 401", auditNoAuth.status === 401, `status=${auditNoAuth.status}`);

  /* 24. claim 限流（CLAIM_RATE_LIMIT=2 → 第 3 次 429 + Retry-After） */
  const rateAgent = "ct-rate";
  await jsonCall(`/v1/agents/${rateAgent}`, "PUT", { pubkey: A.rawPub, entitlements: ["rate.key"] }, ADMIN);
  await jsonCall(`/v1/secrets/${rateAgent}/rate.key`, "PUT", { value: "rate-value" }, ADMIN);
  const envRl = { ...env, CLAIM_RATE_LIMIT: "2" };
  const rlCall = (nonce) => {
    const ts = Math.floor(Date.now() / 1000);
    return worker.fetch(
      new Request("https://broker.test/v1/claim", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          agent_id: rateAgent, wants: ["rate.key"], ts, nonce,
          sig: sign(A.privateKey, rateAgent, ["rate.key"], ts, nonce),
        }),
      }),
      envRl,
      ctx,
    );
  };
  const r1 = await rlCall("noncerate001");
  const r2 = await rlCall("noncerate002");
  const r3 = await rlCall("noncerate003");
  const r3Body = await r3.json();
  check("N2：claim 限流（前 2 次 200、第 3 次 429）",
    r1.status === 200 && r2.status === 200 && r3.status === 429, `${r1.status} ${r2.status} ${r3.status}`);
  check("N2：429 帶 Retry-After + retry_after + no-store",
    r3.headers.get("retry-after") !== null && typeof r3Body.retry_after === "number" &&
      r3.headers.get("cache-control") === "no-store",
    `retry-after=${r3.headers.get("retry-after")}`);

  await Promise.all(pending);

  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} PASS${failed.length ? `，${failed.length} FAIL` : ""}`);
  process.exit(failed.length ? 1 : 0);
}

main().catch((error) => {
  console.error("✖ 測試執行失敗：", error?.message || error);
  process.exit(1);
});
