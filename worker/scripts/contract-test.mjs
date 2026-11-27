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
  const env = {
    BROKER_KV: kv,
    AGENT_TOKEN: ADMIN,
    GITHUB_APP_ID: "123",
    GITHUB_APP_PEM_BASE64: "unused-in-contract-test",
  };

  const A = keypair();
  const B = keypair();

  const call = async (path, init = {}) => {
    const res = await worker.fetch(new Request(`https://broker.test${path}`, init), env);
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
    }), legacyEnv);
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

  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} PASS${failed.length ? `，${failed.length} FAIL` : ""}`);
  process.exit(failed.length ? 1 : 0);
}

main().catch((error) => {
  console.error("✖ 測試執行失敗：", error?.message || error);
  process.exit(1);
});
