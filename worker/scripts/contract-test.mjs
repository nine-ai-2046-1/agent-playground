#!/usr/bin/env node
/**
 * contract-test.mjs — Secret Broker 契約測試（自帶 mock KV + mock D1，唔需要 wrangler、唔需要網絡）
 *
 * 用法：node worker/scripts/contract-test.mjs
 * 要求：Node >= 20（crypto.subtle + Ed25519）
 *
 * 2026-11-27 定案：Worker 冇 admin API。registry / 靜態 secret 由 KV 直接 seed
 * （模擬「人手喺 Cloudflare Dashboard / wrangler 寫入」）。
 *
 * 覆蓋：health 旗標、admin／舊 endpoint 全 404、claim 驗簽各失敗模式、重放、
 *       entitlement、靜態 secret 解密、legacy 明文、master key 缺失 fail closed、
 *       限流 429 + Retry-After、last_used_at、D1 audit（成功＋失敗、無明文、ip 只存 hash、
 *       machine_id）、全回應 no-store。
 * 退出碼：0 全部 PASS；1 有 FAIL。
 */

import crypto from "node:crypto";
import assert from "node:assert";

const workerModule = await import("../src/index.js");
const fetchHandler = workerModule.default.fetch || workerModule.default;
const { encryptSecret } = workerModule;

/* ---------------- mock KV ---------------- */
function makeKV() {
  const store = new Map();
  return {
    _store: store,
    async get(key, type) {
      const raw = store.get(key);
      if (raw === undefined) return null;
      if (type === "json") {
        try {
          return JSON.parse(raw);
        } catch {
          return null;
        }
      }
      return raw;
    },
    async put(key, value) {
      store.set(key, String(value));
    },
    async delete(key) {
      store.delete(key);
    },
    async list({ prefix = "" } = {}) {
      return {
        keys: [...store.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name })),
        list_complete: true,
      };
    },
  };
}

/* ---------------- mock D1 ---------------- */
function makeD1() {
  const rows = [];
  return {
    _rows: rows,
    prepare(sql) {
      const stmt = {
        params: [],
        bind(...args) {
          this.params = args;
          return this;
        },
        async run() {
          if (sql.includes("INSERT INTO audit")) {
            const [
              ts, kind, agent_id, actor, action, wants, result, status,
              ip_hash, ua, latency_ms, details, machine_id,
            ] = this.params;
            rows.push({ ts, kind, agent_id, actor, action, wants, result, status, ip_hash, ua, latency_ms, details, machine_id });
          }
          return { success: true };
        },
        async all() {
          return { results: [] };
        },
      };
      return stmt;
    },
  };
}

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function keypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const rawPub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
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
  const MASTER = Buffer.from("0123456789abcdef0123456789abcdef").toString("base64url");
  const env = {
    BROKER_KV: kv,
    BROKER_MASTER_KEY: MASTER,
    AUDIT_DB: d1,
    GITHUB_APP_ID: "123",
    GITHUB_APP_PEM_BASE64: "unused-in-contract-test",
  };
  const MACHINE = "a1b2c3d4e5f60789"; // 模擬 CLI 送嚟嘅 16-hex 機械指紋

  const A = keypair();

  const call = (path, init = {}) =>
    fetchHandler(
      new Request(`https://broker.test${path}`, {
        ...init,
        headers: { "x-broker-machine": MACHINE, ...(init.headers || {}) },
      }),
      env,
      ctx,
    );

  /** 模擬「人手喺 Cloudflare 寫 agent record」 */
  const seedAgent = async (id, kp, extra = {}) => {
    await kv.put(
      `agent:${id}`,
      JSON.stringify({
        id,
        pubkey: kp.rawPub,
        status: "active",
        entitlements: ["github", "smtp.password", "legacy.key", "ghost.key"],
        github: { installation_id: 185701417, repositories: ["agent-playground"] },
        created_at: new Date().toISOString(),
        ...extra,
      }),
    );
  };
  /** 模擬「人手喺 Cloudflare 寫密文信封」 */
  const seedSecret = async (agent, name, value) => {
    const stored = await encryptSecret(env, agent, name, value);
    await kv.put(`sec:${agent}:${name}`, stored);
  };

  await seedAgent("agent-a", A);
  await seedAgent("agent-rl", A, { entitlements: ["smtp.password"] });
  await seedAgent("agent-gone", keypair(), { status: "disabled" });
  await seedSecret("agent-a", "smtp.password", "s3cr3t-value");
  await seedSecret("agent-rl", "smtp.password", "s3cr3t-value");

  const claimBody = (agentId, wants, kp, nonce, ts = Math.floor(Date.now() / 1000)) => ({
    agent_id: agentId,
    wants,
    ts,
    nonce,
    sig: sign(kp.privateKey, agentId, wants, ts, nonce),
  });

  const claim = (body, e = env) =>
    fetchHandler(
      new Request("https://broker.test/v1/claim", {
        method: "POST",
        headers: { "content-type": "application/json", "x-broker-machine": MACHINE },
        body: JSON.stringify(body),
      }),
      e,
      ctx,
    );

  /* 1. health 公開、無 auth */
  const health = await call("/health");
  const hb = await health.json();
  check(
    "health 公開、無 auth、旗標齊",
    health.status === 200 && hb.ok === true && hb.ed25519 === true && hb.encryption === true &&
      hb.audit === true && hb.rate_limit === true && health.headers.get("cache-control") === "no-store",
    `status=${health.status} audit=${hb.audit}`,
  );

  /* 2. admin／舊 endpoint 全部下架 */
  const adminPaths = [
    ["/v1/agents", "GET"],
    ["/v1/agents/agent-a", "GET"],
    ["/v1/agents/agent-a", "PUT"],
    ["/v1/agents/agent-a", "DELETE"],
    ["/v1/secrets/agent-a/smtp.password", "PUT"],
    ["/v1/admin/audit", "GET"],
    ["/github-token", "POST"],
  ];
  const adminResults = [];
  for (const [p, m] of adminPaths) {
    const r = await call(p, { method: m });
    adminResults.push(`${m} ${p}=${r.status}`);
  }
  check(
    "admin／舊 endpoint 全部 404（Worker 冇寫入面）",
    adminResults.every((x) => x.endsWith("=404")),
    adminResults.join(" "),
  );

  /* 3. 未知 agent → 401 */
  const unknown = await claim(claimBody("nobody-01", ["github"], A, "nonce00000001"));
  check(
    "未知 agent → 401（唔講原因）+ no-store",
    unknown.status === 401 && unknown.headers.get("cache-control") === "no-store",
    `status=${unknown.status}`,
  );

  /* 4. ts 過期 */
  const stale = await claim(claimBody("agent-a", ["github"], A, "nonce00000002", Math.floor(Date.now() / 1000) - 120));
  const staleBody = await stale.json();
  check(
    "ts 過期 → 401 stale_or_skewed_timestamp",
    stale.status === 401 && staleBody.error === "stale_or_skewed_timestamp",
    `status=${stale.status}`,
  );

  /* 5. 錯簽名 */
  const other = keypair();
  const bad = await claim(claimBody("agent-a", ["github"], other, "nonce00000003"));
  check("錯簽名 → 401", bad.status === 401, `status=${bad.status}`);

  /* 6. 無 entitlement */
  const notEnt = await claim(claimBody("agent-a", ["not.allowed"], A, "nonce00000004"));
  const notEntBody = await notEnt.json();
  check("無 entitlement → 403 not_entitled", notEnt.status === 403 && notEntBody.error === "not_entitled", `status=${notEnt.status}`);

  /* 7. 正常 claim（靜態 secret，密文解密） */
  const okRes = await claim(claimBody("agent-a", ["smtp.password"], A, "nonce00000005"));
  const okBody = await okRes.json();
  check(
    "正常 claim → 200 且解密值正確",
    okRes.status === 200 && okBody.secrets?.["smtp.password"]?.value === "s3cr3t-value" &&
      okRes.headers.get("cache-control") === "no-store",
    `status=${okRes.status}`,
  );

  /* 8. nonce 重放 */
  const replay = await claim(claimBody("agent-a", ["smtp.password"], A, "nonce00000005"));
  check("nonce 重用 → 409 replay_detected", replay.status === 409, `status=${replay.status}`);

  /* 9. nonce 有寫入 KV */
  check("KV 內 nonce 有寫入", Boolean(await kv.get("nonce:agent-a:nonce00000005")), "nonce key 存在");

  /* 10. 已停用 agent → 401 */
  const gone = await claim(claimBody("agent-gone", ["github"], A, "nonce00000006"));
  check("status=disabled → 401", gone.status === 401, `status=${gone.status}`);

  /* 11. entitlement 有但 secret 唔存在 → 404 */
  const missing = await claim(claimBody("agent-a", ["ghost.key"], A, "nonce00000007"));
  check("secret 唔存在 → 404 claim_failed", missing.status === 404, `status=${missing.status}`);

  /* 12. legacy 明文 secret 仍可讀 */
  await kv.put("sec:agent-a:legacy.key", "legacy-plaintext-value");
  const legacy = await claim(claimBody("agent-a", ["legacy.key"], A, "nonce00000008"));
  const legacyBody = await legacy.json();
  check(
    "legacy 明文 secret 仍可 claim（向後兼容）",
    legacy.status === 200 && legacyBody.secrets?.["legacy.key"]?.value === "legacy-plaintext-value",
    `status=${legacy.status}`,
  );

  /* 13. KV 內 sec:* 為密文信封 */
  const envRaw = await kv.get("sec:agent-a:smtp.password");
  const parsed = JSON.parse(envRaw);
  check(
    "KV 內 sec:* 為密文信封（無明文）",
    parsed.v === 1 && parsed.alg === "A256GCM" && Boolean(parsed.ct) && !envRaw.includes("s3cr3t-value"),
    "envelope ok",
  );

  /* 14. 未設 master key → 靜態 secret 503（fail closed） */
  const envNoKey = { ...env, BROKER_MASTER_KEY: undefined };
  const noKey = await claim(claimBody("agent-a", ["smtp.password"], A, "nonce00000009"), envNoKey);
  check("未設 BROKER_MASTER_KEY → 503", noKey.status === 503, `status=${noKey.status}`);

  /* 15. claim 限流 429 + Retry-After */
  const envRl = { ...env, CLAIM_RATE_LIMIT: "2" };
  const r1 = await claim(claimBody("agent-rl", ["smtp.password"], A, "nonce00000010"), envRl);
  const r2 = await claim(claimBody("agent-rl", ["smtp.password"], A, "nonce00000011"), envRl);
  const r3 = await claim(claimBody("agent-rl", ["smtp.password"], A, "nonce00000012"), envRl);
  const r3Body = await r3.json();
  check("限流：前 2 次 200、第 3 次 429", r1.status === 200 && r2.status === 200 && r3.status === 429, `${r1.status} ${r2.status} ${r3.status}`);
  check(
    "429 帶 Retry-After + retry_after + no-store",
    r3.headers.get("retry-after") !== null && typeof r3Body.retry_after === "number" &&
      r3.headers.get("cache-control") === "no-store",
    `retry-after=${r3.headers.get("retry-after")}`,
  );

  /* 16. last_used_at 更新（housekeeping） */
  await Promise.all(pending);
  const touched = await kv.get("agent:agent-a", "json");
  check(
    "成功 claim 後 last_used_at / last_used_machine 有更新",
    Boolean(touched?.last_used_at) && touched.last_used_machine === MACHINE,
    `last_used_at=${touched?.last_used_at}`,
  );

  /* 17-20. audit（D1） */
  const rows = d1._rows;
  const seen = new Set(rows.map((r) => r.result));
  check(
    "D1 有 claim 記錄（成功＋多種失敗）",
    rows.length > 0 && seen.has("ok") && seen.has("bad_signature") && seen.has("rate_limited") && seen.has("replay"),
    `rows=${rows.length} results=${[...seen].join(",")}`,
  );
  check(
    "D1 內無 secret 明文",
    !JSON.stringify(rows).includes("s3cr3t-value") && !JSON.stringify(rows).includes("legacy-plaintext-value"),
    `rows=${rows.length}`,
  );
  check("IP 只存 16 hex hash", rows.every((r) => r.ip_hash === null || /^[0-9a-f]{16}$/.test(r.ip_hash)), "ip_hash 格式");
  check(
    "machine_id 有記錄（同一部實機可追）",
    rows.some((r) => r.machine_id === MACHINE),
    `machine=${rows.find((r) => r.machine_id)?.machine_id ?? "none"}`,
  );

  /* KV 寫入失敗（N7.1）：限流降級唔可以 500；nonce 寫唔到要 fail-closed 503 */
  {
    const mkEnvWithFailingPut = async (failPrefix, id) => {
      const kvX = makeKV();
      const kp = keypair();
      await kvX.put(
        `agent:${id}`,
        JSON.stringify({ id, pubkey: kp.rawPub, status: "active", entitlements: ["demo.key"] }),
      );
      await kvX.put(`sec:${id}:demo.key`, await encryptSecret({ BROKER_MASTER_KEY: MASTER }, id, "demo.key", "v"));
      const origPut = kvX.put.bind(kvX);
      kvX.put = async (key, value, opts) => {
        if (String(key).startsWith(failPrefix)) throw new Error("KV PUT failed: 429 write rate limited");
        return origPut(key, value, opts);
      };
      return { env: { ...env, BROKER_KV: kvX }, kp };
    };

    for (const [label, prefix, expectStatus] of [
      ["限流計數寫唔到 → 降級放行（唔可以 500）", "rl:", 200],
      ["nonce 寫唔到 → 503 fail-closed", "nonce:", 503],
    ]) {
      const { env: envX, kp } = await mkEnvWithFailingPut(prefix, `kvfail-${prefix.replace(":", "")}`);
      const agent = `kvfail-${prefix.replace(":", "")}`;
      const ts = Math.floor(Date.now() / 1000);
      const nonce = crypto.randomBytes(16).toString("base64url");
      const res = await fetchHandler(
        new Request("https://broker.test/v1/claim", {
          method: "POST",
          headers: { "content-type": "application/json", "x-broker-machine": MACHINE },
          body: JSON.stringify({ agent_id: agent, wants: ["demo.key"], ts, nonce, sig: sign(kp.privateKey, agent, ["demo.key"], ts, nonce) }),
        }),
        envX,
        ctx,
      );
      let body = {};
      try {
        body = JSON.parse(await res.text());
      } catch (_) {}
      check(label, res.status === expectStatus, `status=${res.status} body=${JSON.stringify(body)}`);
      if (expectStatus === 503) {
        check("503 帶 kv_unavailable + Retry-After", body.error === "kv_unavailable" && res.headers.get("retry-after") === "5", `retry-after=${res.headers.get("retry-after")}`);
      } else {
        check("降級時仍然派到 secret", body?.secrets?.["demo.key"]?.value === "v", "fail-open 只影響限流計數");
      }
    }
  }

  /* 21. 所有抽查回應 no-store */
  const sampled = [health, unknown, stale, bad, notEnt, okRes, replay, gone, missing, legacy, noKey, r3];
  check("所有抽查回應都有 Cache-Control: no-store", sampled.every((r) => r.headers.get("cache-control") === "no-store"), `${sampled.length} 個回應`);

  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} PASS`);
  if (failed.length) {
    for (const f of failed) console.log(`  ✘ ${f.name} — ${f.detail}`);
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("契約測試 crash:", error);
  process.exit(1);
});
