// github-token-broker — Cloudflare Worker
//
// github-token-broker — Cloudflare Worker
//
// 單一對外介面：
//   GET  /health      — 公開健康檢查（只回布林旗標）
//   POST /v1/claim    — 每個 agent 一對 Ed25519 密鑰，驗簽後按 entitlement 派 secret
//
// 設計原則（2026-11-27 定案）：
//   - **冇 admin API**。registry（agent:*）同靜態 secret（sec:*）只可以由 Cloudflare
//     Dashboard／wrangler 用帳號登入寫入；Worker 本身冇任何「可以改資料」嘅端點。
//     即係 Cloudflare 帳號 = 唯一 root of trust，CLI 原始碼可以公開發佈。
//   - 冇共享 admin token、冇 DELETE 端點：撤銷／刪除一律人手喺 Cloudflare 做。
//   - PEM 只在記憶體出現幾秒；不回傳、不 log、不寫入任何 response。
//   - 每次 claim（成功或失敗）寫一行 audit（agent_id / wants / 結果 / ip_hash /
//     machine_id / ua / latency），唔含 secret 值；有 AUDIT_DB 就同時入 D1。
//   - 成功派發即更新 agent 記錄嘅 last_used_at（housekeeping 用）。

const GITHUB_API = "https://api.github.com";
const JWT_TTL_SECONDS = 10 * 60; // GitHub 上限 10 分鐘
const JWT_IAT_SKEW_SECONDS = 60; // 容忍時鐘偏差
const DETAIL_MAX_CHARS = 200;
const TS_WINDOW_SECONDS = 60; // 簽名時間窗 ±60s
const NONCE_TTL_SECONDS = 120; // 重放保護保留時間
const MAX_WANTS = 12;
const AGENT_ID_RE = /^[a-z0-9][a-z0-9._-]{1,47}$/; // 2–48 字元，細寫
// 等時處理用：固定 dummy 公鑰（32 bytes 全 0），令「agent 唔存在」都做一次同樣嘅 verify
const DUMMY_PUBKEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const NONCE_RE = /^[A-Za-z0-9_-]{8,64}$/;

/** base64 -> ArrayBuffer（純 binary，唔經 UTF-8，避免 0x80+ byte 被改） */
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

/**
 * 容忍兩種輸入格式，取回純 DER：
 *   (a) base64(DER)                          — 正式格式
 *   (b) base64(整個 PEM 文字，含 -----BEGIN… 護欄) — 舊版做法／人手抄錯都食得住
 * 遇到 PKCS#1（RSA PRIVATE KEY）會明確報錯，因為 importKey("pkcs8") 唔食。
 */
function pemBase64ToDer(pemBase64) {
  const normalized = String(pemBase64 ?? "").replace(/\s/g, "");
  let buffer = base64ToArrayBuffer(normalized);
  const decodedText = new TextDecoder().decode(new Uint8Array(buffer));
  if (decodedText.includes("-----BEGIN")) {
    if (decodedText.includes("BEGIN RSA PRIVATE KEY")) {
      throw new Error("pkcs1_not_supported: convert with `openssl pkcs8 -topk8 -nocrypt`");
    }
    const body = decodedText
      .replace(/-----BEGIN [^-]+-----/g, "")
      .replace(/-----END [^-]+-----/g, "")
      .replace(/\s/g, "");
    buffer = base64ToArrayBuffer(body);
  }
  return buffer;
}

/** base64url（無 padding） */
function toBase64Url(input) {
  const raw =
    typeof input === "string"
      ? btoa(input)
      : btoa(String.fromCharCode(...new Uint8Array(input)));
  return raw.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** base64url -> Uint8Array */
function fromBase64Url(value) {
  const normalized = String(value ?? "").replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  return new Uint8Array(base64ToArrayBuffer(padded));
}

/** ====== N3：靜態 secret 信封加密（AES-256-GCM，AAD 綁 agent+name）====== */

const ENC_VERSION = 1;
const ENC_ALG = "A256GCM";

/** 由 env BROKER_MASTER_KEY（base64url 32 bytes）取 key 位元組；唔合格回 null（fail closed） */
function masterKeyBytes(env) {
  const raw = String(env.BROKER_MASTER_KEY || "").trim();
  if (!raw) return null;
  try {
    const bytes = fromBase64Url(raw);
    return bytes.byteLength === 32 ? bytes : null;
  } catch (_) {
    return null;
  }
}

async function importMasterKey(env) {
  const bytes = masterKeyBytes(env);
  if (!bytes) return null;
  return crypto.subtle.importKey("raw", bytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

function secretAad(agentId, name) {
  return new TextEncoder().encode(`sec|${agentId}|${name}`);
}

/** 加密 → KV 存的字串（JSON 信封：v/alg/iv/ct；唔含任何明文 metadata） */
async function encryptSecret(env, agentId, name, plaintext) {
  const key = await importMasterKey(env);
  if (!key) throw Object.assign(new Error("encryption_not_configured"), { status: 503 });
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: secretAad(agentId, name) },
    key,
    new TextEncoder().encode(plaintext),
  );
  return JSON.stringify({ v: ENC_VERSION, alg: ENC_ALG, iv: toBase64Url(iv), ct: toBase64Url(ct) });
}

/** 解密；舊格式（未加密明文）原樣回傳並標 legacy:true，方便遷移 */
async function decryptSecret(env, agentId, name, stored) {
  let envelope = null;
  try {
    envelope = JSON.parse(stored);
  } catch (_) {
    envelope = null;
  }
  const isEnvelope =
    envelope && envelope.v === ENC_VERSION && envelope.alg === ENC_ALG && typeof envelope.ct === "string";
  if (!isEnvelope) return { value: stored, legacy: true };
  const key = await importMasterKey(env);
  if (!key) throw Object.assign(new Error("encryption_not_configured"), { status: 503 });
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64Url(envelope.iv), additionalData: secretAad(agentId, name) },
    key,
    fromBase64Url(envelope.ct),
  );
  return { value: new TextDecoder().decode(plain), legacy: false };
}

/** 用 PEM（PKCS#8 base64）簽一張 10 分鐘 App JWT */
async function createAppJwt(appId, pemBase64) {
  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemBase64ToDer(pemBase64),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    iat: now - JWT_IAT_SKEW_SECONDS,
    exp: now + JWT_TTL_SECONDS,
    iss: appId,
  };
  const unsigned = `${toBase64Url(JSON.stringify(header))}.${toBase64Url(JSON.stringify(payload))}`;
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(unsigned),
  );
  return `${unsigned}.${toBase64Url(signature)}`;
}

/** 截短 + 遮罩，確保對外錯誤訊息永遠唔含 JWT / token / PEM */
function sanitizeDetail(text) {
  return String(text ?? "")
    .replace(/eyJ[A-Za-z0-9._-]+/g, "[redacted-jwt]")
    .replace(/gh[psuor]_[A-Za-z0-9]+/g, "[redacted-token]")
    .replace(/-----BEGIN[^]*?-----END[^-]*-----/g, "[redacted-pem]")
    .slice(0, DETAIL_MAX_CHARS);
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

/** ====== Ed25519（per-agent 身份）====== */

/**
 * Workers 對 Ed25519 有兩個名（標準 "Ed25519" / 舊 "NODE-ED25519"），
 * 兩種都試，避免 runtime 版本差異。
 */
async function importEd25519PublicKey(rawB64Url) {
  const raw = fromBase64Url(rawB64Url);
  if (raw.byteLength !== 32) throw new Error("pubkey_must_be_32_bytes");
  for (const alg of [{ name: "Ed25519" }, { name: "NODE-ED25519", namedCurve: "NODE-ED25519" }]) {
    try {
      return await crypto.subtle.importKey("raw", raw, alg, false, ["verify"]);
    } catch (_) {
      /* 試下一個 alg 名 */
    }
  }
  throw new Error("ed25519_unsupported_in_runtime");
}

/** 簽名字串：固定格式，欄位順序唔可以變 */
function canonicalPayload(agentId, wants, ts, nonce) {
  return `v1|${agentId}|${wants.join(",")}|${ts}|${nonce}`;
}

/** ====== GitHub installation token ====== */

async function mintInstallationToken(env, installationId, options = {}) {
  if (!env.GITHUB_APP_ID || !env.GITHUB_APP_PEM_BASE64) {
    throw new Error("broker misconfigured");
  }
  const jwt = await createAppJwt(env.GITHUB_APP_ID, env.GITHUB_APP_PEM_BASE64);

  const payload = {};
  if (Array.isArray(options.repositories) && options.repositories.length > 0) {
    payload.repositories = options.repositories.slice(0, 20);
  }
  if (options.permissions && typeof options.permissions === "object") {
    payload.permissions = options.permissions;
  }

  const ghRes = await fetch(`${GITHUB_API}/app/installations/${installationId}/access_tokens`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${jwt}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "github-token-broker",
    },
    body: JSON.stringify(payload),
  });

  if (!ghRes.ok) {
    const text = await ghRes.text();
    const err = new Error(`github failed (${ghRes.status}): ${sanitizeDetail(text)}`);
    err.githubStatus = ghRes.status;
    throw err;
  }
  const data = await ghRes.json();
  return {
    token: data.token,
    expires_at: data.expires_at,
    permissions: data.permissions,
  };
}

/** ====== registry / secrets 存取 ====== */

async function getAgent(env, agentId) {
  const raw = await env.BROKER_KV.get(`agent:${agentId}`, "json");
  return raw || null;
}

async function resolveSecret(env, agentId, name, agent) {
  if (name === "github") {
    const gh = agent.github || {};
    if (!gh.installation_id) throw Object.assign(new Error("github_not_configured"), { status: 403 });
    return mintInstallationToken(env, String(gh.installation_id), {
      repositories: gh.repositories,
      permissions: gh.permissions,
    });
  }
  // 其他一律當「靜態 secret」：KV key sec:<agent>:<name>（信封加密，AAD 綁 agent+name）
  const raw = await env.BROKER_KV.get(`sec:${agentId}:${name}`, "text");
  if (raw === null) throw Object.assign(new Error("secret_not_found"), { status: 404 });

  // v2 密封信封（X25519）：Worker 冇私鑰，所以唔可以亦唔會解 —— 原封不動交畀 agent 本機解。
  let parsed = null;
  try {
    parsed = JSON.parse(raw);
  } catch (_) {
    parsed = null;
  }
  if (parsed && parsed.v === 2 && parsed.alg === "X25519-A256GCM" && typeof parsed.ct === "string") {
    return { sealed: raw, encrypted: true, e2e: true };
  }

  // 舊格式（v1 master-key 信封 或 明文）：仍然由 Worker 解／原樣回，方便遷移
  const decrypted = await decryptSecret(env, agentId, name, raw);
  return { value: decrypted.value, encrypted: !decrypted.legacy, legacy_format: true };
}

/** ====== audit log（console + D1）====== */

const AUDIT_INSERT_SQL =
  "INSERT INTO audit (ts,kind,agent_id,actor,action,wants,result,status,ip_hash,ua,latency_ms,details,machine_id) " +
  "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)";

/** IP 只存 SHA-256 前 16 hex，唔留原文（隱私 + 仍可追同源） */
/** CLI 送嚟嘅機械指紋（CLI 已哈希成 16 hex）；唔合格式即當無，唔信任何其他值 */
function machineId(request) {
  const raw = (request.headers && request.headers.get("X-Broker-Machine")) || "";
  return /^[0-9a-f]{8,32}$/.test(raw) ? raw : null;
}

async function hashIp(ip) {
  if (!ip) return null;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(ip)));
  return [...new Uint8Array(digest)]
    .slice(0, 8)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * 寫一條 audit：一律 console.log（結構化），有 AUDIT_DB 就同時入 D1。
 * 用 ctx.waitUntil，唔阻塞回應；D1 失敗只吞（唔影響業務），但要留痕喺 console。
 * 呼叫者必須保證 fields 內無 secret 值（本函數唔會做遮蔽，只負責落庫）。
 */
function audit(request, env, ctx, fields) {
  const ip = request.headers.get("CF-Connecting-IP") || null;
  // CLI 送上嚟嘅機械指紋（已由 CLI 哈希成 16 hex，Worker 唔知原值）；唔合格式即當無
  const machine = machineId(request);
  const ua = (request.headers.get("User-Agent") || "").slice(0, 120);
  const row = {
    ts: new Date().toISOString(),
    kind: fields.kind || "claim",
    agent_id: fields.agent_id ?? null,
    actor: fields.actor ?? null,
    action: fields.action ?? null,
    wants: Array.isArray(fields.wants) ? fields.wants : null,
    result: fields.result ?? null,
    status: fields.status ?? null,
    ua,
    latency_ms: fields.latency_ms ?? null,
    details: fields.details ?? null,
    machine_id: machine,
  };

  const write = (async () => {
    try {
      row.ip_hash = await hashIp(ip);
      const line = { audit: row.kind, ...row };
      delete line.details;
      if (row.details) line.details = row.details;
      console.log(JSON.stringify(line));
      if (!env || !env.AUDIT_DB) return;
      await env.AUDIT_DB.prepare(AUDIT_INSERT_SQL)
        .bind(
          row.ts,
          row.kind,
          row.agent_id,
          row.actor,
          row.action,
          row.wants ? JSON.stringify(row.wants) : null,
          row.result,
          row.status,
          row.ip_hash,
          row.ua,
          row.latency_ms,
          row.details ? JSON.stringify(row.details) : null,
          row.machine_id,
        )
        .run();
    } catch (error) {
      // audit 永不可以影響主流程；D1 失敗要見得到，但唔含敏感值
      console.log(JSON.stringify({ audit: "write_failed", kind: row.kind, error: sanitizeDetail(error && error.message) }));
    }
  })();

  if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(write);
  return write;
}

/** ====== 限流（KV 固定窗；best effort，非硬保證）====== */

const RATE = {
  claim: { limit: 40, window: 60 }, // 每 agent + IP 每分鐘
};

function rateConf(env, scope) {
  const keyMap = { claim: "CLAIM_RATE_LIMIT" };
  const base = RATE[scope];
  const override = Number(env[keyMap[scope]]);
  return { ...base, limit: Number.isFinite(override) && override > 0 ? override : base.limit };
}

/** KV 寫唔到時嘅同 isolate 內存兜底（防止突發時限流完全失效） */
const LOCAL_RL = new Map();
const LOCAL_RL_MAX = 4096;

function bumpLocalRate(scope, subject, windowKey, limit) {
  const key = `${scope}:${subject}:${windowKey}`;
  if (LOCAL_RL.size > LOCAL_RL_MAX) LOCAL_RL.clear(); // 粗暴但夠用；isolate 隨時回收
  const used = Number(LOCAL_RL.get(key) || 0);
  if (used >= limit) return { allowed: false, used, limit, retryAfter: null, local: true };
  LOCAL_RL.set(key, used + 1);
  return { allowed: true, used: used + 1, limit, local: true };
}

/**
 * 權威計數：D1（單一寫入點，跨 isolate 一致）。
 * KV 版只做 backup（冇 D1 binding 或者 D1 掛咗時）。
 */
async function bumpD1Rate(env, scope, subject, win, conf, now) {
  const row = await env.AUDIT_DB.prepare(
    "INSERT INTO rate_limit (scope, subject, window, used) VALUES (?1, ?2, ?3, 1) " +
      "ON CONFLICT (scope, subject, window) DO UPDATE SET used = used + 1 RETURNING used",
  )
    .bind(scope, subject, win)
    .first();
  const used = Number((row && row.used) || 1);
  if (used > conf.limit) {
    return { allowed: false, used, limit: conf.limit, retryAfter: conf.window - (now % conf.window), source: "d1" };
  }
  return { allowed: true, used, limit: conf.limit, source: "d1" };
}

async function bumpKvRate(env, scope, subject, win, conf, now) {
  const key = `rl:${scope}:${subject}:${win}`;
  const raw = await env.BROKER_KV.get(key, "text");
  const used = Number(raw || "0");
  if (used >= conf.limit) {
    return { allowed: false, used, limit: conf.limit, retryAfter: conf.window - (now % conf.window), source: "kv" };
  }
  try {
    await env.BROKER_KV.put(key, String(used + 1), { expirationTtl: conf.window * 2 });
  } catch (error) {
    // KV 同一個 key 每秒只可寫一次；突發請求會撞寫入上限。
    // 呢個係「用量控制」而唔係「認證」—— 寫唔到唔可以變 500。
    console.log(JSON.stringify({
      event: "rate_limit_degraded",
      scope,
      reason: String((error && error.message) || error).slice(0, 80),
      ts: new Date().toISOString(),
    }));
    const local = bumpLocalRate(scope, subject, String(win), conf.limit);
    return { ...local, degraded: true, retryAfter: local.retryAfter ?? conf.window - (now % conf.window), source: "memory" };
  }
  return { allowed: true, used: used + 1, limit: conf.limit, source: "kv" };
}

async function bumpRate(env, scope, subject) {
  const conf = rateConf(env, scope);
  const now = Math.floor(Date.now() / 1000);
  const win = Math.floor(now / conf.window);
  if (env.AUDIT_DB) {
    try {
      return await bumpD1Rate(env, scope, subject, win, conf, now);
    } catch (error) {
      // D1 寫唔到（罕見）：退返 KV → 內存，逐級降級，但一定唔會 500
      console.log(JSON.stringify({
        event: "rate_limit_d1_failed",
        scope,
        reason: String((error && error.message) || error).slice(0, 80),
        ts: new Date().toISOString(),
      }));
    }
  }
  return bumpKvRate(env, scope, subject, win, conf, now);
}

export default {
  async fetch(request, env, ctx) {
    const startedAt = Date.now();
    const url = new URL(request.url);
    let status = 500;
    let installationId;

    const finish = (response) => {
      // 所有回應（包括 plain-text 401/404）一律 no-store，避免中介快取
      if (!response.headers.get("Cache-Control")) {
        const headers = new Headers(response.headers);
        headers.set("Cache-Control", "no-store");
        response = new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers,
        });
      }
      status = response.status;
      // 只 log 非敏感 metadata：path / method / status / installation_id / latency
      console.log(
        JSON.stringify({
          path: url.pathname,
          method: request.method,
          status,
          installation_id: installationId ?? null,
          latency_ms: Date.now() - startedAt,
        }),
      );
      return response;
    };

    // 公開健康檢查（唔驗 auth，唔洩任何設定）
    if (url.pathname === "/health" && request.method === "GET") {
      return finish(
        json(
          {
            ok: true,
            version: "v2",
            kv: Boolean(env.BROKER_KV),
            ed25519: true,
            encryption: Boolean(masterKeyBytes(env)),
            audit: Boolean(env.AUDIT_DB),
            rate_limit: true,
          },
          200,
        ),
      );
    }

    /* ===================== (B) 新：/v1/claim ===================== */
    if (url.pathname === "/v1/claim" && request.method === "POST") {
      if (!env.BROKER_KV) return finish(json({ error: "broker misconfigured" }, 500));

      const body = await request.json().catch(() => null);
      if (!body || typeof body !== "object") {
        return finish(json({ error: "invalid_body" }, 400));
      }

      const agentId = String(body.agent_id ?? "");
      const wants = Array.isArray(body.wants) ? body.wants.map(String) : null;
      const ts = Number(body.ts);
      const nonce = String(body.nonce ?? "");
      const sig = String(body.sig ?? "");

      if (!AGENT_ID_RE.test(agentId)) return finish(json({ error: "invalid_agent_id" }, 400));
      if (!wants || wants.length === 0 || wants.length > MAX_WANTS) {
        return finish(json({ error: "invalid_wants" }, 400));
      }
      if (!wants.every((w) => /^[a-z0-9][a-z0-9._-]{0,47}$/.test(w))) {
        return finish(json({ error: "invalid_wants" }, 400));
      }
      if (!Number.isInteger(ts) || Math.abs(Math.floor(Date.now() / 1000) - ts) > TS_WINDOW_SECONDS) {
        return finish(json({ error: "stale_or_skewed_timestamp" }, 401));
      }
      if (!NONCE_RE.test(nonce)) return finish(json({ error: "invalid_nonce" }, 400));
      if (sig.length < 40) return finish(json({ error: "invalid_signature_format" }, 401));

      // N2：claim 限流（每 agent + 來源 IP 每分鐘）
      const claimRl = await bumpRate(env, "claim", `${agentId}:${request.headers.get("CF-Connecting-IP") || "unknown"}`);
      if (!claimRl.allowed) {
        audit(request, env, ctx, {
          agent_id: agentId,
          wants,
          result: "rate_limited",
          status: 429,
          details: { limit: claimRl.limit },
        });
        const res = json({ error: "rate_limited", retry_after: claimRl.retryAfter }, 429);
        res.headers.set("Retry-After", String(claimRl.retryAfter));
        return finish(res);
      }

      const agent = await getAgent(env, agentId);
      // 唔分開講「唔存在」定「簽名錯」，避免枚舉 agent id
      if (!agent || agent.status !== "active" || !agent.pubkey) {
        // 等時處理：用 dummy 公鑰做一次同款 verify，令「唔存在」同「簽名錯」延遲接近
        try {
          const dummy = await importEd25519PublicKey(DUMMY_PUBKEY);
          await crypto.subtle.verify(
            { name: dummy.algorithm.name },
            dummy,
            fromBase64Url(sig),
            new TextEncoder().encode(canonicalPayload(agentId, wants, ts, nonce)),
          );
        } catch (_) {
          /* 預期會失敗／拋錯；目的只係消耗同一個時間量 */
        }
        audit(request, env, ctx, { agent_id: agentId, wants, result: "unknown_agent", status: 401 });
        return finish(new Response("Unauthorized", { status: 401 }));
      }

      let verified = false;
      try {
        const key = await importEd25519PublicKey(agent.pubkey);
        verified = await crypto.subtle.verify(
          { name: key.algorithm.name },
          key,
          fromBase64Url(sig),
          new TextEncoder().encode(canonicalPayload(agentId, wants, ts, nonce)),
        );
      } catch (_) {
        verified = false;
      }
      if (!verified) {
        audit(request, env, ctx, { agent_id: agentId, wants, result: "bad_signature", status: 401 });
        return finish(new Response("Unauthorized", { status: 401 }));
      }

      // 重放保護：nonce 用過即拒（先寫再派 secret，任何失敗都唔會放行兩次）
      const nonceKey = `nonce:${agentId}:${nonce}`;
      if (await env.BROKER_KV.get(nonceKey)) {
        audit(request, env, ctx, { agent_id: agentId, wants, result: "replay", status: 409 });
        return finish(json({ error: "replay_detected" }, 409));
      }
      try {
        await env.BROKER_KV.put(nonceKey, "1", { expirationTtl: NONCE_TTL_SECONDS });
      } catch (error) {
        // 重放保護寫唔到 = 唔可以派（fail closed），但要係乾淨 503 而唔係 500
        audit(request, env, ctx, {
          agent_id: agentId,
          wants,
          result: "kv_error",
          status: 503,
          details: { stage: "nonce", reason: sanitizeDetail((error && error.message) || "kv_write_failed") },
        });
        const res = json({ error: "kv_unavailable", retry_after: 5 }, 503);
        res.headers.set("Retry-After", "5");
        return finish(res);
      }

      // entitlement 檢查：agent 只可以拿 registry 內列明嘅 secret
      const allowed = Array.isArray(agent.entitlements) ? agent.entitlements : [];
      const denied = wants.filter((w) => !allowed.includes(w));
      if (denied.length > 0) {
        audit(request, env, ctx, { agent_id: agentId, wants, denied, result: "not_entitled", status: 403 });
        return finish(json({ error: "not_entitled", denied }, 403));
      }

      const secrets = {};
      const errors = [];
      let earliestExpiry = null;

      for (const want of wants) {
        try {
          const value = await resolveSecret(env, agentId, want, agent);
          secrets[want] = value;
          if (value && value.expires_at) {
            if (!earliestExpiry || value.expires_at < earliestExpiry) earliestExpiry = value.expires_at;
          }
        } catch (error) {
          errors.push({ key: want, error: sanitizeDetail(error && error.message), status: error.status || 500 });
        }
      }

      // N7：housekeeping 用 —— 成功派發即更新 last_used_at / last_used_machine
      const touched = {
        ...agent,
        last_used_at: new Date().toISOString(),
        last_used_machine: machineId(request),
        last_used_ip: await hashIp(request.headers.get("CF-Connecting-IP") || null),
      };
      ctx.waitUntil(env.BROKER_KV.put(`agent:${agentId}`, JSON.stringify(touched)));

      audit(request, env, ctx, {
        agent_id: agentId,
        wants,
        result: errors.length ? (Object.keys(secrets).length ? "partial" : "failed") : "ok",
        status: errors.length ? (Object.keys(secrets).length ? 207 : 500) : 200,
        latency_ms: Date.now() - startedAt,
        details: { delivered: Object.keys(secrets), errors: errors.map((e) => e.key) },
      });

      if (Object.keys(secrets).length === 0) {
        // 單一原因時保留其狀態（404 找唔到／503 未設 master key／500 真故障），混合就 500
        const statuses = errors.map((e) => e.status);
        const failStatus =
          statuses.every((s) => s === 404) ? 404 : statuses.every((s) => s === 503) ? 503 : 500;
        return finish(json({ error: "claim_failed", details: errors }, failStatus));
      }

      return finish(
        json(
          {
            agent_id: agentId,
            secrets,
            errors,
            claimed_at: new Date().toISOString(),
            expires_at: earliestExpiry,
          },
          errors.length ? 207 : 200,
        ),
      );
    }

    // 舊 bearer flow 已完全下架（admin／共享 token 一併撤出 Worker 邊界）
    return finish(new Response("Not Found", { status: 404 }));
  },
};

// 供契約測試直接使用（唔會暴露喺 HTTP 介面）
export { encryptSecret, decryptSecret, hashIp, canonicalPayload };
