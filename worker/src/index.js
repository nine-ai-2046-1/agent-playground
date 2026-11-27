// github-token-broker — Cloudflare Worker
//
// 兩個世代並存：
//   (A) 舊：POST /github-token  — Bearer AGENT_TOKEN（保留做回歸測試 V1/V2）
//   (B) 新：POST /v1/claim      — 每個 agent 一對 Ed25519 密鑰，驗簽後按 entitlement 派 secret
//
// 原則：
//   - PEM 只在記憶體出現幾秒；不回傳、不 log、不寫入任何 response。
//   - 簽名驗證失敗／重放／無 entitlement → 一律唔派 secret，錯誤訊息唔含內部細節。
//   - 每次 claim 寫一行 audit log（agent_id / 要求清單 / 結果），唔含 secret 值。

const GITHUB_API = "https://api.github.com";
const JWT_TTL_SECONDS = 10 * 60; // GitHub 上限 10 分鐘
const JWT_IAT_SKEW_SECONDS = 60; // 容忍時鐘偏差
const DETAIL_MAX_CHARS = 200;
const TS_WINDOW_SECONDS = 60; // 簽名時間窗 ±60s
const NONCE_TTL_SECONDS = 120; // 重放保護保留時間
const MAX_WANTS = 12;
const AGENT_ID_RE = /^[a-z0-9][a-z0-9._-]{1,47}$/; // 2–48 字元，細寫
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

/** 長度先比、再逐字 XOR，避免早期返回造成的時序差異 */
function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
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
  // 其他一律當「靜態 secret」：KV key sec:<agent>:<name>
  const raw = await env.BROKER_KV.get(`sec:${agentId}:${name}`, "text");
  if (raw === null) throw Object.assign(new Error("secret_not_found"), { status: 404 });
  return { value: raw };
}

/** ====== audit log ====== */

function audit(request, fields) {
  console.log(
    JSON.stringify({
      audit: "claim",
      ip: request.headers.get("CF-Connecting-IP") || null,
      ua: (request.headers.get("User-Agent") || "").slice(0, 60),
      ...fields,
    }),
  );
}

export default {
  async fetch(request, env) {
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
        json({ ok: true, version: "v2", kv: Boolean(env.BROKER_KV), ed25519: true }, 200),
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

      const agent = await getAgent(env, agentId);
      // 唔分開講「唔存在」定「簽名錯」，避免枚舉 agent id
      if (!agent || agent.status !== "active" || !agent.pubkey) {
        audit(request, { agent_id: agentId, wants, result: "unknown_agent" });
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
        audit(request, { agent_id: agentId, wants, result: "bad_signature" });
        return finish(new Response("Unauthorized", { status: 401 }));
      }

      // 重放保護：nonce 用過即拒（先寫再派 secret，任何失敗都唔會放行兩次）
      const nonceKey = `nonce:${agentId}:${nonce}`;
      if (await env.BROKER_KV.get(nonceKey)) {
        audit(request, { agent_id: agentId, wants, result: "replay" });
        return finish(json({ error: "replay_detected" }, 409));
      }
      await env.BROKER_KV.put(nonceKey, "1", { expirationTtl: NONCE_TTL_SECONDS });

      // entitlement 檢查：agent 只可以拿 registry 內列明嘅 secret
      const allowed = Array.isArray(agent.entitlements) ? agent.entitlements : [];
      const denied = wants.filter((w) => !allowed.includes(w));
      if (denied.length > 0) {
        audit(request, { agent_id: agentId, wants, denied, result: "not_entitled" });
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

      audit(request, {
        agent_id: agentId,
        wants,
        result: errors.length ? (Object.keys(secrets).length ? "partial" : "failed") : "ok",
        delivered: Object.keys(secrets),
        errors: errors.map((e) => e.key),
      });

      if (Object.keys(secrets).length === 0) {
        return finish(
          json({ error: "claim_failed", details: errors }, errors.some((e) => e.status === 404) ? 404 : 500),
        );
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

    /* ===================== 管理 API（Bearer AGENT_TOKEN = admin）===================== */
    const adminPaths = url.pathname.startsWith("/v1/agents") || url.pathname.startsWith("/v1/secrets");
    if (adminPaths) {
      if (!env.AGENT_TOKEN) return finish(json({ error: "broker misconfigured" }, 500));
      const header = request.headers.get("Authorization") || "";
      const provided = header.startsWith("Bearer ") ? header.slice(7) : "";
      if (!safeEqual(provided, env.AGENT_TOKEN)) {
        return finish(new Response("Unauthorized", { status: 401 }));
      }
      if (!env.BROKER_KV) return finish(json({ error: "broker misconfigured" }, 500));

      const parts = url.pathname.split("/").filter(Boolean); // ["v1","agents","id"]

      // GET /v1/agents
      if (parts[1] === "agents" && parts.length === 2 && request.method === "GET") {
        const list = await env.BROKER_KV.list({ prefix: "agent:" });
        const agents = [];
        for (const k of list.keys) {
          const rec = await env.BROKER_KV.get(k.name, "json");
          if (rec) {
            agents.push({
              id: rec.id,
              status: rec.status,
              pubkey: String(rec.pubkey || "").slice(0, 12) + "…",
              entitlements: rec.entitlements || [],
              created_at: rec.created_at,
            });
          }
        }
        return finish(json({ agents }, 200));
      }

      // GET /v1/agents/:id  （admin：連 pubkey 全值，做輪替／加 entitlement 用）
      if (parts[1] === "agents" && parts.length === 3 && request.method === "GET") {
        const rec = await getAgent(env, parts[2]);
        if (!rec) return finish(json({ error: "not_found" }, 404));
        return finish(json({ agent: rec }, 200));
      }

      // PUT /v1/agents/:id   （註冊／輪替公鑰）
      if (parts[1] === "agents" && parts.length === 3 && request.method === "PUT") {
        const id = parts[2];
        if (!AGENT_ID_RE.test(id)) return finish(json({ error: "invalid_agent_id" }, 400));
        const body = await request.json().catch(() => null);
        if (!body || typeof body !== "object") return finish(json({ error: "invalid_body" }, 400));
        if (!body.pubkey) return finish(json({ error: "missing_pubkey" }, 400));

        const existing = await getAgent(env, id);
        const record = {
          id,
          pubkey: String(body.pubkey),
          status: body.status === "disabled" ? "disabled" : "active",
          entitlements: Array.isArray(body.entitlements) ? body.entitlements.map(String) : [],
          github: body.github && typeof body.github === "object" ? body.github : existing?.github || null,
          created_at: existing?.created_at || new Date().toISOString(),
          updated_at: new Date().toISOString(),
        };
        await env.BROKER_KV.put(`agent:${id}`, JSON.stringify(record));
        return finish(json({ agent: { ...record, pubkey: record.pubkey.slice(0, 12) + "…" } }, 201));
      }

      // DELETE /v1/agents/:id
      if (parts[1] === "agents" && parts.length === 3 && request.method === "DELETE") {
        await env.BROKER_KV.delete(`agent:${parts[2]}`);
        return finish(json({ deleted: parts[2] }, 200));
      }

      // PUT /v1/secrets/:agentId/:name  （存靜態 secret，例如 smtp.password）
      if (parts[1] === "secrets" && parts.length === 4 && request.method === "PUT") {
        const [, , agentId, name] = parts;
        if (!AGENT_ID_RE.test(agentId)) return finish(json({ error: "invalid_agent_id" }, 400));
        if (!/^[a-z0-9][a-z0-9._-]{0,47}$/.test(name)) return finish(json({ error: "invalid_secret_name" }, 400));
        const body = await request.json().catch(() => null);
        if (!body || body.value === undefined) return finish(json({ error: "missing_value" }, 400));
        await env.BROKER_KV.put(`sec:${agentId}:${name}`, String(body.value));
        return finish(json({ stored: { agent: agentId, name } }, 201));
      }

      // DELETE /v1/secrets/:agentId/:name
      if (parts[1] === "secrets" && parts.length === 4 && request.method === "DELETE") {
        await env.BROKER_KV.delete(`sec:${parts[2]}:${parts[3]}`);
        return finish(json({ deleted: { agent: parts[2], name: parts[3] } }, 200));
      }

      return finish(new Response("Not Found", { status: 404 }));
    }

    /* ===================== (A) 舊：/github-token ===================== */
    if (url.pathname !== "/github-token" || request.method !== "POST") {
      return finish(new Response("Not Found", { status: 404 }));
    }
    // 舊 bearer flow 默認下架（回歸測試時才設 LEGACY_BEARER_ENABLED=true）
    if (env.LEGACY_BEARER_ENABLED !== "true") {
      return finish(new Response("Not Found", { status: 404 }));
    }
    if (!env.AGENT_TOKEN) {
      return finish(json({ error: "broker misconfigured" }, 500));
    }
    const header = request.headers.get("Authorization") || "";
    const provided = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (!safeEqual(provided, env.AGENT_TOKEN)) {
      return finish(new Response("Unauthorized", { status: 401 }));
    }

    const body = await request.json().catch(() => null);
    if (!body || body.installation_id === undefined || body.installation_id === null) {
      return finish(json({ error: "missing installation_id" }, 400));
    }
    installationId = String(body.installation_id);
    if (!/^\d{1,20}$/.test(installationId)) {
      return finish(json({ error: "invalid installation_id" }, 400));
    }

    if (!env.GITHUB_APP_ID || !env.GITHUB_APP_PEM_BASE64) {
      return finish(json({ error: "broker misconfigured" }, 500));
    }

    // 舊 flow 必須有 repo allowlist，避免 mint 出全 installation 範圍的 token
    const legacyRepos = String(env.LEGACY_REPOSITORIES || "")
      .split(",")
      .map((v) => v.trim())
      .filter(Boolean);
    if (legacyRepos.length === 0) {
      return finish(json({ error: "legacy_repo_allowlist_missing" }, 403));
    }

    try {
      const minted = await mintInstallationToken(env, installationId, { repositories: legacyRepos });
      // 只揀三個欄位，唔 spread 整個 GitHub response
      return finish(json(minted, 200));
    } catch (error) {
      // 錯誤只講類型，唔回傳 stack
      return finish(
        json(
          { error: "internal error", github_status: error.githubStatus, detail: sanitizeDetail(error && error.message) },
          500,
        ),
      );
    }
  },
};
