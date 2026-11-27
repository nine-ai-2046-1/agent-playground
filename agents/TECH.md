# TECH.md — 給「接手做 development」的 agent

> 對象：會改動 `worker/` 或 `src/index.ts`、要部署、要發版的 agent。
> 本文件寫於 2026-11-27，基於當時實測結果。**任何數字都要以程式碼為準**，改動後請同步更新本文件。
> 語言：粵語；表格優先。

## 1. 這個 project 係咩

一個 **Cloudflare Worker + TypeScript CLI** 的 secret broker：

- **Worker**（`worker/src/index.js`）：驗證每個 agent 的 Ed25519 簽名，按 `entitlements` 派 secret。
  - `github` key → 即時用 GitHub App 私鑰 mint installation token（1 小時、可限定 repo）。
  - 其他 key → 讀 KV 內的靜態 secret。
- **CLI**（`src/index.ts` → `dist/index.js`，全域指令 `broker`）：管理身份、簽名 claim、注入環境變數跑命令。

核心安全立場：**私鑰永不出機器**；broker 只存公鑰；GitHub App 的 PEM 永不出 Cloudflare。

現況（2026-11-27）：S0–S7 完成（Linear NIN-184…NIN-191），S8 文件、S9 final review 未完成（NIN-192、NIN-193）。

## 2. 架構與信任邊界

```
┌─────────── agent 機器 ───────────┐        ┌──── Cloudflare ─────┐
│ broker CLI                       │        │ Worker (v2)         │
│  ├ Keychain: 私鑰 (Ed25519)      │  簽名  │  ├ /v1/claim 驗簽   │
│  ├ endpoint: broker URL（機器級）│ ─────> │  ├ (冇 admin API)   │
│  └ 子進程 env: GH_TOKEN …         │ <───── │  └ /health          │
└──────────────────────────────────┘ secret │        │            │
                                             │        ├ KV BROKER_KV│
                                             │        │  agent:*    │
                                             │        │  sec:*      │
                                             │        │  nonce:*    │
                                             │        └ GITHUB_APP_PEM_BASE64 (Secret)
                                             └─────────────────────┘
                                                        │
                                                  GitHub API (App JWT → installation token)
```

信任邊界三條：

1. **agent 機器**：私鑰在 Keychain；CLI 執行身分即 agent 身分。機器被入侵 = 該 agent 失守（但唔影響其他 agent）。
2. **Cloudflare Worker**：唯一 enforcement 點。程式碼完整性 = 全部 secret 的安全性（見 AUDIT.md P0-2）。
3. **GitHub App PEM**：最高價值資產，能 mint 任何 installation 內 repo 的 token。

## 3. Repo 結構

| 路徑 | 用途 |
| :-- | :-- |
| `src/index.ts` | CLI 原始碼（TypeScript，CommonJS 輸出）|
| `dist/index.js` | **已 commit 的建置產物**（安裝時唔需要 build；改碼後必須重新 build 並 commit）|
| `package.json` | `bin.broker → dist/index.js`；`files: [dist, README.md]`；`prepare` 只在 dist 不存在時才 build |
| `worker/src/index.js` | Worker 全部邏輯（單檔，約 490 行）|
| `worker/wrangler.toml` | Worker 名稱、KV binding、KV namespace id |
| `worker/.dev.vars` | **本機專用 secrets（已 gitignore，永不 commit）** |
| `worker/scripts/s5-proof.sh` | 舊 bearer flow 的 token 過期驗證腳本 |
| `scripts-bootstrap-install.sh` | agent 機安裝腳本（clone → npm pack → 全域裝）|
| `agents/START.md` `TECH.md` `AUDIT.md` | 三份角色文件 |
| `README.md` | 對外總覽（含 API、KV、限制）|

## 4. 資料模型（KV `BROKER_KV`）

| Key | Value | 說明 |
| :-- | :-- | :-- |
| `agent:<id>` | JSON `{id, pubkey, status, entitlements[], github{installation_id,repositories[],permissions}, created_at, updated_at, last_used_at, last_used_machine, last_used_ip}` | `pubkey` = base64url(raw 32 bytes) |
| `sec:<agent>:<name>` | JSON `{v:2, alg:"X25519-A256GCM", epk, iv, ct}` | **端到端密封**：X25519 ECDH + HKDF-SHA256 + AES-256-GCM，AAD=`sec\|<agent>\|<name>`；Worker 認到 v2 只原封轉發（`{sealed}`），**零解密能力**；v1 master-key 信封／明文仍可讀（兼容） |
| `nonce:<agent>:<nonce>` | `"1"`，TTL 120s | 重放保護；**先寫後派**，寫失敗即拒絕 |
| `rl:claim:<hash>` | 數字字串，TTL 90s | 固定窗限流計數器；`<hash>` = `SHA-256(agent|ip)` 前 16 hex |

命名規則（Worker 強制）：

- `agent_id`：`/^[a-z0-9][a-z0-9._-]{1,47}$/`（2–48 字元，細寫）
- `secret name`：`/^[a-z0-9][a-z0-9._-]{0,47}$/`
- `nonce`：`/^[A-Za-z0-9_-]{8,64}$/`（CLI 用 16 bytes base64url）

## 5. API 契約

### 5.1 `GET /health`

`{"ok":true,"version":"v2","kv":true,"ed25519":true,"encryption":true,"audit":true,"rate_limit":true}` — 只係布林旗標（D1 綁定喺咗、master key 有冇、限流開唔開），不洩任何值，無 auth。

### 5.2 `POST /v1/claim`（agent 用）

```json
{
  "agent_id": "opencode-01",
  "wants": ["github", "smtp.password"],
  "ts": 1793000000,
  "nonce": "QmFzZTY0dXJsLTE2Qg",
  "sig": "base64url(Ed25519(sign(canonical)))"
}
```

**canonical payload（固定，唔可以改順序）**：

```
v1|<agent_id>|<wants.join(",")>|<ts>|<nonce>
```

驗證順序（照此實作，唔好搬）：

0. 限流（**喺讀 agent 之前**）：`rl:claim:<hash>` 固定窗 60s，超 `CLAIM_RATE_LIMIT`（默認 40）→ `429 rate_limited`，回 `Retry-After` 頭 + `retry_after` body 欄位 + `no-store`
1. body 合法性 → 400
2. `agent_id` regex → 400
3. `wants` 1–12 項、每項 regex → 400
4. `ts` 與伺服器時間相差 > 60s → `401 stale_or_skewed_timestamp`
5. `nonce` regex → 400；`sig` 長度 ≥ 40 → 否則 401
6. 取 `agent:<id>`；**唔存在／disabled／冇公鑰 → 401（唔講原因，防枚舉）**
7. `crypto.subtle.verify`（先試 `Ed25519`，再試 `NODE-ED25519`）→ 失敗 401
8. nonce 已存在 → `409 replay_detected`
9. 寫 nonce（TTL 120s）
10. `wants` 逐項對 `entitlements` → 有唔准許的 → `403 not_entitled {denied:[]}`
11. 逐項 `resolveSecret`
12. 全部失敗 → 404/500 `claim_failed {details}`；部分成功 → **207**

回應（200 / 207）：

```json
{
  "agent_id": "opencode-01",
  "secrets": { "github": { "token": "ghs_…", "expires_at": "…", "permissions": {…} } },
  "errors": [],
  "claimed_at": "2026-11-27T…Z",
  "expires_at": "…"
}
```

`github` 的 `resolveSecret`：用 `agent.github.installation_id` mint token，
`repositories`（最多 20 個）同 `permissions` 一齊傳去 GitHub；未配置 → 403 `github_not_configured`。

### 5.3 registry 管理（**冇 admin API，全部喺 Cloudflare 帳號層**）

2026-11-27 定案：Worker 只保留 `/health` 同 `/v1/claim`。`/v1/agents*`、`/v1/secrets*`、`/v1/admin/*`、`/github-token` **一律 404**，程式碼同 `AGENT_TOKEN`／`safeEqual` 已刪。改資料只可以：

| 動作 | 做法 |
| :-- | :-- |
| 登記／換公鑰／改 entitlement／停用 | 改 KV `agent:<id>` JSON（Dashboard 或 `wrangler kv key put`）；CLI 用 `broker ask-register` 印 JSON |
| 加／換靜態 secret | 本機 `scripts/secret-seal.mjs --agent <id> --name <n> --enc-pubkey <b64url>` 密封 → `wrangler kv key put "sec:<agent>:<name>" --path <信封檔>` |
| 撤銷 | 刪 KV `agent:<id>`（Dashboard／wrangler）—— CLI 同 Worker 都冇 delete |
| 舊明文遷移 | `decrypt` 仍接受 legacy 明文；用 envelope script 重新加密覆寫該 key |

理由：Cloudflare 帳號成為唯一 root of trust（配合 2FA），CLI 原始碼公開派都冇能力寫伺服器資料；同時消除共享 token 帶嚟嘅暴力猜測／重放／靜默接管風險。

### 5.3.1 KV 寫入上限嘅降級策略（N7.1）

Cloudflare Workers KV 對**同一個 key** 有「每秒 1 次寫入」上限。突發 claim 會撞爆 `rl:claim:*`
嘅寫入，繼而拋錯；處理不當會變成 Cloudflare 邊緣 500（HTML 錯誤頁）。

| 情況 | 處理 | 理由 |
| :-- | :-- | :-- |
| 限流計數寫唔到 | **fail-open**：照派，console 記 `rate_limit_degraded` | 限流係用量控制，唔係認證邊界；唔可以因此中斷服務 |
| 重放 nonce 寫唔到 | **fail-closed**：`503 kv_unavailable` + `Retry-After: 5`，audit `result=kv_error` | 寫唔到就唔知有冇重放，寧願唔派 |
| D1 audit 寫唔到 | fail-open（只 console 記） | 審計唔可以阻塞派發 |

契約測試有對應 4 項（mock KV 對 `rl:`／`nonce:` 拋錯）。

### 5.4 審計讀取（N4）

冇 HTTP 讀取端點（避免多一個要認證嘅面）。查法：

```bash
npx wrangler d1 execute broker-audit --remote --command \
  "SELECT ts,kind,agent_id,result,status,ip_hash,machine_id FROM audit ORDER BY id DESC LIMIT 20"
```


```json
{"rows":[{"id":42,"ts":"2026-11-27T11:25:04.251Z","kind":"claim","agent_id":"ci-e2e-01","actor":null,"action":null,"wants":"[\"github\"]","result":"ok","status":200,"ip_hash":"45398917097cb852","ua":"…","latency_ms":null,"details":"{\"delivered\":[\"github\"],\"errors\":[]}"}],"limit":50}
```

D1（`AUDIT_DB` / database `broker-audit`）schema：

| 欄 | 型 | 說明 |
| :-- | :-- | :-- |
| `ts` | TEXT | ISO8601 UTC（`new Date().toISOString()`） |
| `kind` | TEXT | `claim`（N7 後只有 claim 一種） |
| `wants` | TEXT | JSON 陣列（claim 請求嘅 key） |
| `actor` | TEXT NULL | 預留（N7 後 Worker 已無 admin 路徑，一般 NULL） |
| `action` | TEXT | `claim` / `agent_put` / `secret_put` … |
| `agent_id` | TEXT NULL | 目標 agent |
| `result` | TEXT | `ok` / `failed` / `partial` / `not_entitled` / `replay` / `rate_limited` … |
| `ip_hash` | TEXT NULL | SHA-256(CF-Connecting-IP) 前 16 hex |
| `status` | INTEGER | HTTP status |
| `ua` | TEXT | User-Agent |
| `latency_ms` | INTEGER NULL | 預留 |
| `details` | TEXT | JSON（**永不含 secret 值**，只 name／長度／錯誤碼） |

遷移：`worker/migrations/0001_audit.sql`；`npx wrangler d1 migrations apply broker-audit --remote`。
寫入喺 `ctx.waitUntil`，失敗只記 `audit:write_failed` 落 console，唔影響主流程。

### 5.5 舊相容 endpoint（默認下架）

`POST /github-token` 默認回 `404`。只有 `LEGACY_BEARER_ENABLED=true` 才啟用，並且必須設 `LEGACY_REPOSITORIES`（逗號分隔）；缺 allowlist → `403 legacy_repo_allowlist_missing`。啟用時 mint 只限 allowlist 內 repo。

## 6. CLI 內部結構（`src/index.ts`）

| 區塊 | 內容 |
| :-- | :-- |
| utilities | `die(message, code)`、`parseFlags`、`flagString`、`readCliVersion` |
| endpoint（部機層級） | `~/.config/secret-broker/endpoint`（600）；**默認冇**，未設即擋並提示 `broker endpoint set <url>`；`BROKER_URL` 環境變數最優先 |
| config | `~/.config/secret-broker/config.json`（600，只存 `agentId`）；舊檔內 `brokerUrl` 首次讀取時自動遷移去 endpoint 檔 |
| key material | macOS Keychain service `secret-broker-key:<agent>`；非 macOS 用 `KEYS_DIR` 600 檔；私鑰以 PKCS#8 DER 存放 |
| 身份 | `cmdInit`、`cmdWhoami`、`cmdPubkey`、`cmdRotate` |
| claim | `signPayload` → `doClaim`（含退出碼映射）→ `cmdClaim`（遮罩／`--print`／`--env`）|
| exec | `cmdExec`：claim → 注入 env → `spawnSync`，回傳子進程 exit code |
| registry | `cmdAskRegister` 只印 JSON（唔寫、唔上網）；舊 `register`／`agents`／`secret-put`／`admin-login`／`delete` 一律 `usageDie()` 提示去 Cloudflare |
| 每請求標頭 | `callBroker` 自動帶 `X-Broker-Machine`（IOPlatformUUID→SHA-256 前 16 hex）同 `X-Broker-Client: broker-cli/<ver>` |

**退出碼契約**（agent 依賴它分流，唔可以隨便改）：

| exit | 條件 |
| :-- | :-- |
| 0 | 成功 |
| 1 | 執行錯誤（網絡、Keychain、本機私鑰）|
| 2 | 用法錯誤（冇指令／缺參數／格式錯）|
| 3 | claim 收到 401 |
| 4 | claim 收到 403 |
| 5 | claim 收到 404 |
| 6 | claim 收到 409 |

`envNameFor(key)`：`github` → `GH_TOKEN` + `GITHUB_TOKEN`；其他 → 大寫、非英數字轉 `_`。

## 7. 密鑰格式

| 項目 | 格式 |
| :-- | :-- |
| agent 公鑰 | base64url(32 bytes raw Ed25519 public key) |
| agent 私鑰 | Keychain 內 PKCS#8 DER |
| GitHub App PEM | Cloudflare Secret `GITHUB_APP_PEM_BASE64` = base64(**純 DER**)；Worker 另備容錯層，接受整份 PEM 文字（base64 後）|
| App JWT | RS256，`iat = now-60s`（`JWT_IAT_SKEW_SECONDS=60`）、`exp = now+600s`（10 分鐘上限）、`iss=AppID` |

> 歷史陷阱：曾把整份含 `-----BEGIN…` 護欄的 PEM 文字 base64 上傳，導致 `importKey` 失敗。
> 正確做法是 `openssl pkcs8 -topk8 -nocrypt` 轉 PKCS#8，再抽 DER base64（1 個連續字串、無換行）。

## 8. 部署 playbook（Worker）

```bash
cd worker
npx wrangler secret list                        # 應有 4 個
# 首次／輪替 PEM：
openssl pkcs8 -topk8 -nocrypt -in app.pem -out app.pk8.pem
openssl base64 -A -in <(openssl pkcs8 -topk8 -nocrypt -in app.pem -outform DER) > pem.base64.txt
npx wrangler secret put GITHUB_APP_PEM_BASE64 < pem.base64.txt
npx wrangler deploy
```

必要 secrets：`GITHUB_APP_ID`、`GITHUB_APP_PEM_BASE64`。
`BROKER_MASTER_KEY`（base64url 32 bytes；本機備份 `~/Doubao/secrets/broker-master-key.b64`，600）**只為讀舊 v1 信封而保留**；KV 全部轉 v2 後可以刪。

`AGENT_TOKEN`／`AGENT_TOKEN_PREV` 已無程式引用，部署後應 `wrangler secret delete` 清走。

```bash
# N3 master key（一次性；輪替前要先加舊 key 支援解密，見 README 已知限制）
node -e 'process.stdout.write(require("crypto").randomBytes(32).toString("base64url"))' > ~/Doubao/secrets/broker-master-key.b64
# （已唔需要）如要臨時復原 v1 讀取能力：npx wrangler secret put BROKER_MASTER_KEY < ~/Doubao/secrets/broker-master-key.b64
npx wrangler deploy
```
KV：`wrangler.toml` 內 `[[kv_namespaces]] binding = "BROKER_KV"`。
部署後只可驗 `/health`（生產 `/v1/claim` 需 agent 私鑰，且要網絡通）。

**唔可以**用 wrangler 直接改 KV 去加 agent 做「正常流程」；只有在網絡不通時做應急（要標記 caveat）。

## 9. 本機開發 playbook

```bash
cd worker
npx wrangler dev --local --port 8787          # 用 .dev.vars 的 secrets
# 另一個 terminal：
BROKER_URL=http://127.0.0.1:8787 broker health
BROKER_URL=http://127.0.0.1:8787 broker claim github --agent opencode-01
```

注意：`--local` 的 KV 是本地模擬，**與生產 KV 完全分開**；本地 register 的 agent 在生產不存在。

## 10. 測試 playbook（改碼後必跑）

1. **契約測試（已入 repo）**：

```bash
node worker/scripts/contract-test.mjs      # 22 項，自帶 mock KV + mock D1 + ctx.waitUntil 收集器，唔需要 wrangler／網絡
```

   覆蓋：health 旗標、admin 端點全 404、claim 全流程（成功／遮罩欄位／`last_used_*` 回寫）、未知 agent、錯簽、ts 過期／未來、重放、撤銷、無 entitlement、未知 secret、靜態 secret 信封、legacy 明文可讀、`machine_id` 落 D1、D1 無明文、IP 只存 hash、限流 429 + `Retry-After`、no-store 全覆蓋、舊 `/github-token` 404。
   「真 mint GitHub token」唔在內（要真 PEM，屬生產／本機 `.dev.vars` 測試）。
2. **CLI 退出碼**：

```bash
BROKER_URL=http://127.0.0.1:8787 broker claim github --agent nobody-999 ; echo $?   # 3
BROKER_URL=http://127.0.0.1:8787 broker claim not.granted --agent <id> ; echo $?    # 4
BROKER_URL=http://127.0.0.1:8787 broker claim ghost.key  --agent <id> ; echo $?     # 5
```

3. **安裝路徑**（三個都要試）：`scripts-bootstrap-install.sh`、`--dir` 模式、`npm pack` + tarball。
4. **版本**：`broker --version` 要同 `package.json` 一致。

## 11. 發版 playbook

```bash
# 1) bump 版本（package.json；功能變更升 minor）
# 2) build 並 commit dist（安裝靠 dist，唔會 build）
npm run build && node dist/index.js --version
# 3) 更新 README / agents 文件內任何受影響的事實
# 4) commit + push
# 5) 打 tag 並發 release（N5：安裝靠這個）
SHA=$(git rev-parse HEAD)
#   POST /git/refs            {"ref":"refs/tags/v<ver>","sha":"$SHA"}
#   POST /releases            {"tag_name":"v<ver>", ...}
#   POST uploads.github.com/repos/<slug>/releases/<relId>/assets?name=<file>
# 6) 產生 checksum 檔一併上載：
npm pack --silent
shasum -a 256 nine-ai-secret-broker-cli-<ver>.tgz | awk '{print $1"  "$2}' > nine-ai-secret-broker-cli-<ver>.tgz.sha256
# 7) 驗證安裝路徑（本機）：
GH_TOKEN=<只讀 token> REL_TAG=v<ver> bash scripts-bootstrap-install.sh
```

**注意**：private repo 嘅 `https://github.com/<slug>/releases/download/<tag>/<file>` 會回 **404**（實測），
所以腳本一律用 `GET /releases/assets/<id>` + `Accept: application/octet-stream` 下載。

**唔好用** `npm i -g github:...` 做發版安裝（見陷阱 12.1）；亦唔好用 `main` HEAD 做安裝來源。

## 12. 已知陷阱（真實踩過）

| # | 陷阱 | 症狀 | 對策 |
| :-- | :-- | :-- | :-- |
| 12.1 | `npm i -g github:<url>` 重裝 | `ENOTEMPTY: rename … @nine-ai/secret-broker-cli`，之後 `bin/broker` 消失 | 先 `rm -rf $(npm prefix -g)/lib/node_modules/@nine-ai`，再裝 tarball |
| 12.2 | bash `${var/pat/repl}` 放反斜線 URL | git 走 SSH（22 端口），撞 fake-IP DNS 即失敗 | 用 `sed` 組 `https://x-access-token@…`，並設 `GIT_TERMINAL_PROMPT=0` |
| 12.3 | 本機／雲機 DNS 污染 | `wrangler deploy` 正常但 fetch `*.workers.dev` 失敗（`198.18.x` / `face:b00c` 網段）| 生產 claim 只能靠能通 workers.dev 的環境；或者另設自訂域名 |
| 12.4 | 跨域 XHR | dashboard → worker 的 fetch 被 CORS 擋 | 必須先導航到 worker 同源再請求 |
| 12.5 | `npm_config_prefix` | `command -v broker` 揾到舊版，誤以為升級成功 | 用 `$(npm root -g)/@nine-ai/secret-broker-cli/package.json` 核版本 |
| 12.6 | KV 最終一致 | nonce 檢查跨 region 可能延遲 | 若要求嚴格，改用 Durable Object 做 nonce 單點 |
| 12.7 | `prepare` 觸發 tsc | fresh clone 冇 `node_modules` 時爆 `Cannot find name 'process'` | `prepare = test -f dist/index.js \|\| tsc \|\| true`（已守衛）；**發版前仍要 `npm i` 裝 devDeps 再 build** |
| 12.8 | Cloudflare Access | 一鍵 Access 要 Zero Trust onboarding → 要信用卡 | 已暫緩；邊緣保護目前只靠簽名 + 可加免費 WAF rate limit |

## 13. Roadmap 與 Linear 對應

| Linear | 階段 | 狀態 |
| :-- | :-- | :-- |
| NIN-183 | 父 issue：需求 + 拆子任務 | Backlog |
| NIN-184…188 | S0–S4 環境／Worker 骨架／secrets／契約／部署 | Done |
| NIN-189 | S5 token 生命週期驗證（V3/V4） | Done |
| NIN-190 | S6 CLI + 管理 API | Done |
| NIN-191 | S7 安全方案（Ed25519 簽名、拒絕 Access 綁卡路線） | Done |
| NIN-192 | S8 四份文件（README / TECH / DEV / USER）| **未做** — 本 repo 的 `agents/*` 已覆蓋大部分 |
| NIN-193 | S9 final review（N7 後：admin 面全撤、envelope encryption 已上、舊 endpoint 404、E2E 已跑）| **進行中** |

未實作的 roadmap 項目：

1. 靜態 secret envelope encryption（AES-GCM + KEK 存 Cloudflare Secret）
2. claim 結果短期快取（減少 GitHub API 呼叫；要處理撤銷即時性）
3. `broker exec --env-file`、一次注入多個 secret 到檔案（600）
4. 回應簽名 + CLI 公鑰 pinning（防假 broker／MITM）
5. Durable Object 版 nonce / rate limit
6. audit log 落 D1／R2（可查、可告警）
7. `broker --version` 已在 0.3.0 實作；下一步可加 `broker doctor`（一鍵自檢）

## 14. 慣例

- 文件用**粵語**、point form／表格；程式註解可中英混合但變數名英文。
- commit message 用 `feat(cli):` / `fix(bootstrap):` / `chore(release):` 這類前綴。
- `dist/index.js` 必須同 `src/index.ts` 同步 commit（唔可以只推 src）；build 前先 `npm i`（devDeps 唔入 repo）。
所有 secret 值只可經 stdin／env／Keychain 傳；唔准新增任何「secret 走 argv」的旗標。
- 任何改動影響 API／KV／退出碼，**同時**更新 `README.md`、`agents/TECH.md`、`agents/START.md`。
- 生產 secret 一律用 `wrangler secret put`；KV 應急寫入要在 issue 標明 caveat。
- 安裝要用 pin commit（`git+https://…#<sha>`）或 tarball，唔好跟隨 `main` HEAD。
