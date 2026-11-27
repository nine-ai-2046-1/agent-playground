# Secret Broker for Agent

> 原 repo 用途：`agent-playground` — 私人 repo，用來測試 agent 嘅 GH CLI / access / CLI。
> 現時同時承載 **Secret Broker** 嘅 CLI 同 Worker 原始碼。

每個 agent 一個身份，自己嚟攞自己嗰份 secret。無共享密碼、無「一個 token 通全場」。

```
opencode ─┐                         ┌─ GitHub App → installation token（按 repo 收窄）
doubao   ─┼─ Ed25519 簽名 claim ──> │
grok     ─┘   (Worker 驗簽)         └─ 靜態 secret（SMTP app password / API key / PEM…）
```

## 為何要簽名而唔用 bearer token

| 問題（舊做法：一個 `AGENT_TOKEN`） | 簽名制 |
| :-- | :-- |
| 一張 token 洩漏 = 全部 agent 失守 | 每個 agent 一對密鑰，洩漏只影響自己 |
| 撤銷要換 token，全部 agent 一齊斷 | 刪 registry 一條記錄，該 agent 即時失效，其他人不受影響 |
| 無身份，log 只知「有人 call」 | `agent_id` 入簽名，audit log 可追誰拿了什麼 |
| 重放攻擊無防備 | `ts` ±60s + `nonce` KV（120s TTL），同一請求只能一次 |
| 權限全開 | `entitlements` 逐項授權；GitHub token 再按 repo / permission 收窄 |

私鑰永遠留在 agent 本機（macOS Keychain / 600 權限檔），**永不經網絡傳出**；broker 只存公鑰。

## 目錄

| 路徑 | 內容 |
| :-- | :-- |
| `src/index.ts` → `dist/index.js` | `broker` CLI（TypeScript，全域指令）；`dist` 已 commit，安裝時唔需要 build |
| `worker/` | Cloudflare Worker（驗簽 + 派 secret） |
| `worker/scripts/s5-proof.sh` | 舊 bearer flow 的 token 過期驗證腳本（S5 用） |
| `scripts-bootstrap-install.sh` | agent 機安裝腳本（clone → `npm pack` → 全域裝） |
| `agents/START.md` | 給要用 broker 的 agent（安裝後點用、DO & DONT） |
| `agents/TECH.md` | 給接手開發的 agent（架構、API 契約、部署／發版 playbook） |
| `agents/AUDIT.md` | 給 audit agent（宣稱清單、風險登記冊、audit playbook） |

## 安裝

**推薦：由 release tarball 裝（pin 版本 + sha256 驗證）**

```bash
# A. 一鍵（推薦；private repo 需要只讀 token：fine-grained PAT 只勾 Contents:Read，或 GitHub App installation token）
read -rsp 'GitHub read token: ' GH_TOKEN && echo
GH_TOKEN="$GH_TOKEN" bash scripts-bootstrap-install.sh            # 預設 pin v0.4.0

# 想 pin 其他已發佈版本：
GH_TOKEN="$GH_TOKEN" REL_TAG=v0.4.0 bash scripts-bootstrap-install.sh

# B. 已經手動 clone 落機（完全離線，唔需要 token）
bash ~/src/agent-playground/scripts-bootstrap-install.sh --dir ~/src/agent-playground

# C. 應急：直接由 repo ref 裝（唔 pin、無 checksum，只限網絡故障時）
GH_TOKEN="$GH_TOKEN" REF=main bash scripts-bootstrap-install.sh --from-git
```

安裝流程（A 模式）：

1. `GET /repos/…/releases/tags/<REL_TAG>` 取 asset id（private repo 用 API asset URL；`github.com/…/releases/download/…` 會 404）
2. 下載 `nine-ai-secret-broker-cli-<ver>.tgz` 同同名 `.sha256`
3. `sha256sum -c` 驗證，唔符即中止（**唔會**裝落去）
4. `npm i -g` tarball，最後核對 `broker --version` 同 release tag 一致

驗證：

```bash
broker --version     # 例：broker 0.4.0
broker help
broker whoami
```

> 唔建議 `npm i -g github:nine-ai-2046-1/agent-playground`：會跟隨 `main` HEAD（供應鏈風險），
> 而且喺已有安裝上重裝會撞 npm `ENOTEMPTY`。要用就用 `--from-git` 加 `REF=<tag 或 commit sha>`。

## 快速開始

```bash
# 1. 建立 agent 身份（生成 Ed25519 keypair；macOS 入 Keychain，Linux 寫 ~/.config/secret-broker/keys/*.pkcs8 600）
broker init --agent opencode-01

# 2. 登記（admin 權限；公鑰自動由本機私鑰推導，唔需要抄）
broker admin-login --token-stdin              # 由 stdin 讀 admin token
broker register --agent opencode-01 \
  --entitlements github \
  --installation-id 185701417 \
  --repositories agent-playground

# 3. 加靜態 secret（--grant 會自動加 entitlement）
printf '%s' 'p@ssword' | broker secret-put --agent opencode-01 --name smtp.password --grant

# 4. 用
broker claim github            # 遮罩摘要（sha256 前 8 位 + 長度 + 到期）
broker claim github --print    # 原文 JSON
broker exec -- gh pr list      # 自動注入 GH_TOKEN 再跑命令
broker exec --keys smtp.password -- sh -c 'echo ${#SMTP_PASSWORD}'
```

## 指令

| 指令 | 作用 |
| :-- | :-- |
| `broker init --agent <id>` | 生成 keypair、寫 config、印公鑰 |
| `broker whoami` | 顯示本機 agent / broker / 有冇私鑰 |
| `broker health` | 檢查 broker 可達性（`/health`） |
| `broker pubkey` | 由私鑰推導公鑰（register 用，唔需要抄） |
| `broker claim [key…] [--print\|--env\|--json]` | 簽名 claim；預設遮罩 |
| `broker exec [--keys a,b] -- <cmd…>` | claim 後注入環境變數執行（推薦） |
| `broker rotate` | 換 keypair（register 新公鑰後生效） |
| `broker register / agents / secret-put` | admin：登記公鑰、列 registry、存靜態 secret |
| `broker admin-login --token-stdin` | admin token 入 Keychain |
| `broker version \| --version \| -v` | 印版本 |
| `broker help \| --help \| -h` | 印說明（含文件索引、退出碼） |

環境變數：`BROKER_URL`（覆蓋 broker 網址）、`BROKER_AGENT_ID`（預設 agent）、`BROKER_ADMIN_TOKEN`（admin）。
環境變數優先於 `~/.config/secret-broker/config.json`。

CLI 退出碼：`0` 成功、`1` 執行錯誤、`2` 用法錯誤（包括冇打指令、缺參數、agent id 格式錯）；claim 專用 `3` 401、`4` 403、`5` 404、`6` 409。

secret key → 環境變數：`github` → `GH_TOKEN` 及 `GITHUB_TOKEN`；其他 key 大寫、非英數轉底線（`smtp.password` → `SMTP_PASSWORD`）。

## API

### `POST /v1/claim`

```json
{
  "agent_id": "opencode-01",
  "wants": ["github"],
  "ts": 1732700000,
  "nonce": "b64url-random-16B",
  "sig": "base64url(Ed25519('v1|agent_id|wants.join(,)|ts|nonce'))"
}
```

回應（200，或部分成功 207）：

```json
{
  "agent_id": "opencode-01",
  "secrets": { "github": { "token": "ghs_…", "expires_at": "…", "permissions": {…} } },
  "errors": [],
  "claimed_at": "…",
  "expires_at": "…"
}
```

| 情況 | 回應 |
| :-- | :-- |
| 簽名錯 / agent 不存在 / 已撤銷（身份類） | `401` plain `Unauthorized`（唔分原因，防枚舉） |
| `ts` 超出 ±60s | `401 stale_or_skewed_timestamp`（時間類錯誤會講原因，方便校時） |
| nonce 重用 | `409 replay_detected` |
| 未在 `entitlements` | `403 not_entitled`（列出 `denied`） |
| 超過限流（默認 40 次／分鐘／agent+IP） | `429 rate_limited` + `Retry-After`、`retry_after` |

### 管理 API（`Authorization: Bearer <admin token>`）

| Method / Path | 作用 |
| :-- | :-- |
| `PUT /v1/agents/:id` | 登記 / 輪替公鑰（`pubkey`, `entitlements`, `github{installation_id,repositories,permissions}`） |
| `GET /v1/agents` | 列 registry（公鑰只露前 12 字元） |
| `GET /v1/agents/:id` | 單筆全值（供輪替／加 entitlement） |
| `DELETE /v1/agents/:id` | 撤銷 agent |
| `PUT /v1/secrets/:agentId/:name` | 存靜態 secret（`{"value":"…"}`）；**落 KV 前自動信封加密** |
| `DELETE /v1/secrets/:agentId/:name` | 刪靜態 secret |
| `POST /v1/admin/reencrypt` | 把舊明文 `sec:*` 就地遷移成密文（回 `{migrated, already_encrypted, failed}`） |
| `GET /v1/admin/audit?limit=50&kind=claim\|admin` | 讀 D1 審計記錄（預設 50，最多 200） |

### 舊相容 endpoint（默認已下架）

`POST /github-token`（Bearer `AGENT_TOKEN`）默認回 `404`。只做回歸測試時才開：

```bash
npx wrangler secret put LEGACY_BEARER_ENABLED   # 值 "true"
npx wrangler secret put LEGACY_REPOSITORIES     # 例：agent-playground（必填）
```

冇 `LEGACY_REPOSITORIES` 時回 `403 legacy_repo_allowlist_missing`，避免 mint 出全 installation 範圍的 token。

## KV 結構（`BROKER_KV`）

| Key | 內容 |
| :-- | :-- |
| `agent:<id>` | `{id, pubkey, status, entitlements, github{…}, created_at, updated_at}` |
| `sec:<agent>:<name>` | 信封加密後嘅 JSON：`{v:1, alg:"A256GCM", iv, ct}`（AAD 綁 `<agent>:<name>`；KV 內**無明文**）|
| `nonce:<agent>:<nonce>` | `"1"`，TTL 120s（重放保護）|

## 限流（N2）

固定窗（KV 計數，60s 視窗），超限即 `429` + `Retry-After: <秒>`：

| 桶 | 默認 | 覆寫 secret | key |
| :-- | :-- | :-- | :-- |
| claim | 40/min | `CLAIM_RATE_LIMIT` | agent + IP |
| admin 寫入 | 60/min | `ADMIN_RATE_LIMIT` | IP |
| audit 讀取 | 30/min | `AUDIT_RATE_LIMIT` | IP |

```bash
wrangler secret put CLAIM_RATE_LIMIT   # 例：20
```

> 限流係 best-effort：KV 最終一致，多 colo 之間可能有少量超額，用嚟擋失控 loop，唔係 DDoS 防護（邊緣層仍建議 Access／WAF）。

## Admin token 輪替（N2）

Worker 同時接受 `AGENT_TOKEN`（current）與 `AGENT_TOKEN_PREV`（舊）。零停機流程：

```bash
# 1. 舊 token 降為 prev（此時兩條都通）
wrangler secret put AGENT_TOKEN_PREV   # 貼入現用 token

# 2. 換新 current
node -e 'process.stdout.write(require("crypto").randomBytes(32).toString("base64url"))' > ~/Doubao/secrets/broker-admin-token
wrangler secret put AGENT_TOKEN < ~/Doubao/secrets/broker-admin-token

# 3. 全客戶端換完（建議觀察 24h）後，刪 prev
wrangler secret delete AGENT_TOKEN_PREV
```

`GET /v1/admin/audit` 的 `actor` 會寫 `admin:current` / `admin:prev`，可直接睇邊個仲用舊 token。

## 審計（N4）

每次 claim 同每次 admin 寫操作（agent put/delete、secret put/delete、reencrypt）都會寫：

| 去邊 | 內容 |
| :-- | :-- |
| Cloudflare log（console JSON） | 全量，供 `wrangler tail` / Logpush |
| D1 `broker-audit.audit` | `id, ts(ISO8601), kind, agent_id, actor, action, wants, result, status, ip_hash, ua, latency_ms, details` |

設計約束：

- **永不記 secret 值**（只記 name / 長度 / 結果）
- IP 只存 `SHA-256(CF-Connecting-IP)` 前 16 hex，唔存原文
- 寫入用 `ctx.waitUntil`，D1 掛咗都唔會拖死 claim（只記 `audit:write_failed` 落 console）
- 查：`GET /v1/admin/audit?limit=50` 或
  `wrangler d1 execute broker-audit --remote --command "SELECT ts,kind,action,agent_id,result,status FROM audit ORDER BY id DESC LIMIT 20"`

## 靜態 secret 加密（N3）

Worker 收到 `PUT /v1/secrets/:agent/:name` 後**即刻用 AES-256-GCM 加密**才寫入 KV：

| 項 | 設計 |
| :-- | :-- |
| 演算法 | AES-256-GCM，12-byte 隨機 IV |
| 金鑰 | `BROKER_MASTER_KEY`（Worker secret，base64url 32 bytes） |
| AAD | `sec|<agent>|<name>` — 搬 key／改 agent 名會解密失敗（防調包） |
| KV 內 | `{"v":1,"alg":"A256GCM","iv":"…","ct":"…"}` — 無明文、無 metadata |
| 舊資料 | 讀到非信封格式即當 legacy 明文（向後兼容），`POST /v1/admin/reencrypt` 可就地遷移 |
| 未設 key | 寫入回 **503 `encryption_not_configured`**（fail closed，唔會偷偷存明文） |

```bash
# 一次性：產生 master key 並上載
node -e 'process.stdout.write(require("crypto").randomBytes(32).toString("base64url"))' > ~/Doubao/secrets/broker-master-key.b64
wrangler secret put BROKER_MASTER_KEY < ~/Doubao/secrets/broker-master-key.b64

# 遷移舊明文（admin token 必備）
curl -X POST "$BROKER_URL/v1/admin/reencrypt" -H "Authorization: Bearer $BROKER_ADMIN_TOKEN"
```

## CI 驗證（生產 E2E）

`.github/workflows/e2e-prod.yml` 由 GitHub runner（乾淨出口）打生產 worker，補本機／內網出口被封嘅缺口。觸發：`workflow_dispatch`、`push main`、每日 `01:00 UTC`。

Repo secrets（Settings → Secrets and variables → Actions）：

| Secret | 值 |
| :-- | :-- |
| `BROKER_PRIVATE_KEY` | CI agent 私鑰（base64 PKCS#8，單行） |
| `BROKER_AGENT_ID` | `ci-e2e-01`（生產 KV 已登記） |
| `BROKER_URL` | `https://github-token-broker.baobao2046.workers.dev` |

冇 secret 都跑得（只做 health／舊 endpoint 404／錯簽 401／契約測試）。報告寫入 `e2e-report.json` 並 commit 回 main（`[skip ci]`），**只含 token 嘅 `prefix`／`len`／`expires_at`／`permissions`，永不含 token 值**。

## 已知限制

1. **Cloudflare Access 未開**：Zero Trust Free 要綁信用卡（$0 但要授權超額收費），所以邊緣層未有 Access Service Token；現時保護全靠 Worker 內簽名驗證。
2. 公鑰 registry 靠 admin token 寫入（只作登記／管理用，唔參與每次 claim）。已支援雙 token 重疊輪替（見上節），但實務上仍係共享 secret：建議每季度輪替一次並收緊 `AGENT_TOKEN_PREV` 生命週期。
3. **Master key 單點**：`BROKER_MASTER_KEY` 只存喺 Worker secret 同本機 `~/Doubao/secrets/broker-master-key.b64`（600）。遺失即解唔到舊 secret（要重新 `secret-put`）；輪替要保留舊 key 做解密（kid 欄位已預留但未多 key）。
4. `wants` 最多 12 項，`repositories` 最多 20 個。
5. 舊 bearer endpoint 仍然存在，文件齊備後應下架。

## Roadmap

- claim token 短期快取，減少 GitHub API 呼叫
- Access / Service Token 作為第二層（要卡）
- `broker run --env-file` 一次過注入多個 secret

## 角色文件（給 agent 讀）

| 文件 | 對象 | 內容 |
| :-- | :-- | :-- |
| `agents/START.md` | 要用 broker 的 agent | 前提檢查、常用指令、env 對應、退出碼、DO & DONT |
| `agents/TECH.md` | 接手的 developer agent | 架構、API 契約、KV 模型、部署／發版／測試 playbook、已知陷阱 |
| `agents/AUDIT.md` | audit agent | 宣稱清單、控制清單、風險登記冊（P0–P2）、audit playbook、測試案例、證據要求 |

審核基線（2026-11-27 N2+N4 後）：Worker 版本 `207a66f2`、CLI `0.4.0`、契約測試 30/30、D1 `broker-audit` 已上線、生產 registry 有 `opencode-01` + `ci-e2e-01`、Access 未開。
