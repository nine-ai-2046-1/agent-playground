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

# 2. 登記（喺 Cloudflare 帳號層做；CLI 只負責印出要寫入嘅 JSON）
broker ask-register --agent opencode-01 \
  --entitlements github \
  --installation-id 185701417 \
  --repositories agent-playground
# → 跟住喺 Cloudflare KV 寫入 agent:opencode-01（指令會印埋出嚟）

# 3. 加靜態 secret（本機加密，只出密文）
printf '%s' 'p@ssword' | node scripts/secret-envelope.mjs --agent opencode-01 --name smtp.password

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
| `broker pubkey` | 由私鑰推導公鑰（貼上 Cloudflare 用，唔需要抄） |
| `broker ask-register` | 印出要人手寫入 Cloudflare KV 嘅 agent JSON |
| `broker claim [key…] [--print\|--env\|--json]` | 簽名 claim；預設遮罩 |
| `broker exec [--keys a,b] -- <cmd…>` | claim 後注入環境變數執行（推薦） |
| `broker rotate` | 換 keypair（舊公鑰即刻失效；新公鑰要喺 Cloudflare 更新） |
| `broker version \| --version \| -v` | 印版本 |
| `broker help \| --help \| -h` | 印說明（含文件索引、退出碼） |

環境變數：`BROKER_URL`（覆蓋 broker 網址）、`BROKER_AGENT_ID`（預設 agent）、`BROKER_PRIVATE_KEY`（CI／容器用私鑰）。
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

### 註冊與管理（**Cloudflare 帳號層，唔經 Worker**）

Worker **冇任何 admin API**：`/v1/agents`、`/v1/secrets`、`/v1/admin/*` 全部 404。registry 同 secret 只可以由 Cloudflare 帳號持有人寫入 —— 所以 CLI 原始碼可以公開派，因為佢冇能力改任何伺服器資料。

**① 新 agent 註冊**

```bash
broker init --agent opencode-01                          # 本機生成 keypair
broker ask-register --agent opencode-01                                   # 印出完整 agent JSON + wrangler 指令
```

跟住喺 Cloudflare 做（Dashboard → Workers KV → `BROKER_KV` → 新增 key，或者）：

```bash
cd worker
npx wrangler kv key put --binding=BROKER_KV --remote "agent:opencode-01" '<上面印出嘅 JSON>'
```

**② 加靜態 secret（值只喺你部機加密）**

```bash
printf 'my-smtp-password' | node scripts/secret-envelope.mjs --agent opencode-01 --name smtp.password
# 會印出密文信封 + 一行 wrangler kv key put
```

**③ 改 entitlement / 公鑰 / 停用**

直接改 `agent:<id>` 嘅 JSON（`entitlements`、`pubkey`、`status:"disabled"`）。

**④ 撤銷（刪除）**

`wrangler kv key delete --binding=BROKER_KV --remote "agent:<id>"` 或 Dashboard 刪 key。**CLI 冇 delete 指令，Worker 亦冇 DELETE 端點** —— 刻意令「消滅一個身分」只能由雲帳號做。

| 資料 | KV key | 邊個寫 |
| :-- | :-- | :-- |
| agent 記錄 | `agent:<id>` | Cloudflare 帳號 |
| 靜態 secret（密文信封） | `sec:<agent>:<name>` | 本機加密 → Cloudflare 帳號 |
| nonce / 限流計數 | `nonce:*` / `rl:*` | Worker（自動，TTL 過期） |

### 舊 endpoint 已完全下架

`POST /github-token` 同所有 admin 路徑一樣回 **404**，程式碼已移除（唔再靠 flag 開關）。

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

```bash
wrangler secret put CLAIM_RATE_LIMIT   # 例：20
```

> 限流係 best-effort：KV 最終一致，多 colo 之間可能有少量超額，用嚟擋失控 loop，唔係 DDoS 防護（邊緣層仍建議 Access／WAF）。

## 為何冇 admin API（2026-11-27 定案）

| 原因 | 說明 |
| :-- | :-- |
| 收窄攻擊面 | 少一套可被暴力猜測／重放嘅共享 token；Worker 只剩 `/health` + `/v1/claim` |
| 單一 root of trust | 改資料 = Cloudflare 帳號（開 2FA 之後只有你做到），CLI／source 派街坊都冇所謂 |
| 無「靜默接管」 | 冇 PUT 端點就冇得覆蓋別人公鑰；要換 key 就要喺 Cloudflare 手動改，一定有紀錄 |
| 無 delete 面 | 撤銷只可以喺雲帳號做，冇任何 client 可以單方面刪身分 |

## 審計（N4）

每次 claim（成功／失敗、包括重放同限流）都會寫。**離線指令（`init`／`whoami`／`ask-register`／`rotate`）完全唔上網，所以冇 log** —— 呢個設計刻意：只關注「邊個用過 broker、邊個試圖入侵」。

| 去邊 | 內容 |
| :-- | :-- |
| Cloudflare log（console JSON） | 全量，供 `wrangler tail` / Logpush |
| D1 `broker-audit.audit` | `id, ts, kind, agent_id, actor, action, wants, result, status, ip_hash, ua, latency_ms, details, machine_id` |

設計約束：

- **永不記 secret 值**（只記 name / 長度 / 結果）
- `machine_id` = 呼叫端 `X-Broker-Machine`（IOPlatformUUID→SHA-256 前 16 hex，唔含原始硬體 ID）；缺／格式錯記 `-`
- 成功 claim 會同時更新 KV `agent:<id>` 嘅 `last_used_at`／`last_used_machine`／`last_used_ip`，用嚟 housekeeping
- IP 只存 `SHA-256(CF-Connecting-IP)` 前 16 hex，唔存原文
- 寫入用 `ctx.waitUntil`，D1 掛咗都唔會拖死 claim（只記 `audit:write_failed` 落 console）
- **成功派發會更新 `agent:<id>.last_used_at` / `last_used_machine`**（housekeeping 用：超過 N 日冇用就考慮刪）
- 查（Cloudflare 帳號層，冇 HTTP 讀取端點）：
  `wrangler d1 execute broker-audit --remote --command "SELECT ts,agent_id,result,status,ip_hash,machine_id FROM audit ORDER BY id DESC LIMIT 20"`

## 靜態 secret 加密（N3）

Worker 收到 `PUT /v1/secrets/:agent/:name` 後**即刻用 AES-256-GCM 加密**才寫入 KV：

| 項 | 設計 |
| :-- | :-- |
| 演算法 | AES-256-GCM，12-byte 隨機 IV |
| 金鑰 | `BROKER_MASTER_KEY`（Worker secret，base64url 32 bytes） |
| AAD | `sec|<agent>|<name>` — 搬 key／改 agent 名會解密失敗（防調包） |
| KV 內 | `{"v":1,"alg":"A256GCM","iv":"…","ct":"…"}` — 無明文、無 metadata |
| 舊資料 | 讀到非信封格式即當 legacy 明文（向後兼容）；要遷移就用 `scripts/secret-envelope.mjs` 重新加密再覆寫該 KV key |
| 未設 key | 寫入回 **503 `encryption_not_configured`**（fail closed，唔會偷偷存明文） |

```bash
# 一次性：產生 master key 並上載
node -e 'process.stdout.write(require("crypto").randomBytes(32).toString("base64url"))' > ~/Doubao/secrets/broker-master-key.b64
wrangler secret put BROKER_MASTER_KEY < ~/Doubao/secrets/broker-master-key.b64

# 舊明文遷移：本機重新加密後覆寫
printf '%s' "$OLD_VALUE" | node scripts/secret-envelope.mjs --agent <id> --name <key>
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
2. registry 只可以由 Cloudflare 帳號寫入（已冇 admin API）。**Cloudflare 帳號 = 唯一 root of trust**：請務必開 2FA、用最小權限 API token。
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

審核基線（2026-11-27 N7 後）：Worker 只暴露 `/health` + `/v1/claim`，admin API 全撤；契約測試 22/22；D1 `broker-audit` 有 `machine_id` 欄；Access 未開。
