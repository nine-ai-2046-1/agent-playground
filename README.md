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
| `src/index.ts` → `dist/index.js` | `broker` CLI（TypeScript，全域指令） |
| `worker/` | Cloudflare Worker（驗簽 + 派 secret） |
| `worker/scripts/s5-proof.sh` | 舊 bearer flow 的 token 過期驗證腳本（S5 用） |

## 安裝（channel A：由 repo 直接裝）

```bash
npm i -g github:nine-ai-2046-1/agent-playground
broker --help
```

Private repo 要先有權限：用 broker 自己派嘅 installation token，或者 GitHub 已登入嘅 git credential。

## 快速開始

```bash
# 1. 建立 agent 身份（生成 Ed25519 keypair，私鑰入 Keychain）
broker init --agent opencode-01

# 2. 拿公鑰去登記（admin 權限）
broker admin-login --token-stdin              # 由 stdin 讀 admin token
broker register --agent opencode-01 \
  --pubkey <init 印出嘅公鑰> \
  --entitlements github \
  --installation-id 185701417 \
  --repositories agent-playground

# 3. 用
broker claim github            # 遮罩摘要（sha256 前 8 位 + 長度 + 到期）
broker claim github --print    # 原文 JSON
broker exec -- gh pr list      # 自動注入 GH_TOKEN 再跑命令
```

## 指令

| 指令 | 作用 |
| :-- | :-- |
| `broker init --agent <id>` | 生成 keypair、寫 config、印公鑰 |
| `broker whoami` | 顯示本機 agent / broker / 有冇私鑰 |
| `broker health` | 檢查 broker 可達性（`/health`） |
| `broker claim [key…] [--print\|--env\|--json]` | 簽名 claim；預設遮罩 |
| `broker exec [--keys a,b] -- <cmd…>` | claim 後注入環境變數執行 |
| `broker rotate` | 換 keypair（register 新公鑰後生效） |
| `broker register / agents / secret-put` | admin：登記公鑰、列 registry、存靜態 secret |
| `broker admin-login --token-stdin` | admin token 入 Keychain |

環境變數慣例：`github` → `GH_TOKEN` 及 `GITHUB_TOKEN`；其他 key 大寫、非英數轉底線（`smtp.password` → `SMTP_PASSWORD`）。

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
| 簽名錯 / agent 不存在 / 已撤銷 | `401`（不分開講原因，防枚舉） |
| `ts` 超出 ±60s | `401 stale_or_skewed_timestamp` |
| nonce 重用 | `409 replay_detected` |
| 未在 `entitlements` | `403 not_entitled`（列出 `denied`） |

### 管理 API（`Authorization: Bearer <admin token>`）

| Method / Path | 作用 |
| :-- | :-- |
| `PUT /v1/agents/:id` | 登記 / 輪替公鑰（`pubkey`, `entitlements`, `github{installation_id,repositories,permissions}`） |
| `GET /v1/agents` | 列 registry（公鑰只露前 12 字元） |
| `DELETE /v1/agents/:id` | 撤銷 agent |
| `PUT /v1/secrets/:agentId/:name` | 存靜態 secret（`{"value":"…"}`） |
| `DELETE /v1/secrets/:agentId/:name` | 刪靜態 secret |

### 舊相容 endpoint

`POST /github-token`（Bearer `AGENT_TOKEN`）保留做回歸測試，唔建議新 agent 用。

## KV 結構（`BROKER_KV`）

| Key | 內容 |
| :-- | :-- |
| `agent:<id>` | `{id, pubkey, status, entitlements, github{…}, created_at, updated_at}` |
| `sec:<agent>:<name>` | 靜態 secret 原文（KV 本身已加密靜態儲存）|
| `nonce:<agent>:<nonce>` | `"1"`，TTL 120s（重放保護）|

## 已知限制

1. **Cloudflare Access 未開**：Zero Trust Free 要綁信用卡（$0 但要授權超額收費），所以邊緣層未有 Access Service Token；現時保護全靠 Worker 內簽名驗證。
2. 公鑰 registry 靠 admin token 寫入；admin token 仍係單一共享 secret（只作登記用，唔參與每次 claim）。
3. `wants` 最多 12 項，`repositories` 最多 20 個。
4. 舊 bearer endpoint 仍然存在，文件齊備後應下架。

## Roadmap

- 每個 static secret 加密（envelope encryption，KV 內只存 ciphertext）
- claim token 短期快取，減少 GitHub API 呼叫
- Access / Service Token 作為第二層（要卡）
- `broker run --env-file` 一次過注入多個 secret
