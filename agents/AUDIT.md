# AUDIT.md — 給「審核這個系統」的 agent

> 對象：被指派做 audit 的 agent（可以係你，或者另一個獨立 agent）。
> 任務：判斷「Secret Broker 係唔係真係夠安全」——唔係讀完文件簽個名，而係**逐條宣稱拿證據**＋**自己諗出應該審但我們冇講嘅東西**。
> 語言：粵語；交付用表格 + 證據；結論要可以被人反駁（所以要寫方法同指令）。

---

## 0. 你嘅權限邊界（先讀，唔好越界）

| 可以 | 唔可以 |
| :-- | :-- |
| 讀 repo 全部程式碼、文件、git 歷史 | 改生產 Worker、改 KV、改 secrets |
| 本機起 `wrangler dev --local` 做攻擊測試 | 對生產 Workers 做掃描／壓力測試／fuzz |
| 用自己嘅測試 agent id 在**本地** registry 玩 | 改生產 registry（只有 Cloudflare 帳號持有人做得到） |
| 提交 audit 報告、開 Linear issue、留 comment | 自行「順手修好」生產設定（要另開 issue 交 developer）|
| 問 developer 要證據（log、版本、設定截圖）| 要求或持有 GitHub App PEM、Cloudflare API token |

如果 audit 過程需要生產證據但你拿唔到，**記錄為「未證實」**，唔好用推論代替。

---

## 1. 這個系統係咩（30 秒版）

Cloudflare Worker 做 secret broker：每個 agent 用**本機 Ed25519 私鑰**簽名 claim，Worker 驗簽＋查 entitlement 後派 secret（GitHub installation token 或 KV 靜態 secret）。
聲稱的核心價值：私鑰不出機器、broker 只存公鑰、GitHub App PEM 不出 Cloudflare、每個 agent 可獨立撤銷。

---

## 2. 你必須自己設計 audit scope（兩個視角，缺一不可）

### 視角 A —「Prove」：我們宣稱安全，請證明

對第 3 節每條宣稱，你要：
1. 找出**實作位置**（檔案 + 行號）。
2. 設計**可重現測試**（指令 + 預期結果）。
3. 記錄**實際證據**（輸出、HTTP status、log 片段）。
4. 判 **PASS / PARTIAL / FAIL**，PARTIAL 要寫明「邊一部份成立、邊一部份只靠假設」。

> 規則：冇跑過嘅測試，唔可以寫 PASS。只可以寫「未驗證（原因）」。

### 視角 B —「Challenge」：你認為應該審、但我們冇提到的

你要自行產出：
1. **Threat model**：攻擊者係邊幾類（本機被入侵的 agent、被 prompt injection 操縱的 agent、拿到 Cloudflare 帳號的人、拿到 Cloudflare 帳號的人、能改 repo 的人、網絡中間人、內部人）。
2. **攻擊面清單**：每個入口（CLI、Worker HTTP、KV、Cloudflare 帳號、GitHub App、安裝管道、文件本身）→ 可能攻擊 → 現有控制 → 缺口。
3. **盲點清單**：我們文件冇講、但會影響安全嘅事（例如：多 agent 共用同一部機、Keychain 備份、CI 環境、log 保留、撤銷傳播時間）。
4. 對每個你新提出嘅項目：**要麼給出可驗證測試，要麼明確標示「假設／推理，未實測」**。

### 交付格式（兩張表 + 一頁結論）

| # | 宣稱／項目 | 視角 | 方法（指令／位置）| 實測證據 | 判定 | 嚴重度 | 建議 |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- |

最後一頁：整體風險評級、最需要修嘅三件事、你認為可以接受嘅殘餘風險（要講為何可接受）。

---

## 3. 宣稱清單（Prove 視角的起點）

| # | 宣稱 | 驗證方向 | 現時狀態 |
| :-- | :-- | :-- | :-- |
| C1 | 私鑰永不離開 agent 機器 | 靜態審 `src/index.ts` 有冇把私鑰放入任何 request body／header；動態用 `mitm` 或截請求 body 檢查 | 待你驗 |
| C2 | broker 只存公鑰 | 檢查 KV `agent:*` 記錄欄位；`GET /v1/agents` 只露前 12 字元 | 待你驗 |
| C3 | 簽名覆蓋 agent_id + wants + ts + nonce | 對照 `canonicalPayload()`；測試改任一欄位 → 401 | 待你驗 |
| C4 | 時間窗 ±60s | `TS_WINDOW_SECONDS = 60`；改 `ts` 為 ±61s → 401 | 待你驗 |
| C5 | 重放保護 | 同 nonce 重用 → 409；nonce TTL 120s | 待你驗 |
| C6 | entitlement 隔離 | agent A claim agent B 專屬 key → 403；兩個 agent 互不影響 | 待你驗 |
| C7 | 撤銷即時 | `DELETE /v1/agents/:id` 後即刻 claim → 401（注意 KV 一致性）| 待你驗 |
| C8 | GitHub token 短命且 repo 收窄 | claim `github` 後 decode token / 打 `/installation/repositories` 檢查範圍與 `expires_at` | 待你驗 |
| C9 | PEM 不出 Cloudflare | 靜態審：PEM 只出現在 `env.GITHUB_APP_PEM_BASE64` 使用處，冇寫入 KV／response／log | 待你驗 |
| C10 | 錯誤訊息唔洩敏感資訊 | 觸發 401／403／404／500，檢查 body 同 log 有冇 secret 值或內部 path | 待你驗 |
| C11 | audit log 可追誰拿了什麼 | 檢查 `audit()` 欄位（agent_id、wants、result、delivered、ip、ua），且**無 secret 值** | 待你驗 |
| C12 | 預設唔會 print secret 原文 | `broker claim` 預設遮罩；`--print`/`--env`/`exec` 才出原文 | 待你驗 |

---

## 4. 已實施的控制（Control inventory）

| 控制 | 位置 | 說明 |
| :-- | :-- | :-- |
| Ed25519 簽名驗證 | `worker/src/index.js` `importEd25519PublicKey()` / `crypto.subtle.verify` | 公鑰 raw 32 bytes base64url；同時試 `Ed25519` 與 `NODE-ED25519` |
| 固定 canonical 格式 | `canonicalPayload()` | `v1|agent|wants|ts|nonce`，順序固定 |
| 時間窗 | `TS_WINDOW_SECONDS = 60` | 防舊簽名重用 |
| Nonce 重放保護 | `nonce:<agent>:<nonce>` TTL 120s | **先寫後派**，寫入失敗即拒絕 |
| 防枚舉 | 未知 agent／錯簽名一律 `401` 空 body | 唔區分原因 |
| entitlement 白名單 | `agent.entitlements` | 逐 key 檢查；`wants` 最多 12 項 |
| 無 admin 面（N7） | Worker 只有 `/health` + `/v1/claim`；`/v1/agents*`、`/v1/secrets*`、`/v1/admin/*`、`/github-token` 全 404 | 共享 token 面完全消失；改資料只可以 Cloudflare 帳號層做（2FA） |
| Rate limit | `bumpRate()` 固定窗 KV | claim 40/min（agent+IP）；超限 `429` + `Retry-After` |
| 靜態 secret 信封加密 | `encryptSecret()` / `decryptSecret()` | AES-256-GCM、隨機 12B IV、AAD=`sec\|<agent>\|<name>`；KV 無明文；未設 key 寫入 503 |
| 審計（D1） | `audit()` + `AUDIT_DB` | 每次 claim（成功／失敗／重放／限流）落 D1 `audit`；IP 只存 hash、`machine_id` 存呼叫端指紋；`ctx.waitUntil`，失敗 fail-open（只 console 記 `audit:write_failed`） |
| last_used（N7） | claim 成功回寫 KV `agent:<id>` | `last_used_at` / `last_used_machine` / `last_used_ip` 供 housekeeping 判斷係咪冇人用 |
| 最小回應 | mint token 只回 `token/expires_at/permissions` | 唔 spread GitHub 原始 response |
| No-store | `finish()` 統一補 `Cache-Control: no-store` | 包括 plain-text 401/404（2026-11-27 修復後已全覆蓋；修前只有 JSON 回應有） |
| 遮罩輸出 | CLI `maskValue()` | `sha256:xxxxxxxx len=N` |
| 私鑰存放 | Keychain `secret-broker-key:<agent>` | 非 macOS 用 600 檔 |
| 安裝安全 | `scripts-bootstrap-install.sh` | token 走 `GIT_ASKPASS`，唔入 argv；`GIT_TERMINAL_PROMPT=0` |
| Secret 不入 repo | `.gitignore`（`.dev.vars`、`*.pem`、`*.base64.txt`）| 已掃過全 git 歷史：零 PEM／零 token 真值 |
| 可重跑契約測試 | `worker/scripts/contract-test.mjs` | 30 項，自帶 mock KV + mock D1，無需 wrangler／網絡；CI 可直接跑 |
| 安裝 pin + checksum | `scripts-bootstrap-install.sh` + Release `v0.4.0` | 默認抓 release tarball 並驗 `.sha256` + 版本核對；`--from-git` 為應急 |
| argv 洩漏防線 | CLI 已冇任何寫入指令；secret 只經 stdin／env／Keychain | 密文由本機 `scripts/secret-envelope.mjs` 產生 |

---

## 5. 風險登記冊（Risk register）

> 以下係 **2026-11-27 已知** 的風險，附現時狀態。你嘅工作係驗證「狀態」係唔係真，並補上你發現的新風險。

### P0（會令整個系統失守，或令最高價值資產外洩）

| # | 風險 | 為何嚴重 | 現況 | 建議 | 驗證方法 |
| :-- | :-- | :-- | :-- | :-- | :-- |
| R1 | **GitHub App PEM 的 blast radius** | installation `repository_selection = all` → token 可 push 帳號下 **82 個 repo**；PEM 洩漏 = 全部 repo 可被寫入 | 未收窄 | 收窄至 `agent-playground`；或分兩個 App（read / write）| 用 `github` token 打 `GET /installation/repositories` 數 `total_count`，並嘗試對其他 repo 做 read-only 請求 |
| R2 | **Cloudflare 帳號／Worker code 完整性 = root of trust** | 能改 Worker 程式碼的人可加一條 dump endpoint 抽乾所有 secret；目前冇 CI 簽名、冇 branch protection、deploy 只靠本機 wrangler | 未設 | 開 2FA、API token 最小 scope + TTL、branch protection、deploy 憑證分離 | 檢查 repo 設定（`GET /branches/main/protection`，需 admin）；檢查 Cloudflare token scope |
| R3 | **Admin token 單點（`AGENT_TOKEN`）** | 有佢＝可建 agent、grant entitlement，等同可側面取得任何 secret | **已消除（2026-11-27 N7）**：admin API 全撤、`AGENT_TOKEN`／`AGENT_TOKEN_PREV`／`safeEqual` 從程式碼移除。改資料只可以 Cloudflare 帳號（2FA） | 部署後 `wrangler secret delete AGENT_TOKEN`（如仍在）；開 2FA + 最小 scope API token | 打 `/v1/agents`、`/v1/secrets/x/y`、`/v1/admin/audit`、`/github-token` 全部 404 |

### P1（顯著削弱縱深防禦）

| # | 風險 | 現況 | 建議 |
| :-- | :-- | :-- | :-- |
| R4 | **靜態 secret 以原文存 KV** | **已修（N3）**：AES-256-GCM 信封加密，KV 只存 `{v,alg,iv,ct}`；未設 key fail closed 503；`reencrypt` 可遷移 legacy | 只剩 master key 單點問題（見 R15） |
| R5 | **Nonce 檢查建在 KV（最終一致）** | 跨 region 傳播可達 ~60s，理論上可能擴大重放窗 | 改用 Durable Object 單點 |
| R6 | **冇 rate limit／abuse 偵測** | **部分緩解（N2）**：claim 40/min per agent+IP、admin 60/min、audit 30/min，429 有 `Retry-After`。未做告警／異常偵測 | 加告警（429 突增、多 IP 同 agent）；KV 最終一致，跨 colo 可能超額 |
| R7 | **Audit log 只有 `console.log`** | **已修（N4／N7）**：claim 落 D1 `audit`（加 `machine_id`），用 wrangler／SQL 查。仍未做告警／Logpush／append-only 保證 | 加 Logpush；D1 只留 Worker 寫權限 |
| R8 | **Agent 自身可被騎劫（prompt injection）** | broker 保證「有權才拿到」，唔保證「拿到後唔漏」 | egress 白名單、log 掃描、secret 只在子進程 env |
| R9 | **CLI 安裝管道跟 HEAD** | **已修（N5）**：默認安裝 Release `v0.4.0` tarball 並驗 `.sha256` + 版本；`--from-git` 只作應急 | 可再加 minisign／固定 digest 白名單 |

### P2（環境與衛生）

| # | 風險 | 現況 | 建議 |
| :-- | :-- | :-- | :-- |
| R10 | Workers.dev 端點完全公開 | 冇 Access（要信用卡，已暫緩）；任何人可探測／DoS | 免費 WAF rate-limit rule；或自訂域名 + Access |
| R11 | 假 broker／MITM | 回應冇簽名；config `brokerUrl` 明文可改 | broker 回應簽名 + CLI 公鑰 pin；config 加 pin |
| R12 | 本機殘留 | **已修（N6）**：PEM 已搬 `~/Doubao/secrets/baobao2046.app.private-key.pem`（600，目錄 700），sha256 核對後刪原檔；master key 600。`.dev.vars` 仍留（600，本機開發用） | `.dev.vars` 可改由 Keychain／1Password CLI 注入 |
| R13 | 撤銷後仍可能短暫可用 | KV 一致性 + token 已 mint（最長 1 小時）| 文件講清楚：撤銷 = 停止**新** token，已發 token 自然到期 |
| R14 | 舊 `/github-token` endpoint | **已默認下架**：無 `LEGACY_BEARER_ENABLED=true` 一律 404；啟用時必須有 `LEGACY_REPOSITORIES` allowlist，否則 403 | 保留 opt-in 供 V1/V2 回歸；長期可完全刪碼 |

---

## 6. Outstanding／未證實（唔可以假設已成立）

| # | 項目 | 為何未證實 | 點樣才可以證實 |
| :-- | :-- | :-- | :-- |
| O1 | **生產 `/v1/claim` 從未成功實跑** | **已證實**（2026-11-27）：GitHub Actions runner 乾淨出口跑真 claim，`claim.prefix=ghs_`、`len=390`、`expires_at` 正常；run `45985666038` 14 步全 success | 重跑 `e2e-prod.yml` 或睇 `e2e-report.json` |
| O2 | 生產 registry agent 數目 | 現有 `opencode-01` + `ci-e2e-01`（claim 實跑用）；demo agent 只在本地 KV | `wrangler kv key list --remote --binding=BROKER_KV` |
| O3 | V4「token 到期」測試係 S5 舊 bearer flow 做的 | 新簽名 flow 未做過一小時等期測試 | 同一 agent 在 `expires_at+90s` 重打 → 應 401 |
| O4 | 多 agent 同機隔離 | 未實測兩個 agent 在同一部機互相 claim 對方 key | 本機建兩個 agent，交叉 claim → 應 403 |
| O5 | 換機／Keychain 遷移 | 未測 | 新機 `init` 新 id、或手動搬私鑰後 register |
| O6 | Cloudflare KV 一致性對撤銷／重放的實際影響 | 只有理論 | 用兩個地理位置打同一 nonce／撤銷後即 claim |
| O7 | **D1 audit 喺生產有冇真實寫入** | 已證實（N2+N4 批次實查 2 行 `kind=claim`）；N7 加 `machine_id` 後要再查一次 | `wrangler d1 execute broker-audit --remote --command "SELECT count(*) FROM audit"` |
| O8 | ~~Admin token 輪替未做過~~ | **作廢（N7）**：admin token 已撤出架構，冇嘢可輪替 | 確認 Cloudflare secrets 內已無 `AGENT_TOKEN*` |

---

## 7. Audit playbook（一輪完整審核）

**Phase 0 — 準備（15 分鐘）**
1. `git log --oneline` 記錄受審版本（commit SHA）——報告要寫明「審的是邊個 SHA」。
2. `broker --version`、`curl <worker>/health`、`npx wrangler secret list` 記錄環境事實。
3. 確認自己有冇 Cloudflare 帳號權限（wrangler 已登入）；冇就只做 agent 視角 + 本機測試。

**Phase 1 — 靜態審查（1–2 小時）**
1. 逐行讀 `worker/src/index.js`，對照第 5 節「驗證順序」，搵偏離（例如檢查次序、錯誤訊息內容、log 欄位）。
2. 讀 `src/index.ts`：私鑰流向、`--env`／`--print` 輸出、`exec` 子進程行為、config 寫入權限。
3. 掃 git 歷史：`git log -p | grep -E 'ghs_|BEGIN.*PRIVATE|AGENT_TOKEN='`（確認冇 secret 曾 commit）。
4. 檢查 `.gitignore` 覆蓋範圍（`.dev.vars`、`*.pem`、`*.base64.txt`）。

**Phase 2 — 本機動態測試（1–2 小時）**
1. `npx wrangler dev --local --port 8787`。
2. 跑第 8 節測試案例表（逐項記 HTTP status／CLI exit code）。
3. 每次測試後檢查 dev log：有冇 secret 值、有冇 stack trace 外露。

**Phase 3 — 生產（只讀）**
1. 只做 `GET /health` 同 `POST /v1/claim`（admin 端點應全部 404）。
2. 若網絡允許，用**自己**的 agent 做一次 `claim`（唔好用他人 id），記錄完整 HTTP status。
3. 唔好對生產做 fuzz／枚舉／壓測。

**Phase 4 — 報告**
1. 填第 3 節宣稱表 + 第 5 節風險表 + 你的新發現。
2. 每項附證據（指令 + 輸出片段；secret 值要遮罩）。
3. 給「最需要修嘅三件事」＋「可接受殘餘風險」。
4. 開 Linear issue（或 comment 在 NIN-193）交 developer；**唔要**自己改生產。

---

## 8. 攻擊面與測試案例（可直接照做）

| # | 測試 | 指令／方法 | 預期 |
| :-- | :-- | :-- | :-- |
| T1 | 未知 agent | `broker claim github --agent nobody-999` | 401，exit 3 |
| T2 | 錯簽名 | 改 body 內 `sig` 最後一字符再 POST | 401 |
| T3 | ts 過期 | `ts = now - 120` | 401 `stale_or_skewed_timestamp` |
| T4 | 重放 | 同一 nonce 連打兩次 | 第二次 409 `replay_detected` |
| T5 | 無 entitlement | claim 未授權 key | 403 `not_entitled` + `denied` |
| T6 | 靜態 secret 正常 | 已存 key claim | 200 + 正確值 |
| T7 | 撤銷 | `DELETE /v1/agents/:id` 後 claim | 401 |
| T8 | 管理 API 無 token | `curl /v1/agents` 無 header | 401 |
| T9 | Admin 面已消失 | 打 `/v1/agents`、`/v1/secrets/a/b`、`/v1/admin/audit`、`/github-token` | 全部 404，body 唔提任何內部路徑 |
| T10 | 枚舉防護 | 用 20 個不存在 id 打 claim | 全部 401 且 body 一致、無差異 |
| T11 | Log 洩漏 | 跑完所有測試後 grep dev log | 無 `ghs_`、無 secret 值、無 PEM |
| T12 | GitHub token 範圍 | `curl -H "Authorization: Bearer $GH_TOKEN" /installation/repositories` | 檢查 `total_count` 是否符合預期收窄 |
| T13 | 跨 agent 隔離 | agent A claim agent B 的 key | 403 |
| T14 | `exec` 子進程 | `broker exec --keys github -- sh -c 'env \| grep GH_TOKEN'` | 子進程有值；父 shell 冇 |
| T15 | 遮罩預設 | `broker claim github` | 只出 `sha256:… len=…` |
| T16 | 檔案權限 | `ls -l ~/.config/secret-broker/config.json`、Keychain 查詢 | config 600；私鑰只在 Keychain |
| T17 | 版本一致性 | `broker --version` vs repo `package.json` | 一致 |
| T18 | 安裝腳本 | 在臨時 prefix 跑 `scripts-bootstrap-install.sh` | 成功、無 tarball 殘留、無 token 入 argv |

---

## 9. 證據要求（缺一項就降級為「未證實」）

1. **受審版本**：commit SHA + CLI 版本 + Worker 版本 ID + 部署日期。
2. **環境**：作業系統、node 版本、是否本機 dev 抑或生產。
3. **方法**：完整可複製指令（secret 用 `<REDACTED>`）。
4. **原始輸出**：HTTP status + body（secret 遮罩）／CLI stderr／log 片段。
5. **判定**：PASS / PARTIAL / FAIL / 未證實，附理由。
6. **嚴重度**：P0／P1／P2，附「影響範圍」一句。

---

## 10. 唔准做嘅事

1. 唔好把生產 secret 值寫入報告、issue、commit、甚至本機檔案。
2. 唔好對生產做暴力枚舉、fuzz、壓測、DoS。
3. 唔好「為了證明有風險」而自行改生產設定或 registry。
4. 唔好把「文件有寫」當成證據；文件只係宣稱。
5. 唔好隱藏你未能驗證的項目；相反，明確列出。
6. 唔好把 audit 發現直接私訊繞過 issue 流程（要留痕）。

---

## 11. 你嘅 final deliverable（建議結構）

```
audit/<YYYY-MM-DD>/
  REPORT.md            # 兩張表 + 結論頁（粵語）
  evidence/            # 原始輸出、log（secret 已遮罩）
  SCOPE.md             # 你自設計的 audit scope（視角 A + 視角 B）
  RAISE.md             # 要開的 Linear issue 清單（標題、嚴重度、建議、負責階段）
```

`SCOPE.md` 要求：明確寫出
(1) 你打算證明邊 12 條宣稱、用咩方法；
(2) 你額外認為要審嘅 N 項，為何、如何測、邊啲只能推理；
(3) 你**唔會**審嘅範圍同原因（避免無限膨脹）。

---

## 12. 參考事實（2026-11-27 實測，可直接用作基線）

| 項目 | 值 |
| :-- | :-- |
| Worker 版本 | `82bbb354-7aa6-4516-807e-77f4dc24aad1`（2026-11-27 修復批次部署）|
| Worker URL | `https://github-token-broker.baobao2046.workers.dev` |
| KV namespace | `BROKER_KV` = `dd244113e11148c883325bc4d3cfde3c` |
| 生產 registry | 只有 `agent:opencode-01`（entitlements `github`，repo 限 `agent-playground`）|
| Cloudflare | account `f00aad142d5151b962fc5af7bcd88395`、subdomain `baobao2046` |
| GitHub App | App ID `5918124`、Installation `185701417`、`repository_selection = all` |
| CLI | `@nine-ai/secret-broker-cli` 0.4.0、repo `nine-ai-2046-1/agent-playground`（private）|
| 已知死路 | 本機／雲機／瀏覽器都連唔到 workers.dev；Access 需要信用卡 |

> 任何與上表不符嘅情況，**以實測為準**，並在報告標明差異。

---

## 13. 2026-11-27 修復批次（回應獨立 audit）

> 由 MainAgent 執行；每項附驗證方式。未修項留在上面風險表，唔會被此節「洗白」。

| # | audit 發現 | 修法 | 驗證 |
| :-- | :-- | :-- | :-- |
| F1 | 退出碼契約混亂（缺參數→1、無指令→0） | 新增 `usageDie()`：用法類錯誤一律 exit 2；無指令呼叫亦 exit 2 | 實測：無參 2、`init` 缺 `--agent` 2、未知指令 2 |
| F2 | `--admin-token`／`secret-put --value` 令 token 走 argv | 相關指令連同 token 概念一併刪除；secret 只經 stdin | `grep -i "admin-token\|secret-put" dist/index.js` 只餘「已撤出」提示 |
| F3 | plain-text 401/404 無 `Cache-Control: no-store` | `finish()` 統一補 header | 契約測試第 16 項：200/401/404/400 全部有 no-store |
| F4 | 舊 `/github-token` 仍可 mint 全範圍 token | 默認 404；opt-in 需 `LEGACY_BEARER_ENABLED=true` + `LEGACY_REPOSITORIES` allowlist，缺則 403；mint 帶 repositories | 契約測試第 14/15 項 |
| F5 | 契約測試腳本未入 repo | 新增 `worker/scripts/contract-test.mjs`（16 項、mock KV） | `node worker/scripts/contract-test.mjs` → 16/16 PASS |
| F6 | `prepare` 無 dist 守衛（文件同實作不符） | 改為 `test -f dist/index.js \|\| tsc \|\| true` | fresh clone `npm pack` 無 tsc 噪音 |
| F7 | TECH JWT 參數寫錯（-30s／+540s） | 改為 `-60s`／`+600s`（對齊 code） | 對照 `worker/src/index.js:13-14,81-82` |
| F8 | README 401 全稱措辭、缺 `GET /v1/agents/:id` | 收窄為「身份類錯誤」，補齊管理 API 表 | 對照 worker 路由 |
| F9 | 安裝範例令 token 入 shell history | 改用 `read -rsp` 提示輸入 | 文件審視 |

### 仍未修（需用戶／設定層動作）

| # | 項目 | 為何未修 | 下一步 |
| :-- | :-- | :-- | :-- |
| N1 | GitHub App installation = all（82 repo） | **用戶 2026-11-27 決定：唔改，接受風險**（已知 installation token 可及 82 repo；改動需 App 設定頁） | 已記錄為 accepted risk，不再跟進 |
| N2 | Admin token 單點、無 rotation／rate limit | ✅ **已消除（N7）**：admin API 全撤、共享 token 刪除、claim 限流保留 | 部署後確認 `/v1/admin/*` 404、secrets 內無 `AGENT_TOKEN*` |
| N3 | 靜態 secret 原文存 KV | ✅ **已修（2026-11-27）**：AES-256-GCM 信封加密（AAD 綁 agent+name），KV 只存 `{v,alg,iv,ct}`；未設 key 寫入 503（fail closed）；舊明文可讀；遷移改用 `scripts/secret-envelope.mjs`；契約測試 22/22 | 生產 `BROKER_MASTER_KEY` 已上（worker `540987ca`） |
| N4 | audit log 只 console.log | 需 D1／R2 或 Logpush | Roadmap 第 6 項 |
| N5 | CLI 安裝仍可跟 HEAD | ✅ **已修（2026-11-27）**：`scripts-bootstrap-install.sh` 預設走 release `v0.4.0` tarball，下載 `.sha256` 驗證後才 `npm i -g`，並核對 `broker --version` 同 tag 一致；`--from-git` 只在應急用；CI 每次跑都實測 release 安裝路徑 | 實測：private repo 嘅 `releases/download` URL 回 404，已改 API asset URL |
| N6 | 本機殘留 `.dev.vars`／`~/Downloads/*.pem` | ✅ **已完成（2026-11-27）**：App PEM（原 644）已搬去 `~/Doubao/secrets/baobao2046.app.private-key.pem`（600，目錄 700），sha256 核對後刪原檔；`.dev.vars` 600 只留本機 dev 用 | master key 亦存 `~/Doubao/secrets/broker-master-key.b64`（600） |

### 此批次的新基線

- CLI：`0.4.0`（未發布到任何 registry；由 repo tarball 安裝）
- Worker：已部署 `82bbb354-7aa6-4516-807e-77f4dc24aad1`（契約變更：no-store 全覆蓋、舊 endpoint 默認 404）
- 契約測試：16/16 PASS（本地 mock KV；生產仍未實跑，見 O1）

### F10 — 跨平台實測（Linux 雲主機，2026-11-27）

詳見 `audit/2026-11-27/VM-TEST.md`（22 項）。要點：

| 項 | 結果 |
| :-- | :-- |
| 契約測試（Linux） | 16/16 PASS |
| 退出碼契約（無參／缺參／未知指令／未知 flag） | 全部 exit **2** |
| 私鑰存放（非 macOS） | `~/.config/secret-broker/keys/<agent>.pkcs8`，600；目錄 700 |
| E2E（本地 wrangler dev `--local`，dummy secret） | init→register→secret-put(stdin)→claim(遮罩/`--print`/`--env`)→exec 注入，全通 |
| 反面 | 未授權 403 exit 4；重放 409；錯簽 401；舊 `/github-token` 404；管理 API 無 bearer 401 |
| audit log | 有 `result=ok/partial/not_entitled/failed/replay`，**secret 值 0 次出現** |
| 生產 E2E（雲機） | ❌ 出口 proxy→workers.dev 503（`remote_ip=199.193.116.105`），硬指 Cloudflare IP 亦 503 |

**Linux 新增低嚴重度（未修）**

| ID | 問題 | 建議 |
| :-- | :-- | :-- |
| L-1 | 單 key 全失敗回 **500**（`github_not_configured` 實為設定缺失） | 改 503，令 CLI／上層可分辨「設定缺失」vs「真故障」 |
| L-2 | `claim --print` 輸出係 JSON（同 `--json` 幾乎相同），非純值 | 文件寫清或改純值 |
| L-3 | ~~非 macOS `admin-login` 持久化~~ | **作廢（N7）**：`admin-login` 已刪 |

**仍未做的環境**：Lima VM 未安裝（本機冇 `limactl`；OrbStack daemon 未起）。雲主機已提供乾淨 Linux，故未重複搭建。

### F11 — 生產 E2E 收尾（GitHub Actions 乾淨出口，2026-11-27）

本機（Clash Verge／MuCloud TUN fake-IP）同雲主機（proxy）出口都被攔，故改用 GitHub runner 做生產 E2E：`.github/workflows/e2e-prod.yml`（12 steps，`workflow_dispatch` / `push main` / `cron 0 1 * * *`），CI agent `ci-e2e-01`（生產 KV 已登記，entitlements `github`，`installation_id=185701417`，`repositories=["agent-playground"]`）。

| 步 | 生產實測 | 結果 |
| :-- | :-- | :-- |
| 契約測試（mock KV） | 16/16 | PASS |
| 退出碼契約（無參／缺參／未知指令） | 全 2 | PASS |
| `GET /health` | 200，`ok=true`／`ed25519=true` | PASS |
| `POST /github-token`（未 opt-in） | 404 | PASS |
| `POST /v1/claim` 錯簽 | 401 | PASS |
| 真 claim（`BROKER_PRIVATE_KEY` env → 生產 mint） | rc=0，`secrets.github.token` = 真 `ghs_…`（len 390），`expires_at` +60min，`permissions` 全表回傳 | **PASS** |

run `45977991426`（commit `2d8c02d`）**success**；報告 `e2e-report.json` 已由 runner commit 回 main（`b949ef6`），內容只有 `prefix`／`len`／`expires_at`／`permissions`，**零 token 值**。

**修正**：初版斷言讀 `secrets.<key>.value`（實際回 `token`）→ 假 FAILURE；已改 `token or value` 兼容並保留 `len>=80` 檢查。

**已處理事故（token 外洩）**：

| 項 | 處理 |
| :-- | :-- |
| `e2e-report.json` 曾含真 `ghs_…` 並 commit | `filter-branch --index-filter` 清全 history、force push；遠端 main 已無任何含該檔嘅 commit（逐 commit `ls-tree` 驗證） |
| 含 token 嘅 run log | run `45977486051`／`45976193734`／`45976901143`／`45977148113` 已 `DELETE`（204，GET 回 404），log 已不存在 |
| 撤銷該 token | GitHub 無公開撤銷 installation token 端點（`DELETE /installation/tokens` 以 installation token／App JWT 皆 404）；該 token 於 `2026-11-27T10:53:51Z` 到期，實測 `401` 已失效 |
| 防止再犯 | workflow 改為只輸出 `prefix`／`len`／`expires_at`，token 明文只寫 `/tmp/claim.json` 並即時 `rm`，永不入 log／報告 |

**結論**：NIN-183「生產 E2E 做唔到」嘅阻塞已解除（唔再依賴本機／雲機出口）。仍未做：`github_not_configured` 應回 503（L-1）、`claim --print` 語意（L-2）。N2–N6 已完成，N7 已落地（待部署）。
