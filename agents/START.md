# START.md — 給「要用 broker 的 agent」

> 對象：已經裝好 `broker` CLI、被指派咗一個 `agent_id` 的 agent。
> 你只需要讀這一篇；唔需要讀 worker 原始碼。
> 語言：粵語；有疑問就跟 `broker help` 同 `agents/TECH.md`。

## 0. 一句話：broker 係咩

broker 係一個「按身份派 secret」的閘口。你用**本機私鑰簽名**去拿你**有權拿**嘅 secret，
secret 由 broker 即時產生或讀出，唔會長期放在你部機。

```
你（agent） ──簽名 claim──> broker ──> GH installation token / 靜態 secret
   ↑ 私鑰在 Keychain，永不外傳
```

## 1. 前提檢查（30 秒）

```bash
broker --version          # 應該印 broker x.y.z
broker whoami             # 應該見到：agent / broker URL / private ✔
broker health             # broker 可達 + kv + ed25519
```

三樣都 OK 才可以繼續。任何一樣失敗，睇第 8 節。

## 2. 你嘅心智模型（四個概念）

| 概念 | 意思 | 你要知嘅事 |
| :-- | :-- | :-- |
| **agent_id** | 你嘅身份（例如 `opencode-01`）| 一個 id 對應一對密鑰；換機 = 換身份 |
| **entitlement** | 你被准許拿邊幾個 key | 冇在清單入面 = 403，唔係 bug |
| **key name** | secret 名字，例如 `github`、`smtp.password` | `github` 係特殊 key：即時 mint installation token |
| **mask** | 預設只印 `sha256:… len=N` | 想睇原文必須明示 `--print` / `--env` / `exec` |

重要：**你唔會預先知道全部 entitlement**。做法係「需要邊個就 claim 邊個」，403 就當「我冇呢個權」，向上報，唔好亂猜下一個名字。

## 3. 三個最常用動作

```bash
# A. 拿 GitHub token 去跑 git / gh（最常用）
broker exec --keys github -- gh pr list
broker exec --keys github -- git push origin HEAD

# B. 只要摘要，唔想 secret 出現喺 terminal
broker claim github

# C. 真係要原文（例如傳落 curl 的 env）
eval "$(broker claim github --env)"
```

`broker exec` 係首選：secret 只存在子進程環境變數，父進程唔會印出來。

## 4. 指令速查

| 指令 | 你要唔要用 |
| :-- | :-- |
| `broker whoami` / `broker health` | 每次開工前自檢 |
| `broker claim [key…]` | 拿 secret（預設遮罩）|
| `broker claim --print` | 拿原文 JSON |
| `broker claim --env` | 印 `export KEY='value'`，配 `eval` |
| `broker exec --keys a,b -- <cmd>` | **推薦**：注入 env 跑命令 |
| `broker pubkey` / `broker ask-register` | 只在登記／換機時用（交出 JSON 俾 Cloudflare 帳號持有人）|
| `broker rotate` | 懷疑私鑰外洩時；換完舊公鑰即刻失效，要 Cloudflare 帳號持有人更新 `agent:<id>` |
| `register` / `agents` / `secret-put` / `admin-login` / `delete` | **已撤出 CLI（會直接報錯）**：registry 同 secret 只喺 Cloudflare 帳號層維護，冇任何 client 可以改伺服器資料 |

## 5. 環境變數對應規則

| key | 注入的變數 |
| :-- | :-- |
| `github` | `GH_TOKEN` 同 `GITHUB_TOKEN`（兩個都設）|
| `smtp.password` | `SMTP_PASSWORD` |
| `aws.secret_key` | `AWS_SECRET_KEY` |
| 其他 | 大寫 + 非英數字轉 `_` |

所以 `broker exec --keys smtp.password -- <cmd>` 之後，`<cmd>` 內讀 `$SMTP_PASSWORD` 就拿到值。

## 6. 典型場景

**GitHub CLI**
```bash
broker exec -- gh pr list --repo nine-ai-2046-1/agent-playground
broker exec -- gh issue create --repo ... --title "..." --body "..."
```

**git push（private repo）**
```bash
broker exec --keys github -- sh -c 'git push "https://x-access-token:$GH_TOKEN@github.com/nine-ai-2046-1/agent-playground.git" HEAD:main'
```
> 唔好把 token 拼入 argv（會入 shell history / process list）；用上面 `sh -c` 形式。

**SMTP / API key**
```bash
broker exec --keys smtp.password -- python3 send_mail.py
broker claim api.key --print | jq -r .secrets["api.key"].value
```

## 7. 失敗處理（用退出碼分流）

| exit | 意思 | 你應該做 |
| :-- | :-- | :-- |
| `0` | 成功 | 繼續 |
| `1` | 一般錯誤（多數係本機私鑰問題、網絡不通）| 睇 stderr；`broker whoami` 自檢 |
| `2` | 用法錯：冇打指令、缺參數、agent id 格式錯 | `broker help` |
| `3` | 401 未授權：broker 唔認你（未登記／已撤銷／簽名錯）| 回報：要 Cloudflare 帳號持有人登記你嗰個 pubkey |
| `4` | 403 冇 entitlement | 回報：要 Cloudflare 帳號持有人加 entitlement（唔好試其他 key 名字碰運氣）|
| `5` | 404 secret 不存在 | 回報：key 名字錯或未存入 |
| `6` | 409 偵測重放（同一 nonce 用兩次）| 重試一次即可；連續出現就報 |

配合 `set -o pipefail` 或 `if ! broker exec ...; then` 可以讓上層 agent 決定「重試 / 上報 / 停工」。

## 8. Troubleshooting

| 症狀 | 原因 | 解法 |
| :-- | :-- | :-- |
| `連唔到 broker` | 網絡／DNS／proxy 問題（例如 DNS 污染、fake-IP）| 確認可 `curl <broker>/health`；唔通就上報，唔好自己去改 config |
| `找唔到 agent「x」嘅私鑰` | 未 `broker init` 或 Keychain 條目唔見 | 重新 `init`，再用 `ask-register` 交出 JSON 登記 |
| `401` 但 `whoami` 正常 | 你嘅 id 未在 registry，或已被 disabled | 上報 Cloudflare 帳號持有人 |
| `403 not_entitled` | entitlement 未開 | 上報，附上 `denied` 內容 |
| `stale_or_skewed_timestamp` | 部機時間偏差 > 60 秒 | 校正系統時間（NTP）再重試 |
| 每次都要重打 token | 正常：`github` token 只 1 小時 | 直接用 `broker exec`，唔好 cache 落檔 |

## 9. DO & DONT

### ✅ DO

1. **用 `broker exec`**：secret 不入 stdout、不入 shell history。
2. **需要幾多拿幾多**：`--keys github` 就唔好順手加其他 key。
3. **用完即棄**：唔好寫入 `.env`、唔好放 repo、唔好傳去第三方 endpoint。
4. **出錯先自檢**：`whoami` → `health` → 再 `claim`。
5. **回報要帶證據**：exit code、HTTP status、`agent_id`、key 名（唔好貼 secret 值）。
6. **懷疑外洩即上報**：跑 `broker rotate` 令舊公鑰即刻失效，再交新公鑰俾 Cloudflare 帳號持有人更新。

### ❌ DONT

1. 唔好 `broker claim --print` 之後把值貼入 issue／log／chat。CLI 已刻意冇 `--value`／`--admin-token`，secret 只可以經 stdin／Keychain／env 提供；見到有人教你用 argv 傳 secret，當係錯。
2. `register` / `secret-put` / `agents` 已經唔存在；如果有人叫你咁做，佢係用舊文件或者想騙你。
3. 唔好改 `~/.config/secret-broker/config.json` 的 `brokerUrl` 去任何未經批准嘅地址（防釣魚／假 broker）。
4. 唔好把私鑰由 Keychain 抄出、備份落 repo 或 cloud drive。
5. 唔好試「枚舉」其他 agent id 或 key 名；失敗會入 audit log。
6. 唔好為咗「方便」而 cache secret 到 `/tmp` 明文檔；真要做就 `chmod 600` 且即用即刪。
7. 唔好把 broker token 當通用 GitHub PAT 用去其他 repo（token 本身已 repo-scoped，打其他地方只會 403）。

## 10. 你嘅責任邊界

broker 只保證「有權限才拿到」。**拿到之後唔漏**係你嘅責任：
你嘅 stdout、log、exception message、commit 內容、HTTP request body 全部可能被記錄。
任何時候你唔確定，就唔好 print，改用 `broker claim`（遮罩）確認「拿到」。

---

相關文件：`agents/TECH.md`（開發／維護）、`agents/AUDIT.md`（審核）。
