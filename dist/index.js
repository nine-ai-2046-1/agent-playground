#!/usr/bin/env node
"use strict";
/**
 * broker — 全域 CLI，對接 per-agent Secret Broker（Ed25519 簽名 claim）
 *
 * 設計原則：
 *   1. 私鑰只在 Keychain（macOS）或 600 權限檔（Linux），永不經網絡傳出。
 *   2. claim 回來的 secret 預設只印遮罩摘要；要原文必須明示 --print / --env / exec。
 *   3. 每個 agent 一個身份，各自 entitlement，互不影響；撤銷只需刪 registry 一條。
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_crypto_1 = __importDefault(require("node:crypto"));
const node_fs_1 = __importDefault(require("node:fs"));
const node_os_1 = __importDefault(require("node:os"));
const node_path_1 = __importDefault(require("node:path"));
const node_child_process_1 = require("node:child_process");
const DEFAULT_BROKER_URL = "https://github-token-broker.baobao2046.workers.dev";
const CONFIG_DIR = node_path_1.default.join(node_os_1.default.homedir(), ".config", "secret-broker");
const CONFIG_FILE = node_path_1.default.join(CONFIG_DIR, "config.json");
const KEYS_DIR = node_path_1.default.join(CONFIG_DIR, "keys");
// ---------------------------------------------------------------- utilities
function die(message, code = 1) {
    console.error(`✖ ${message}`);
    process.exit(code);
}
/** 用法錯誤一律 exit 2（同 README／START 的退出碼契約一致） */
function usageDie(message) {
    console.error(`✖ ${message}`);
    console.error("  用法：broker help");
    process.exit(2);
}
function parseFlags(argv) {
    const flags = {};
    const positional = [];
    for (let i = 0; i < argv.length; i += 1) {
        const arg = argv[i];
        if (arg === "--") {
            positional.push(...argv.slice(i + 1));
            break;
        }
        if (arg.startsWith("--")) {
            const name = arg.slice(2);
            const next = argv[i + 1];
            if (next === undefined || next.startsWith("--")) {
                flags[name] = true;
            }
            else {
                flags[name] = next;
                i += 1;
            }
        }
        else {
            positional.push(arg);
        }
    }
    return { flags, positional };
}
function flagString(flags, name) {
    const value = flags[name];
    return typeof value === "string" ? value : undefined;
}
/** 讀取 CLI 自身版本：由執行檔位置往上找 package.json（dist/ 或 src/ 都成立） */
function readCliVersion() {
    try {
        const here = node_path_1.default.dirname(node_fs_1.default.realpathSync(process.argv[1] ?? __filename));
        for (const candidate of [
            node_path_1.default.join(here, "..", "package.json"),
            node_path_1.default.join(here, "package.json"),
            node_path_1.default.join(here, "..", "..", "package.json"),
        ]) {
            if (!node_fs_1.default.existsSync(candidate))
                continue;
            const parsed = JSON.parse(node_fs_1.default.readFileSync(candidate, "utf8"));
            if (typeof parsed.version === "string")
                return parsed.version;
        }
    }
    catch (_) {
        /* ignore */
    }
    return "unknown";
}
function readConfig() {
    let brokerUrl = DEFAULT_BROKER_URL;
    let agentId;
    try {
        const raw = JSON.parse(node_fs_1.default.readFileSync(CONFIG_FILE, "utf8"));
        brokerUrl = String(raw.brokerUrl || DEFAULT_BROKER_URL);
        agentId = raw.agentId ? String(raw.agentId) : undefined;
    }
    catch {
        /* 未初始化：用預設 */
    }
    // 環境變數優先，方便 CI／staging／本機 dev 唔改 config 就切 broker
    if (process.env.BROKER_URL)
        brokerUrl = process.env.BROKER_URL;
    return { brokerUrl: brokerUrl.replace(/\/+$/, ""), agentId };
}
function writeConfig(config) {
    node_fs_1.default.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
    node_fs_1.default.writeFileSync(CONFIG_FILE, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
}
function resolveAgent(config, flags) {
    const agent = flagString(flags, "agent") || process.env.BROKER_AGENT_ID || config.agentId;
    if (!agent)
        usageDie("未指定 agent；先跑 `broker init --agent <id>` 或用 --agent 指定");
    return agent;
}
// ------------------------------------------------------------- key material
const isMac = process.platform === "darwin";
function keychainSave(agent, pkcs8Base64) {
    const res = (0, node_child_process_1.spawnSync)("security", ["add-generic-password", "-U", "-s", `secret-broker-key:${agent}`, "-a", agent, "-w", pkcs8Base64], { encoding: "utf8" });
    if (res.status !== 0)
        die(`Keychain 寫入失敗：${(res.stderr || "").trim()}`);
}
function keychainLoad(agent) {
    const res = (0, node_child_process_1.spawnSync)("security", ["find-generic-password", "-s", `secret-broker-key:${agent}`, "-w"], {
        encoding: "utf8",
    });
    if (res.status !== 0)
        return null;
    return res.stdout.trim();
}
function fileKeyPath(agent) {
    return node_path_1.default.join(KEYS_DIR, `${agent}.pkcs8`);
}
function savePrivateKey(agent, pkcs8Base64) {
    if (isMac) {
        keychainSave(agent, pkcs8Base64);
        return "macOS Keychain";
    }
    node_fs_1.default.mkdirSync(KEYS_DIR, { recursive: true, mode: 0o700 });
    node_fs_1.default.writeFileSync(fileKeyPath(agent), `${pkcs8Base64}\n`, { mode: 0o600 });
    return fileKeyPath(agent);
}
/** CI／容器用：私鑰可由環境變數注入（base64 PKCS#8），永不落碟 */
function envPrivateKey() {
    const raw = process.env.BROKER_PRIVATE_KEY;
    if (!raw)
        return null;
    return raw.replace(/\s/g, "");
}
function loadPrivateKey(agent) {
    const base64 = envPrivateKey() || (isMac ? keychainLoad(agent) : readFileQuiet(fileKeyPath(agent)));
    if (!base64) {
        die(`找唔到 agent「${agent}」嘅私鑰；先跑 \`broker init --agent ${agent}\`，或設 BROKER_PRIVATE_KEY（base64 PKCS#8）`);
    }
    return node_crypto_1.default.createPrivateKey({ key: Buffer.from(base64.replace(/\s/g, ""), "base64"), format: "der", type: "pkcs8" });
}
function readFileQuiet(file) {
    try {
        return node_fs_1.default.readFileSync(file, "utf8").trim();
    }
    catch {
        return null;
    }
}
function generateKeypair() {
    const { publicKey, privateKey } = node_crypto_1.default.generateKeyPairSync("ed25519");
    const pkcs8 = privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");
    const spki = publicKey.export({ type: "spki", format: "der" });
    const rawPublic = Buffer.from(spki.subarray(spki.length - 32)).toString("base64url");
    return { pkcs8, rawPublic };
}
function canonicalPayload(agentId, wants, ts, nonce) {
    return `v1|${agentId}|${wants.join(",")}|${ts}|${nonce}`;
}
/** 由 Keychain 私鑰推導返 raw 公鑰（32 bytes base64url），用嚟 register／rotate */
function derivePublicKey(agentId) {
    const privateKey = loadPrivateKey(agentId);
    const publicKey = node_crypto_1.default.createPublicKey(privateKey);
    const spki = publicKey.export({ type: "spki", format: "der" });
    return Buffer.from(spki.subarray(spki.length - 32)).toString("base64url");
}
function signPayload(agentId, wants, ts, nonce) {
    const key = loadPrivateKey(agentId);
    const payload = canonicalPayload(agentId, wants, ts, nonce);
    return node_crypto_1.default.sign(null, Buffer.from(payload), key).toString("base64url");
}
// ----------------------------------------------------------------- http api
/** 本機機械指紋：硬件 UUID → SHA-256 前 16 hex（只送指紋，永不送原值） */
let cachedMachine = null;
function machineFingerprint() {
    if (cachedMachine)
        return cachedMachine;
    let source = "";
    if (isMac) {
        const res = (0, node_child_process_1.spawnSync)("ioreg", ["-d2", "-c", "IOPlatformExpertDevice"], { encoding: "utf8" });
        const m = (res.stdout || "").match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/);
        if (m)
            source = m[1];
    }
    else {
        try {
            source = node_fs_1.default.readFileSync("/etc/machine-id", "utf8").trim();
        }
        catch {
            /* ignore */
        }
    }
    if (!source)
        source = `${node_os_1.default.hostname()}:${node_os_1.default.userInfo().username}`;
    cachedMachine = node_crypto_1.default.createHash("sha256").update(source).digest("hex").slice(0, 16);
    return cachedMachine;
}
async function callBroker(config, method, pathname, body) {
    const headers = {
        "Content-Type": "application/json",
        "X-Broker-Machine": machineFingerprint(),
        "X-Broker-Client": `broker-cli/${readCliVersion()}`,
    };
    let response;
    try {
        response = await fetch(`${config.brokerUrl}${pathname}`, {
            method,
            headers,
            body: body === undefined ? undefined : JSON.stringify(body),
            signal: AbortSignal.timeout(20000),
        });
    }
    catch (error) {
        die(`連唔到 broker（${config.brokerUrl}）：${error.message}`);
    }
    const text = await response.text();
    let json = null;
    try {
        json = text ? JSON.parse(text) : null;
    }
    catch {
        json = null;
    }
    return { status: response.status, json };
}
// ---------------------------------------------------------------- env names
function envNameFor(secretKey) {
    if (secretKey === "github")
        return ["GH_TOKEN", "GITHUB_TOKEN"];
    return [secretKey.replace(/[^A-Za-z0-9]+/g, "_").toUpperCase()];
}
function maskValue(value) {
    const text = typeof value === "string" ? value : JSON.stringify(value);
    if (!text)
        return "(empty)";
    const digest = node_crypto_1.default.createHash("sha256").update(text).digest("hex").slice(0, 8);
    return `sha256:${digest} len=${text.length}`;
}
// ----------------------------------------------------------------- commands
async function cmdHealth(config) {
    const res = await callBroker(config, "GET", "/health");
    if (res.status !== 200)
        die(`health 失敗：HTTP ${res.status}`);
    console.log(`✔ ${config.brokerUrl}  ok=${res.json?.ok} version=${res.json?.version} kv=${res.json?.kv}`);
}
function cmdInit(flags) {
    const agentId = flagString(flags, "agent");
    if (!agentId)
        usageDie("用法：broker init --agent <id> [--broker-url <url>] [--force]");
    if (!/^[a-z0-9][a-z0-9._-]{1,47}$/.test(agentId))
        usageDie("agent id 只可以用細寫英數、. _ -，2–48 字元");
    const config = readConfig();
    const brokerUrl = (flagString(flags, "broker-url") || config.brokerUrl).replace(/\/+$/, "");
    const existing = envPrivateKey() || (isMac ? keychainLoad(agentId) : readFileQuiet(fileKeyPath(agentId)));
    if (existing && !flags.force)
        die(`agent「${agentId}」已有私鑰；如要換新，加 --force（舊公鑰會即刻失效）`);
    const { pkcs8, rawPublic } = generateKeypair();
    const where = savePrivateKey(agentId, pkcs8);
    writeConfig({ brokerUrl, agentId });
    console.log(`✔ agent「${agentId}」身份已建立`);
    console.log(`  私鑰存放：${where}（永不經網絡傳出）`);
    console.log(`  公鑰（base64url，貼上 registry 用）：\n  ${rawPublic}`);
    console.log(`\n下一步（admin token 執行，登記公鑰）：`);
    console.log(`  broker register --agent ${agentId} --pubkey ${rawPublic} --entitlements github --installation-id 185701417\n`);
}
function cmdWhoami(config, flags) {
    const agent = resolveAgent(config, flags);
    const fromEnv = Boolean(envPrivateKey());
    const hasKey = fromEnv || (isMac ? Boolean(keychainLoad(agent)) : Boolean(readFileQuiet(fileKeyPath(agent))));
    console.log(`agent   : ${agent}`);
    console.log(`broker  : ${config.brokerUrl}`);
    const where = fromEnv ? "環境變數 BROKER_PRIVATE_KEY" : isMac ? "Keychain" : fileKeyPath(agent);
    console.log(`private : ${hasKey ? "✔ 已存在（" + where + "）" : "✖ 未建立"}`);
}
function cmdPubkey(config, flags) {
    const agent = resolveAgent(config, flags);
    console.log(derivePublicKey(agent));
}
async function doClaim(config, agent, wants) {
    const ts = Math.floor(Date.now() / 1000);
    const nonce = node_crypto_1.default.randomBytes(16).toString("base64url");
    const sig = signPayload(agent, wants, ts, nonce);
    const res = await callBroker(config, "POST", "/v1/claim", { agent_id: agent, wants, ts, nonce, sig });
    if (res.status !== 200 && res.status !== 207) {
        // 讓 agent 可以按退出碼分流：3 未授權 / 4 無權限 / 5 找不到 / 6 重放
        const code = { 401: 3, 403: 4, 404: 5, 409: 6 }[res.status] ?? 1;
        die(`claim 失敗：HTTP ${res.status} ${JSON.stringify(res.json)}`, code);
    }
    return res.json;
}
async function cmdClaim(config, flags, keys) {
    const agent = resolveAgent(config, flags);
    const wants = keys.length > 0 ? keys : ["github"];
    const result = await doClaim(config, agent, wants);
    if (flags.env) {
        for (const [key, value] of Object.entries(result.secrets)) {
            const names = envNameFor(key);
            const raw = value.token ?? value.value ?? "";
            for (const name of names)
                console.log(`export ${name}='${raw}'`);
        }
        return;
    }
    if (flags.json || flags.print) {
        console.log(JSON.stringify(result, null, 2));
        return;
    }
    console.log(`✔ ${result.agent_id} claimed: ${Object.keys(result.secrets).join(", ")}`);
    for (const [key, value] of Object.entries(result.secrets)) {
        const type = value.token ? "token" : value.value ? "static" : "object";
        console.log(`  - ${key}  [${type}]  ${value.token ? maskValue(value.token) : maskValue(value.value ?? JSON.stringify(value))}`);
        if (value.expires_at)
            console.log(`    expires_at: ${value.expires_at}`);
    }
    if (result.errors && result.errors.length > 0) {
        for (const e of result.errors)
            console.log(`  ! ${e.key}: ${e.error}`);
    }
    const keysText = wants.join(" ");
    console.log("\n要原文： broker claim " + keysText + " --print  |  --env  |  broker exec -- <cmd>");
}
async function cmdExec(config, flags, command) {
    if (command.length === 0)
        usageDie("用法：broker exec [--keys github] -- <command...>");
    const agent = resolveAgent(config, flags);
    const keys = (flagString(flags, "keys") || "github").split(",").map((s) => s.trim()).filter(Boolean);
    const result = await doClaim(config, agent, keys);
    const env = { ...process.env };
    for (const [key, value] of Object.entries(result.secrets)) {
        const raw = value.token ?? value.value ?? "";
        for (const name of envNameFor(key))
            env[name] = String(raw);
    }
    const child = (0, node_child_process_1.spawnSync)(command[0], command.slice(1), { stdio: "inherit", env, shell: false });
    process.exit(child.status ?? 1);
}
function cmdRotate(config, flags) {
    const agent = resolveAgent(config, flags);
    const { pkcs8, rawPublic } = generateKeypair();
    const where = savePrivateKey(agent, pkcs8);
    console.log(`✔ agent「${agent}」已換新 keypair（舊公鑰仍然有效直到 register 覆寫）`);
    console.log(`  新私鑰：${where}`);
    console.log(`  新公鑰：${rawPublic}`);
    console.log(`\n立即生效：`);
    console.log(`  broker register --agent ${agent} --pubkey ${rawPublic} --entitlements <維持原清單>`);
}
function usage() {
    console.log(`broker — per-agent Secret Broker CLI (v${readCliVersion()})

用法:
  broker init --agent <id> [--broker-url <url>] [--force]      建立 agent 身份（Ed25519；macOS→Keychain，Linux→600 檔）
  broker ask-register [--agent <id>]                          印出「要喺 Cloudflare 寫入嘅 agent JSON」
  broker whoami [--agent <id>]                                 顯示本機身份
  broker pubkey [--agent <id>]                                 由私鑰推導公鑰（register 用，唔需要抄）
  broker health                                                檢查 broker

  broker claim [key...] [--print|--env|--json] [--agent <id>]   取 secret（預設遮罩摘要）
  broker exec [--keys github] -- <command...>                  取 secret 後注入環境變數再跑命令

  broker rotate [--agent <id>]                                 換 keypair（舊公鑰即刻失效）

環境變數:
  BROKER_PRIVATE_KEY   agent 私鑰（base64 PKCS#8；CI／容器用，優先於 Keychain／檔案）
  BROKER_AGENT_ID      預設 agent id
  BROKER_URL           覆蓋 broker 網址（等同 init 時 --broker-url）

安全慣例:
  私鑰只經 Keychain／600 檔／BROKER_PRIVATE_KEY 提供，永不經網絡傳出。
  本 CLI 冇 admin 功能：registry／secret 一律喺 Cloudflare 帳號層維護，所以 CLI 原始碼可以公開發佈。

慣例:
  github  → GH_TOKEN / GITHUB_TOKEN
  其他     → 大寫、非英數轉底線（smtp.password → SMTP_PASSWORD）

其他:
  broker version | --version | -v    印出版本
  broker help | --help | -h          印出本說明

文件:
  agents/START.md   給要用 broker 的 agent（安裝後點用、DO & DONT）
  agents/TECH.md    給接手開發的 agent（架構、契約、playbook）
  agents/AUDIT.md   給 audit agent（宣稱、風險、待辦、audit scope 設計）

退出碼:
  0 成功 ／ 1 執行錯誤 ／ 2 用法錯誤
  claim 專用：3 未授權(401) ／ 4 無 entitlement(403) ／ 5 secret 不存在(404) ／ 6 偵測重放(409)
`);
}
// -------------------------------------------------------------------- entry
async function main() {
    const argv = process.argv.slice(2);
    const cmd = argv[0];
    const { flags, positional } = parseFlags(argv.slice(1));
    const config = readConfig();
    switch (cmd) {
        case "init":
            cmdInit(flags);
            return;
        case "whoami":
            cmdWhoami(config, flags);
            return;
        case "pubkey":
            cmdPubkey(config, flags);
            return;
        case "health":
            await cmdHealth(config);
            return;
        case "claim":
            await cmdClaim(config, flags, positional);
            return;
        case "exec":
            await cmdExec(config, flags, positional);
            return;
        case "register":
        case "agents":
        case "secret-put":
        case "admin-login":
        case "delete":
            usageDie("admin 指令已撤出 CLI：registry／secret 只喺 Cloudflare Dashboard 或 wrangler 維護（見 README「註冊與管理」）");
            return;
        case "rotate":
            cmdRotate(config, flags);
            return;
        case "version":
        case "--version":
        case "-v":
            console.log(`broker ${readCliVersion()}`);
            return;
        case "help":
        case "--help":
        case "-h":
            usage();
            return;
        case undefined:
            usage();
            process.exit(2);
        default:
            console.error(`未知指令：${cmd}`);
            usage();
            process.exit(2);
    }
}
main().catch((error) => die(error.message));
