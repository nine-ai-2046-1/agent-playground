#!/usr/bin/env node
/**
 * broker — 全域 CLI，對接 per-agent Secret Broker（Ed25519 簽名 claim）
 *
 * 設計原則：
 *   1. 私鑰只在 Keychain（macOS）或 600 權限檔（Linux），永不經網絡傳出。
 *   2. claim 回來的 secret 預設只印遮罩摘要；要原文必須明示 --print / --env / exec。
 *   3. 每個 agent 一個身份，各自 entitlement，互不影響；撤銷只需刪 registry 一條。
 */

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const DEFAULT_BROKER_URL = "https://github-token-broker.baobao2046.workers.dev";
const CONFIG_DIR = path.join(os.homedir(), ".config", "secret-broker");
const CONFIG_FILE = path.join(CONFIG_DIR, "config.json");
const KEYS_DIR = path.join(CONFIG_DIR, "keys");
const ADMIN_KEYCHAIN_SERVICE = "secret-broker-admin";

// ---------------------------------------------------------------- utilities

function die(message: string, code = 1): never {
  console.error(`✖ ${message}`);
  process.exit(code);
}

/** 用法錯誤一律 exit 2（同 README／START 的退出碼契約一致） */
function usageDie(message: string): never {
  console.error(`✖ ${message}`);
  console.error("  用法：broker help");
  process.exit(2);
}

function parseFlags(argv: string[]) {
  const flags: Record<string, string | true> = {};
  const positional: string[] = [];
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
      } else {
        flags[name] = next;
        i += 1;
      }
    } else {
      positional.push(arg);
    }
  }
  return { flags, positional };
}

function flagString(flags: Record<string, string | true>, name: string): string | undefined {
  const value = flags[name];
  return typeof value === "string" ? value : undefined;
}

/** 讀取 CLI 自身版本：由執行檔位置往上找 package.json（dist/ 或 src/ 都成立） */
function readCliVersion(): string {
  try {
    const here = path.dirname(fs.realpathSync(process.argv[1] ?? __filename));
    for (const candidate of [
      path.join(here, "..", "package.json"),
      path.join(here, "package.json"),
      path.join(here, "..", "..", "package.json"),
    ]) {
      if (!fs.existsSync(candidate)) continue;
      const parsed = JSON.parse(fs.readFileSync(candidate, "utf8"));
      if (typeof parsed.version === "string") return parsed.version;
    }
  } catch (_) {
    /* ignore */
  }
  return "unknown";
}

// ------------------------------------------------------------------- config

interface Config {
  brokerUrl: string;
  agentId?: string;
}

function readConfig(): Config {
  let brokerUrl = DEFAULT_BROKER_URL;
  let agentId: string | undefined;
  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
    brokerUrl = String(raw.brokerUrl || DEFAULT_BROKER_URL);
    agentId = raw.agentId ? String(raw.agentId) : undefined;
  } catch {
    /* 未初始化：用預設 */
  }
  // 環境變數優先，方便 CI／staging／本機 dev 唔改 config 就切 broker
  if (process.env.BROKER_URL) brokerUrl = process.env.BROKER_URL;
  return { brokerUrl: brokerUrl.replace(/\/+$/, ""), agentId };
}

function writeConfig(config: Config) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(CONFIG_FILE, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
}

function resolveAgent(config: Config, flags: Record<string, string | true>): string {
  const agent = flagString(flags, "agent") || process.env.BROKER_AGENT_ID || config.agentId;
  if (!agent) usageDie("未指定 agent；先跑 `broker init --agent <id>` 或用 --agent 指定");
  return agent;
}

// ------------------------------------------------------------- key material

const isMac = process.platform === "darwin";

function keychainSave(agent: string, pkcs8Base64: string) {
  const res = spawnSync(
    "security",
    ["add-generic-password", "-U", "-s", `secret-broker-key:${agent}`, "-a", agent, "-w", pkcs8Base64],
    { encoding: "utf8" },
  );
  if (res.status !== 0) die(`Keychain 寫入失敗：${(res.stderr || "").trim()}`);
}

function keychainLoad(agent: string): string | null {
  const res = spawnSync("security", ["find-generic-password", "-s", `secret-broker-key:${agent}`, "-w"], {
    encoding: "utf8",
  });
  if (res.status !== 0) return null;
  return res.stdout.trim();
}

function fileKeyPath(agent: string) {
  return path.join(KEYS_DIR, `${agent}.pkcs8`);
}

function savePrivateKey(agent: string, pkcs8Base64: string) {
  if (isMac) {
    keychainSave(agent, pkcs8Base64);
    return "macOS Keychain";
  }
  fs.mkdirSync(KEYS_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(fileKeyPath(agent), `${pkcs8Base64}\n`, { mode: 0o600 });
  return fileKeyPath(agent);
}

/** CI／容器用：私鑰可由環境變數注入（base64 PKCS#8），永不落碟 */
function envPrivateKey(): string | null {
  const raw = process.env.BROKER_PRIVATE_KEY;
  if (!raw) return null;
  return raw.replace(/\s/g, "");
}

function loadPrivateKey(agent: string): crypto.KeyObject {
  const base64 = envPrivateKey() || (isMac ? keychainLoad(agent) : readFileQuiet(fileKeyPath(agent)));
  if (!base64) {
    die(`找唔到 agent「${agent}」嘅私鑰；先跑 \`broker init --agent ${agent}\`，或設 BROKER_PRIVATE_KEY（base64 PKCS#8）`);
  }
  return crypto.createPrivateKey({ key: Buffer.from(base64.replace(/\s/g, ""), "base64"), format: "der", type: "pkcs8" });
}

function readFileQuiet(file: string): string | null {
  try {
    return fs.readFileSync(file, "utf8").trim();
  } catch {
    return null;
  }
}

function generateKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pkcs8 = privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");
  const spki = publicKey.export({ type: "spki", format: "der" });
  const rawPublic = Buffer.from(spki.subarray(spki.length - 32)).toString("base64url");
  return { pkcs8, rawPublic };
}

function canonicalPayload(agentId: string, wants: string[], ts: number, nonce: string) {
  return `v1|${agentId}|${wants.join(",")}|${ts}|${nonce}`;
}

/** 由 Keychain 私鑰推導返 raw 公鑰（32 bytes base64url），用嚟 register／rotate */
function derivePublicKey(agentId: string): string {
  const privateKey = loadPrivateKey(agentId);
  const publicKey = crypto.createPublicKey(privateKey);
  const spki = publicKey.export({ type: "spki", format: "der" });
  return Buffer.from(spki.subarray(spki.length - 32)).toString("base64url");
}

function signPayload(agentId: string, wants: string[], ts: number, nonce: string): string {
  const key = loadPrivateKey(agentId);
  const payload = canonicalPayload(agentId, wants, ts, nonce);
  return crypto.sign(null, Buffer.from(payload), key).toString("base64url");
}

// ----------------------------------------------------------------- http api

async function callBroker<T>(
  config: Config,
  method: string,
  pathname: string,
  body?: unknown,
  adminToken?: string,
): Promise<{ status: number; json: T | null }> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (adminToken) headers.Authorization = `Bearer ${adminToken}`;
  let response: Response;
  try {
    response = await fetch(`${config.brokerUrl}${pathname}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(20000),
    });
  } catch (error) {
    die(`連唔到 broker（${config.brokerUrl}）：${(error as Error).message}`);
  }
  const text = await response.text();
  let json: T | null = null;
  try {
    json = text ? (JSON.parse(text) as T) : null;
  } catch {
    json = null;
  }
  return { status: response.status, json };
}

function adminToken(_flags: Record<string, string | true>): string {
  // 刻意唔接受 --admin-token：token 走 argv 會出現在 shell history 同 process list
  if (process.env.BROKER_ADMIN_TOKEN) return process.env.BROKER_ADMIN_TOKEN;
  if (isMac) {
    const res = spawnSync("security", ["find-generic-password", "-s", ADMIN_KEYCHAIN_SERVICE, "-w"], {
      encoding: "utf8",
    });
    if (res.status === 0 && res.stdout.trim()) return res.stdout.trim();
  }
  die("冇 admin token；設 BROKER_ADMIN_TOKEN（env）或先 `broker admin-login --token-stdin`");
}

// ---------------------------------------------------------------- env names

function envNameFor(secretKey: string): string[] {
  if (secretKey === "github") return ["GH_TOKEN", "GITHUB_TOKEN"];
  return [secretKey.replace(/[^A-Za-z0-9]+/g, "_").toUpperCase()];
}

function maskValue(value: unknown): string {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  if (!text) return "(empty)";
  const digest = crypto.createHash("sha256").update(text).digest("hex").slice(0, 8);
  return `sha256:${digest} len=${text.length}`;
}

// ----------------------------------------------------------------- commands

async function cmdHealth(config: Config) {
  const res = await callBroker<{ ok: boolean; version?: string; kv?: boolean }>(config, "GET", "/health");
  if (res.status !== 200) die(`health 失敗：HTTP ${res.status}`);
  console.log(`✔ ${config.brokerUrl}  ok=${res.json?.ok} version=${res.json?.version} kv=${res.json?.kv}`);
}

function cmdInit(flags: Record<string, string | true>) {
  const agentId = flagString(flags, "agent");
  if (!agentId) usageDie("用法：broker init --agent <id> [--broker-url <url>] [--force]");
  if (!/^[a-z0-9][a-z0-9._-]{1,47}$/.test(agentId)) usageDie("agent id 只可以用細寫英數、. _ -，2–48 字元");

  const config = readConfig();
  const brokerUrl = (flagString(flags, "broker-url") || config.brokerUrl).replace(/\/+$/, "");
  const existing = envPrivateKey() || (isMac ? keychainLoad(agentId) : readFileQuiet(fileKeyPath(agentId)));
  if (existing && !flags.force) die(`agent「${agentId}」已有私鑰；如要換新，加 --force（舊公鑰會即刻失效）`);

  const { pkcs8, rawPublic } = generateKeypair();
  const where = savePrivateKey(agentId, pkcs8);
  writeConfig({ brokerUrl, agentId });

  console.log(`✔ agent「${agentId}」身份已建立`);
  console.log(`  私鑰存放：${where}（永不經網絡傳出）`);
  console.log(`  公鑰（base64url，貼上 registry 用）：\n  ${rawPublic}`);
  console.log(`\n下一步（admin token 執行，登記公鑰）：`);
  console.log(
    `  broker register --agent ${agentId} --pubkey ${rawPublic} --entitlements github --installation-id 185701417\n`,
  );
}

function cmdWhoami(config: Config, flags: Record<string, string | true>) {
  const agent = resolveAgent(config, flags);
  const fromEnv = Boolean(envPrivateKey());
  const hasKey = fromEnv || (isMac ? Boolean(keychainLoad(agent)) : Boolean(readFileQuiet(fileKeyPath(agent))));
  console.log(`agent   : ${agent}`);
  console.log(`broker  : ${config.brokerUrl}`);
  const where = fromEnv ? "環境變數 BROKER_PRIVATE_KEY" : isMac ? "Keychain" : fileKeyPath(agent);
  console.log(`private : ${hasKey ? "✔ 已存在（" + where + "）" : "✖ 未建立"}`);
}

function cmdPubkey(config: Config, flags: Record<string, string | true>) {
  const agent = resolveAgent(config, flags);
  console.log(derivePublicKey(agent));
}

async function cmdRegister(config: Config, flags: Record<string, string | true>) {
  const agent =
    flagString(flags, "agent") || usageDie("用法：broker register --agent <id> [--pubkey <raw>] [--entitlements a,b]");
  const token = adminToken(flags);
  const pubkey = flagString(flags, "pubkey") || derivePublicKey(agent);

  let entitlements: string[];
  const entitlementsFlag = flagString(flags, "entitlements");
  if (entitlementsFlag) {
    entitlements = entitlementsFlag.split(",").map((s) => s.trim()).filter(Boolean);
  } else {
    const existing = await callBroker<{ agent: { entitlements?: string[] } }>(
      config,
      "GET",
      `/v1/agents/${agent}`,
      undefined,
      token,
    );
    entitlements = existing.status === 200 && Array.isArray(existing.json?.agent?.entitlements)
      ? existing.json!.agent.entitlements!
      : ["github"];
  }

  const github: Record<string, unknown> = {};
  const installation = flagString(flags, "installation-id");
  if (installation) github.installation_id = Number(installation);
  const repositories = flagString(flags, "repositories");
  if (repositories) github.repositories = repositories.split(",").map((s) => s.trim()).filter(Boolean);
  const permissions = flagString(flags, "permissions"); // e.g. contents=read,pull_requests=read
  if (permissions) {
    github.permissions = Object.fromEntries(
      permissions.split(",").map((pair) => pair.split("=").map((s) => s.trim()) as [string, string]),
    );
  }

  const body: Record<string, unknown> = { pubkey, entitlements };
  if (Object.keys(github).length > 0) body.github = github;
  if (flags["status"] === "disabled") body.status = "disabled";

  const res = await callBroker<{ agent: { id: string; entitlements: string[] } }>(
    config,
    "PUT",
    `/v1/agents/${agent}`,
    body,
    token,
  );
  if (res.status !== 201) die(`登記失敗：HTTP ${res.status} ${JSON.stringify(res.json)}`);
  console.log(`✔ 已登記 agent「${res.json?.agent.id}」，entitlements=${res.json?.agent.entitlements.join(",")}`);
}

async function cmdAgents(config: Config, flags: Record<string, string | true>) {
  const res = await callBroker<{ agents: Array<Record<string, unknown>> }>(
    config,
    "GET",
    "/v1/agents",
    undefined,
    adminToken(flags),
  );
  if (res.status !== 200) die(`讀取失敗：HTTP ${res.status}`);
  const agents = res.json?.agents || [];
  if (agents.length === 0) {
    console.log("(registry 未有 agent)");
    return;
  }
  for (const a of agents) {
    console.log(`- ${a.id}  [${a.status}]  entitlements=${(a.entitlements as string[]).join(",") || "-"}  pubkey=${a.pubkey}`);
  }
}

async function cmdSecretPut(config: Config, flags: Record<string, string | true>) {
  const agent = flagString(flags, "agent") || usageDie("用法：broker secret-put --agent <id> --name <key> （值由 stdin 讀）");
  const name = flagString(flags, "name") || usageDie("缺 --name");
  const rawInput = fs.readFileSync(0, "utf8"); // 值只經 stdin，禁止 --value（argv 會外洩）
  const value = rawInput.replace(/\n$/, "");
  if (!value) usageDie("值為空（值只可以經 stdin 提供）");
  const res = await callBroker<{ stored: unknown }>(
    config,
    "PUT",
    `/v1/secrets/${agent}/${name}`,
    { value },
    adminToken(flags),
  );
  if (res.status !== 201) die(`寫入失敗：HTTP ${res.status}`);
  console.log(`✔ 已存入 ${agent}/${name}（${maskValue(value)}）`);

  // --grant：自動把呢個 key 加入該 agent 嘅 entitlements（唔會覆蓋現有清單）
  if (flags.grant) {
    const token = adminToken(flags);
    const existing = await callBroker<{ agent: Record<string, unknown> & { pubkey?: string; entitlements?: string[] } }>(
      config,
      "GET",
      `/v1/agents/${agent}`,
      undefined,
      token,
    );
    if (existing.status !== 200 || !existing.json?.agent?.pubkey) {
      console.log(`⚠ 未加到 entitlement：registry 內冇 agent「${agent}」，先跑 broker register`);
      return;
    }
    const record = existing.json.agent;
    const entitlements = Array.from(new Set([...(record.entitlements || []), name]));
    const put = await callBroker(
      config,
      "PUT",
      `/v1/agents/${agent}`,
      { pubkey: record.pubkey, entitlements, github: record.github ?? null, status: record.status ?? "active" },
      token,
    );
    if (put.status !== 201) die(`加 entitlement 失敗：HTTP ${put.status}`);
    console.log(`✔ entitlement 已更新：${entitlements.join(",")}`);
  }
}

interface ClaimResponse {
  agent_id: string;
  secrets: Record<string, Record<string, unknown> & { value?: string }>;
  errors?: Array<{ key: string; error: string }>;
  expires_at?: string | null;
}

async function doClaim(config: Config, agent: string, wants: string[]): Promise<ClaimResponse> {
  const ts = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(16).toString("base64url");
  const sig = signPayload(agent, wants, ts, nonce);
  const res = await callBroker<ClaimResponse>(config, "POST", "/v1/claim", { agent_id: agent, wants, ts, nonce, sig });
  if (res.status !== 200 && res.status !== 207) {
    // 讓 agent 可以按退出碼分流：3 未授權 / 4 無權限 / 5 找不到 / 6 重放
    const code = ({ 401: 3, 403: 4, 404: 5, 409: 6 } as Record<number, number>)[res.status] ?? 1;
    die(`claim 失敗：HTTP ${res.status} ${JSON.stringify(res.json)}`, code);
  }
  return res.json as ClaimResponse;
}

async function cmdClaim(config: Config, flags: Record<string, string | true>, keys: string[]) {
  const agent = resolveAgent(config, flags);
  const wants = keys.length > 0 ? keys : ["github"];
  const result = await doClaim(config, agent, wants);

  if (flags.env) {
    for (const [key, value] of Object.entries(result.secrets)) {
      const names = envNameFor(key);
      const raw = value.token ?? value.value ?? "";
      for (const name of names) console.log(`export ${name}='${raw}'`);
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
    if (value.expires_at) console.log(`    expires_at: ${value.expires_at}`);
  }
  if (result.errors && result.errors.length > 0) {
    for (const e of result.errors) console.log(`  ! ${e.key}: ${e.error}`);
  }
  const keysText = wants.join(" ");
  console.log("\n要原文： broker claim " + keysText + " --print  |  --env  |  broker exec -- <cmd>");
}

async function cmdExec(config: Config, flags: Record<string, string | true>, command: string[]) {
  if (command.length === 0) usageDie("用法：broker exec [--keys github] -- <command...>");
  const agent = resolveAgent(config, flags);
  const keys = (flagString(flags, "keys") || "github").split(",").map((s) => s.trim()).filter(Boolean);
  const result = await doClaim(config, agent, keys);

  const env: Record<string, string> = { ...process.env } as Record<string, string>;
  for (const [key, value] of Object.entries(result.secrets)) {
    const raw = value.token ?? value.value ?? "";
    for (const name of envNameFor(key)) env[name] = String(raw);
  }
  const child = spawnSync(command[0], command.slice(1), { stdio: "inherit", env, shell: false });
  process.exit(child.status ?? 1);
}

function cmdRotate(config: Config, flags: Record<string, string | true>) {
  const agent = resolveAgent(config, flags);
  const { pkcs8, rawPublic } = generateKeypair();
  const where = savePrivateKey(agent, pkcs8);
  console.log(`✔ agent「${agent}」已換新 keypair（舊公鑰仍然有效直到 register 覆寫）`);
  console.log(`  新私鑰：${where}`);
  console.log(`  新公鑰：${rawPublic}`);
  console.log(`\n立即生效：`);
  console.log(`  broker register --agent ${agent} --pubkey ${rawPublic} --entitlements <維持原清單>`);
}

async function cmdAdminLogin(flags: Record<string, string | true>) {
  const token = flags["token-stdin"] ? fs.readFileSync(0, "utf8").trim() : flagString(flags, "token");
  if (!token) usageDie("用法：broker admin-login --token-stdin（由 stdin 讀 admin token）");
  if (isMac) {
    const res = spawnSync("security", ["add-generic-password", "-U", "-s", ADMIN_KEYCHAIN_SERVICE, "-a", "admin", "-w", token], {
      encoding: "utf8",
    });
    if (res.status !== 0) die(`Keychain 寫入失敗：${(res.stderr || "").trim()}`);
    console.log(`✔ admin token 已存入 Keychain（service=${ADMIN_KEYCHAIN_SERVICE}）`);
    return;
  }
  die("非 macOS：請用環境變數 BROKER_ADMIN_TOKEN");
}

function usage() {
  console.log(`broker — per-agent Secret Broker CLI (v${readCliVersion()})

用法:
  broker init --agent <id> [--broker-url <url>] [--force]      建立 agent 身份（Ed25519；macOS→Keychain，Linux→600 檔）
  broker whoami [--agent <id>]                                 顯示本機身份
  broker pubkey [--agent <id>]                                 由私鑰推導公鑰（register 用，唔需要抄）
  broker health                                                檢查 broker

  broker claim [key...] [--print|--env|--json] [--agent <id>]   取 secret（預設遮罩摘要）
  broker exec [--keys github] -- <command...>                  取 secret 後注入環境變數再跑命令

  broker register --agent <id> [--pubkey <raw>] [--entitlements a,b]   [admin] 登記 / 輪替公鑰
  broker agents                                                [admin] 列出 registry
  broker secret-put --agent <id> --name <key> [--grant]        [admin] 存靜態 secret（stdin 讀值；--grant 自動加 entitlement）
  broker admin-login --token-stdin                             [admin] 存 admin token 入 Keychain
  broker rotate [--agent <id>]                                 換 keypair（之後要 register 新公鑰）

環境變數:
  BROKER_PRIVATE_KEY   agent 私鑰（base64 PKCS#8；CI／容器用，優先於 Keychain／檔案）
  BROKER_ADMIN_TOKEN   admin token（否則讀 Keychain service ${ADMIN_KEYCHAIN_SERVICE}）
  BROKER_AGENT_ID      預設 agent id
  BROKER_URL           覆蓋 broker 網址（等同 init 時 --broker-url）

安全慣例:
  所有 secret 值只經 stdin／Keychain／env 提供；CLI 刻意唔接受 --value / --admin-token（argv 會外洩）。

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
      await cmdRegister(config, flags);
      return;
    case "agents":
      await cmdAgents(config, flags);
      return;
    case "secret-put":
      await cmdSecretPut(config, flags);
      return;
    case "admin-login":
      await cmdAdminLogin(flags);
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

main().catch((error) => die((error as Error).message));
