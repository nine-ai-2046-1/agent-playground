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

const ENDPOINT_FILE_NAME = "endpoint";
const CONFIG_DIR = path.join(os.homedir(), ".config", "secret-broker");
const CONFIG_FILE = path.join(CONFIG_DIR, "config.json");
const KEYS_DIR = path.join(CONFIG_DIR, "keys");

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

/** endpoint 係「部機層級」設定：任何 folder 行 CLI 都讀同一個檔（600） */
const ENDPOINT_FILE = path.join(CONFIG_DIR, ENDPOINT_FILE_NAME);

function readEndpointFile(): string {
  try {
    return fs.readFileSync(ENDPOINT_FILE, "utf8").trim();
  } catch {
    return "";
  }
}

function writeEndpointFile(rawUrl: string) {
  const url = normalizeEndpoint(rawUrl);
  fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(ENDPOINT_FILE, `${url}\n`, { mode: 0o600 });
}

function normalizeEndpoint(rawUrl: string): string {
  const url = String(rawUrl || "").trim().replace(/\/+$/, "");
  if (!url) die("endpoint 唔可以空白", 2);
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    die(`endpoint 唔係合法 URL：${url}`, 2);
  }
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && /^(localhost|127\.0\.0\.1)$/.test(parsed.hostname))) {
    die("endpoint 一定要 https（只有 localhost 可以用 http）", 2);
  }
  if (parsed.search || parsed.hash || parsed.username || parsed.password) die("endpoint 唔可以有 query／hash／帳密", 2);
  return parsed.origin + parsed.pathname.replace(/\/+$/, "");
}

function readConfig(): Config {
  let agentId: string | undefined;
  let legacyUrl = "";
  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
    legacyUrl = raw.brokerUrl ? String(raw.brokerUrl) : "";
    agentId = raw.agentId ? String(raw.agentId) : undefined;
  } catch {
    /* 未初始化 */
  }
  const stored = readEndpointFile();
  // 一次性遷移：舊版把 URL 寫死在 config.json → 搬去 endpoint 檔，之後 config 只存 agentId
  if (!stored && legacyUrl) {
    try {
      writeEndpointFile(legacyUrl);
    } catch {
      /* 遷移失敗唔阻住，下面照用 legacyUrl */
    }
  }
  // 優先次序：環境變數（CI／臨時） > 機器層級 endpoint 檔 > 舊 config
  const brokerUrl = (process.env.BROKER_URL || stored || legacyUrl || "").replace(/\/+$/, "");
  return { brokerUrl, agentId };
}

function writeConfig(config: Config) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(CONFIG_FILE, `${JSON.stringify({ agentId: config.agentId }, null, 2)}\n`, { mode: 0o600 });
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

/**
 * 由同一條 Ed25519 私鑰確定性衍生 X25519 keypair（libsodium 同款做法）。
 * 好處：唔需要新 storage／新 key 檔，舊 agent 即刻有；公鑰可以公開貼上 registry。
 */
function x25519FromEd25519(agent: string): { privateKey: crypto.KeyObject; pubB64u: string } {
  const ed = loadPrivateKey(agent);
  const jwk = ed.export({ format: "jwk" }) as { d?: string };
  if (!jwk.d) throw new Error("ed25519_export_failed");
  const digest = crypto.createHash("sha512").update(Buffer.from(jwk.d, "base64url")).digest();
  const scalar = Buffer.from(digest.subarray(0, 32));
  scalar[0] &= 248;
  scalar[31] &= 127;
  scalar[31] |= 64;
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([X_PKCS8_PREFIX, scalar]),
    format: "der",
    type: "pkcs8",
  });
  const spki = crypto.createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return { privateKey, pubB64u: Buffer.from(spki.subarray(spki.length - 32)).toString("base64url") };
}

/* X25519 raw key 嘅 DER 前綴（RFC 8410）：PKCS#8 私有 / SPKI 公開 */
const X_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const X_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

function encPubkeyFor(agent: string): string {
  return x25519FromEd25519(agent).pubB64u;
}

/** 解開 v2 密封信封（X25519 ECDH → HKDF → AES-256-GCM；AAD 綁 agent+name） */
function openSealed(agent: string, name: string, envelope: string): string {
  let env: { v?: number; alg?: string; epk?: string; iv?: string; ct?: string };
  try {
    env = JSON.parse(envelope);
  } catch {
    die(`secret「${name}」信封格式壞咗（唔係 JSON）`, 1);
  }
  if (!env || env.v !== 2 || env.alg !== "X25519-A256GCM" || !env.epk || !env.iv || !env.ct) {
    die(`secret「${name}」唔係 v2 密封信封（可能係舊格式，需要重新 seal）`, 1);
  }
  const { privateKey } = x25519FromEd25519(agent);
  const eph = crypto.createPublicKey({
    key: Buffer.concat([X_SPKI_PREFIX, Buffer.from(String(env.epk), "base64url")]),
    format: "der",
    type: "spki",
  });
  const shared = crypto.diffieHellman({ privateKey, publicKey: eph });
  const key = Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.from(`broker|${agent}|${name}`), Buffer.from("secret-broker-v2"), 32));
  const raw = Buffer.from(String(env.ct), "base64url");
  const tag = raw.subarray(raw.length - 16);
  const body = raw.subarray(0, raw.length - 16);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(String(env.iv), "base64url"));
  decipher.setAAD(Buffer.from(`sec|${agent}|${name}`));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]).toString("utf8");
}

/** claim 回應內 sealed 欄位 → 本機解密成 value（Worker 由頭到尾冇明文） */
function hydrateSealedSecrets(agent: string, response: ClaimResponse): void {
  for (const [name, entry] of Object.entries(response.secrets || {})) {
    if (entry && typeof (entry as { sealed?: unknown }).sealed === "string") {
      const sealed = String((entry as { sealed: string }).sealed);
      (entry as Record<string, unknown>).value = openSealed(agent, name, sealed);
      delete (entry as Record<string, unknown>).sealed;
      (entry as Record<string, unknown>).encrypted = true;
      (entry as Record<string, unknown>).e2e = true;
    }
  }
}

function signPayload(agentId: string, wants: string[], ts: number, nonce: string): string {
  const key = loadPrivateKey(agentId);
  const payload = canonicalPayload(agentId, wants, ts, nonce);
  return crypto.sign(null, Buffer.from(payload), key).toString("base64url");
}

// ----------------------------------------------------------------- http api

/** 本機機械指紋：硬件 UUID → SHA-256 前 16 hex（只送指紋，永不送原值） */
let cachedMachine: string | null = null;
function machineFingerprint(): string {
  if (cachedMachine) return cachedMachine;
  let source = "";
  if (isMac) {
    const res = spawnSync("ioreg", ["-d2", "-c", "IOPlatformExpertDevice"], { encoding: "utf8" });
    const m = (res.stdout || "").match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/);
    if (m) source = m[1];
  } else {
    try {
      source = fs.readFileSync("/etc/machine-id", "utf8").trim();
    } catch {
      /* ignore */
    }
  }
  if (!source) source = `${os.hostname()}:${os.userInfo().username}`;
  cachedMachine = crypto.createHash("sha256").update(source).digest("hex").slice(0, 16);
  return cachedMachine;
}

async function callBroker<T>(
  config: Config,
  method: string,
  pathname: string,
  body?: unknown,
): Promise<{ status: number; json: T | null }> {
  if (!config.brokerUrl) {
    die(
      "未設定 broker endpoint（默認冇 endpoint，唔會偷偷連任何網址）。\n  先設定一次（部機層級，任何 folder 通用）：\n    broker endpoint set https://<worker>.workers.dev\n  或臨時：export BROKER_URL=https://<worker>.workers.dev",
      2,
    );
  }
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Broker-Machine": machineFingerprint(),
    "X-Broker-Client": `broker-cli/${readCliVersion()}`,
  };
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
  const flagUrl = flagString(flags, "broker-url");
  if (flagUrl) writeEndpointFile(flagUrl);
  const brokerUrl = readConfig().brokerUrl;
  const existing = envPrivateKey() || (isMac ? keychainLoad(agentId) : readFileQuiet(fileKeyPath(agentId)));
  if (existing && !flags.force) die(`agent「${agentId}」已有私鑰；如要換新，加 --force（舊公鑰會即刻失效）`);

  const { pkcs8, rawPublic } = generateKeypair();
  const where = savePrivateKey(agentId, pkcs8);
  writeConfig({ brokerUrl, agentId });

  console.log(`✔ agent「${agentId}」身份已建立`);
  console.log(`  私鑰存放：${where}（永不經網絡傳出）`);
  console.log(`  簽名公鑰（貼上 registry）：\n  ${rawPublic}`);
  console.log(`  密封公鑰（貼上 registry，用嚟加密 secret）：\n  ${encPubkeyFor(agentId)}`);
  if (!brokerUrl) {
    console.log(`\n⚠ 未設定 broker endpoint（默認冇 endpoint，唔會偷偷連任何網址）`);
    console.log(`  先設定一次（部機層級，任何 folder 通用）：`);
    console.log(`    broker endpoint set https://<worker>.workers.dev`);
  } else {
    console.log(`\nendpoint：${brokerUrl}`);
  }
  console.log(`\n下一步（Cloudflare 帳號持有人登記）：`);
  console.log(`  broker ask-register --agent ${agentId} --entitlements github --installation-id <id>`);
  console.log(`  跟住照印出嘅 wrangler 指令寫入 KV（CLI 本身冇寫入能力）\n`);
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

function cmdEndpoint(config: Config, flags: Record<string, string | true>, args: string[]) {
  const action = args[0] || "show";
  if (action === "show") {
    const url = process.env.BROKER_URL || readEndpointFile();
    console.log(`endpoint : ${url || "(未設定)"}`);
    console.log(`來源     : ${process.env.BROKER_URL ? "環境變數 BROKER_URL" : readEndpointFile() ? ENDPOINT_FILE : "無"}`);
    return;
  }
  if (action === "set") {
    const url = args[1] || flagString(flags, "url");
    if (!url) usageDie("用法：broker endpoint set <https://...>");
    writeEndpointFile(url);
    console.log(`✔ endpoint 已設定（部機層級，任何 folder 通用）：${normalizeEndpoint(url)}`);
    console.log(`  檔案：${ENDPOINT_FILE}（600）`);
    return;
  }
  if (action === "clear") {
    try {
      fs.unlinkSync(ENDPOINT_FILE);
      console.log("✔ endpoint 已清除（之後所有 command 會要求重新設定）");
    } catch {
      console.log("（本來就冇設定）");
    }
    return;
  }
  usageDie("用法：broker endpoint show | set <url> | clear");
}

function cmdEncPubkey(config: Config, flags: Record<string, string | true>) {
  const agent = resolveAgent(config, flags);
  console.log(encPubkeyFor(agent));
}

function cmdPubkey(config: Config, flags: Record<string, string | true>) {
  const agent = resolveAgent(config, flags);
  console.log(derivePublicKey(agent));
}

interface ClaimResponse {
  agent_id: string;
  secrets: Record<string, Record<string, unknown> & { value?: string; sealed?: string }>;
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
  hydrateSealedSecrets(agent, result);

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
  hydrateSealedSecrets(agent, result);

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
  console.log(`✔ agent「${agent}」已換新 keypair`);
  console.log(`  注意：舊公鑰由呢刻起失效，未更新 Cloudflare 之前 claim 會一直 401`);
  console.log(`  新私鑰：${where}`);
  console.log(`  新公鑰：${rawPublic}`);
  console.log(`\n下一步（人手喺 Cloudflare 改 agent:${agent} 嘅 pubkey）：`);
  console.log(`  broker ask-register --agent ${agent}      # 印出完整 JSON，貼落 KV`);
}

/** 印出要人手寫入 Cloudflare KV 嘅 agent record（CLI 本身唔寫、唔上網） */
function cmdAskRegister(config: Config, flags: Record<string, string | true>) {
  const agent = resolveAgent(config, flags);
  const pubkey = flagString(flags, "pubkey") || derivePublicKey(agent);
  const entFlag = flagString(flags, "entitlements");
  const entitlements = entFlag
    ? entFlag.split(",").map((v) => v.trim()).filter(Boolean)
    : ["github"];
  const record: Record<string, unknown> = {
    id: agent,
    pubkey,
    enc_pubkey: encPubkeyFor(agent),
    status: "active",
    entitlements,
    created_at: new Date().toISOString(),
  };
  const installation = flagString(flags, "installation-id");
  if (installation) {
    const repos = flagString(flags, "repositories");
    record.github = {
      installation_id: Number(installation),
      ...(repos ? { repositories: repos.split(",").map((v) => v.trim()).filter(Boolean) } : {}),
    };
  }
  const body = JSON.stringify(record);
  console.log(body);
  console.log("");
  console.log("# 寫入提示（Cloudflare 帳號層；KV 已有同名 key 就係覆寫）");
  console.log(`cd worker && npx wrangler kv key put --binding=BROKER_KV --remote "agent:${agent}" '${body}'`);
  console.log("");
  console.log("# 只有 Cloudflare 帳號持有人做得到，所以 CLI 本身冇寫入能力");
}

function usage() {
  console.log(`broker — per-agent Secret Broker CLI (v${readCliVersion()})

用法:
  broker endpoint show|set <url>|clear                         設定部機層級 endpoint（默認冇）
  broker init --agent <id> [--broker-url <url>] [--force]      建立 agent 身份（Ed25519；macOS→Keychain，Linux→600 檔）
  broker ask-register [--agent <id>]                          印出「要喺 Cloudflare 寫入嘅 agent JSON」
  broker whoami [--agent <id>]                                 顯示本機身份
  broker pubkey [--agent <id>]                                 由私鑰推導簽名公鑰
  broker enc-pubkey [--agent <id>]                             由私鑰推導密封公鑰（畀人 seal secret）
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
    case "endpoint":
      cmdEndpoint(config, flags, positional);
      return;
    case "enc-pubkey":
      cmdEncPubkey(config, flags);
      return;
    case "whoami":
      cmdWhoami(config, flags);
      return;
    case "pubkey":
      cmdPubkey(config, flags);
      return;
    case "ask-register":
      cmdAskRegister(config, flags);
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

main().catch((error) => die((error as Error).message));
