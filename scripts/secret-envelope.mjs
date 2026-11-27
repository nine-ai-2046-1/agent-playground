#!/usr/bin/env node
/**
 * secret-envelope.mjs — 喺本機產生「可以直接貼落 Cloudflare KV」嘅密文信封
 *
 * 背景：Worker 已經冇 admin API，靜態 secret 只可以喺 Cloudflare 帳號層寫入。
 * 呢支小工具用同 Worker 一樣嘅格式（AES-256-GCM / 12-byte IV / AAD=sec|<agent>|<name>）
 * 喺本機加密，只輸出密文信封 —— 明文永遠唔會離開你部機。
 *
 * 用法：
 *   BROKER_MASTER_KEY=$(cat ~/Doubao/secrets/broker-master-key.b64) \
 *     node scripts/secret-envelope.mjs --agent opencode-01 --name smtp.password
 *   # 值由 stdin 讀（避免 argv 洩漏）
 *
 * 輸出：信封 JSON + 一行 wrangler 指令（貼去 Cloudflare 用）
 */
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const argv = process.argv.slice(2);
const flag = (name) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : undefined;
};

const agent = flag("agent");
const name = flag("name");
if (!agent || !name) {
  console.error("用法：node scripts/secret-envelope.mjs --agent <id> --name <key>   （值由 stdin 讀）");
  process.exit(2);
}
if (!/^[a-z0-9][a-z0-9._-]{1,47}$/.test(agent)) {
  console.error("agent id 格式錯（細寫英數 . _ -，2–48 字元）");
  process.exit(2);
}
if (!/^[a-z0-9][a-z0-9._-]{0,47}$/.test(name)) {
  console.error("secret name 格式錯（細寫英數 . _ -，1–48 字元）");
  process.exit(2);
}

const value = fs.readFileSync(0, "utf8").replace(/\n$/, "");
if (!value) {
  console.error("值為空（一定要由 stdin 提供）");
  process.exit(2);
}

let master = process.env.BROKER_MASTER_KEY || "";
if (!master) {
  const file = path.join(os.homedir(), "Doubao/secrets/broker-master-key.b64");
  if (fs.existsSync(file)) master = fs.readFileSync(file, "utf8").trim();
}
if (!master) {
  console.error("冇 BROKER_MASTER_KEY（env 或 ~/Doubao/secrets/broker-master-key.b64）");
  process.exit(1);
}

const key = Buffer.from(master.trim(), "base64url");
if (key.length !== 32) {
  console.error(`master key 長度錯：${key.length} bytes（要 32）`);
  process.exit(1);
}

const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
cipher.setAAD(Buffer.from(`sec|${agent}|${name}`, "utf8"));
const ct = Buffer.concat([cipher.update(value, "utf8"), cipher.final(), cipher.getAuthTag()]);
const envelope = JSON.stringify({
  v: 1,
  alg: "A256GCM",
  iv: iv.toString("base64url"),
  ct: ct.toString("base64url"),
});

console.log(envelope);
console.log("");
console.log("# 下一步：喺 Cloudflare 寫入（唔經 Worker）");
console.log(`cd worker && npx wrangler kv key put --binding=BROKER_KV --remote "sec:${agent}:${name}" '${envelope}'`);
console.log("");
console.log("# 記得同時確認 agent 嘅 entitlements 有呢個 key（agent:<id> JSON 內）");
console.log("# 刪除同輪替一律喺 Cloudflare Dashboard / wrangler 手動做，CLI 冇 delete");
