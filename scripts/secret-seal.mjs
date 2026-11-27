#!/usr/bin/env node
/**
 * secret-seal — 喺「寫入 secret 嗰個人」部機上，把明文封成 X25519 密封信封。
 *
 * 安全模型：
 *   - 只需要 agent 嘅「密封公鑰」（公開資料，可以貼喺 Cloudflare KV record）
 *   - 產生一次性 X25519 keypair → ECDH → HKDF → AES-256-GCM
 *   - 只有持有 agent 私鑰嘅機（agent 本機 CLI）解得開
 *   - Worker 只會見到密文（`{v:2,alg:"X25519-A256GCM",epk,iv,ct}`），完全冇解密能力
 *
 * 用法：
 *   node scripts/secret-seal.mjs --agent opencode-01 --name openai.api_key --enc-pubkey <b64url> [--value <明文>]
 *   或者把明文由 stdin 餵入（避免出現在 shell history）：
 *     printf '%s' "$OPENAI_API_KEY" | node scripts/secret-seal.mjs --agent opencode-01 --name openai.api_key --enc-pubkey <b64url>
 *
 * 輸出：信封 JSON（stdout）＋ 一行可以直接貼去 Cloudflare 嘅 wrangler 指令（stderr）
 */
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const X_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");
const HKDF_INFO = Buffer.from("secret-broker-v2");

function fail(msg) {
  process.stderr.write(`✖ ${msg}\n`);
    process.exit(2);
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i];
    if (!key.startsWith("--")) continue;
    const name = key.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) {
      out[name] = true;
    } else {
      out[name] = next;
      i += 1;
    }
    }
  return out;
}

const args = parseArgs(process.argv.slice(2));
if (args.help) {
  process.stderr.write(
    "用法：node scripts/secret-seal.mjs --agent <id> --name <secret-name> --enc-pubkey <b64url> [--value <明文>]\n" +
      "      明文亦可以由 stdin 餵入（推薦，唔會留在 shell history）\n",
  );
  process.exit(0);
}

const agent = String(args.agent || "");
const name = String(args.name || "");
const encPubkey = String(args["enc-pubkey"] || "");

if (!/^[a-z0-9][a-z0-9._-]{1,47}$/.test(agent)) fail("--agent 唔合法（^[a-z0-9][a-z0-9._-]{1,47}$）");
if (!/^[A-Za-z0-9._-]{1,64}$/.test(name)) fail("--name 唔合法（字母數字 . _ -，最長 64）");
if (!encPubkey) fail("缺少 --enc-pubkey（由 agent 部機跑 `broker enc-pubkey` 取得，屬公開資料）");

let plain;
if (typeof args.value === "string") {
  plain = args.value;
} else {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  plain = Buffer.concat(chunks.map((c) => Buffer.from(c))).toString("utf8");
  // 去掉一個尾隨換行（printf/echo 常見）
  plain = plain.replace(/\r?\n$/, "");
}
if (!plain) fail("冇明文：請用 --value 或者由 stdin 餵入");
if (plain.length > 8192) fail("明文太長（上限 8192 bytes）");

let peerPub;
try {
  const raw = Buffer.from(encPubkey, "base64url");
  if (raw.length !== 32) fail("--enc-pubkey 長度唔係 32 bytes（要 raw base64url，唔係 PEM）");
  peerPub = crypto.createPublicKey({
    key: Buffer.concat([X_SPKI_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
} catch (err) {
  fail(`--enc-pubkey 解析失敗：${err.message}`);
}

const eph = crypto.generateKeyPairSync("x25519");
const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: peerPub });
const key = Buffer.from(
  crypto.hkdfSync("sha256", shared, Buffer.from(`broker|${agent}|${name}`), HKDF_INFO, 32),
);
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
cipher.setAAD(Buffer.from(`sec|${agent}|${name}`));
const body = Buffer.concat([cipher.update(Buffer.from(plain, "utf8")), cipher.final()]);
const ct = Buffer.concat([body, cipher.getAuthTag()]);
const epkSpki = eph.publicKey.export({ format: "der", type: "spki" });

const envelope = JSON.stringify({
  v: 2,
  alg: "X25519-A256GCM",
  epk: Buffer.from(epkSpki.subarray(epkSpki.length - 32)).toString("base64url"),
  iv: iv.toString("base64url"),
  ct: ct.toString("base64url"),
  created_at: new Date().toISOString(),
});

const outFile = path.join(os.tmpdir(), `sealed-${agent}-${name}.json`.replace(/[^A-Za-z0-9._-]/g, "_"));
fs.writeFileSync(outFile, `${envelope}\n`, { mode: 0o600 });

process.stdout.write(`${envelope}\n`);
process.stderr.write(
  "\n下一步（Cloudflare 帳號持有人執行；CLI 本身冇寫入能力）：\n" +
    `  npx wrangler kv key put --binding=BROKER_KV --remote "sec:${agent}:${name}" --path ${outFile}\n` +
    `  或者用 Cloudflare Dashboard → Workers KV → BROKER_KV → 新增 key「sec:${agent}:${name}」貼上以上 JSON\n` +
    "  之後 agent 部機 `broker claim " + name + "` 就會本機解密（Worker 全程見唔到明文）。\n",
);
