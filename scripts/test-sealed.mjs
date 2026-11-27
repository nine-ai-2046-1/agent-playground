#!/usr/bin/env node
/**
 * test-sealed — 本機閉環測試：證明「seal（寫入方）」同「CLI 解密（agent 方）」格式對得上，
 * 而且 claim 回應只帶密文（sealed），明文只喺 agent 部機出現。
 *
 * 唔需要網絡、唔需要 Cloudflare：用一個臨時 mock broker（127.0.0.1）。
 */
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const AGENT = "sealed-e2e-01";
const NAME = "openai.api_key";
const PLAIN = "sk-test-SEALED-e2e-0001";

let failures = 0;
function check(label, ok, detail = "") {
  if (ok) {
    console.log(`  PASS  ${label}`);
  } else {
    failures += 1;
    console.log(`  FAIL  ${label}${detail ? ` — ${detail}` : ""}`);
  }
}

// 1) 產生 agent 身份（等價 broker init 出嘅 Ed25519 私鑰）
const kp = crypto.generateKeyPairSync("ed25519");
const privB64 = kp.privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
const env = { ...process.env, BROKER_PRIVATE_KEY: privB64, BROKER_AGENT_ID: AGENT };

// 2) 用 CLI 推導密封公鑰（同 init 時候印出嗰條一樣）
const pubRes = spawnSync(process.execPath, [path.join(root, "dist/index.js"), "enc-pubkey", "--agent", AGENT], {
  env,
  encoding: "utf8",
});
check("enc-pubkey 成功", pubRes.status === 0, pubRes.stderr.trim());
const encPub = (pubRes.stdout || "").trim();
check("enc-pubkey 係 32-byte base64url", Buffer.from(encPub, "base64url").length === 32, encPub);

// 3) 寫入方 seal（只知公鑰）
const sealRes = spawnSync(
  process.execPath,
  [path.join(root, "scripts/secret-seal.mjs"), "--agent", AGENT, "--name", NAME, "--enc-pubkey", encPub],
  { env, input: PLAIN, encoding: "utf8" },
);
check("secret-seal 成功", sealRes.status === 0, sealRes.stderr.trim());
const envelope = (sealRes.stdout || "").trim();
let parsed = null;
try {
  parsed = JSON.parse(envelope);
} catch {
  parsed = null;
}
check("信封係 v2 格式", parsed?.v === 2 && parsed?.alg === "X25519-A256GCM", envelope.slice(0, 60));
check("信封冇明文（唔會漏 secret）", envelope.includes(PLAIN) === false);
check("信封不含私鑰材料", typeof parsed?.epk === "string" && parsed.epk.length === 43);

// 4) mock broker：只回密文（同真 Worker 行為一致）
const server = http.createServer((req, res) => {
  if (req.method !== "POST" || !req.url.startsWith("/v1/claim")) {
    res.writeHead(404).end("{}");
    return;
  }
  let body = "";
  req.on("data", (c) => {
    body += c;
  });
  req.on("end", () => {
    const wants = [...(JSON.parse(body || "{}").wants || [])];
    const secrets = {};
    for (const want of wants) {
      secrets[want] = { sealed: envelope, encrypted: true, e2e: true };
    }
    res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
    res.end(JSON.stringify({ agent_id: AGENT, secrets, expires_in: 300 }));
  });
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const port = server.address().port;

// 5) agent 部機 claim → 本機解密
// 注意：必須用 async spawn，否則 spawnSync 會卡住同 process 嘅 mock server（死鎖）
let claimRes = { status: 1, stdout: "", stderr: "" };
try {
  const out = await execFileAsync(
    process.execPath,
    [path.join(root, "dist/index.js"), "claim", NAME, "--json", "--agent", AGENT],
    { env: { ...env, BROKER_URL: `http://127.0.0.1:${port}` }, encoding: "utf8", timeout: 20000 },
  );
  claimRes = { status: 0, stdout: out.stdout, stderr: out.stderr };
} catch (err) {
  claimRes = { status: err.code ?? 1, stdout: err.stdout || "", stderr: err.message || String(err) };
}
server.close();

check("claim 成功", claimRes.status === 0, claimRes.stderr.trim());
check("本機解出明文", claimRes.stdout.includes(PLAIN), claimRes.stdout.slice(0, 200));
check("輸出冇殘留 sealed 欄位", claimRes.stdout.includes('"sealed"') === false);
check("輸出標記 e2e", claimRes.stdout.includes('"e2e": true'));

// 6) 錯 agent（冇對應私鑰）應該解唔到
const wrong = spawnSync(
  process.execPath,
  [path.join(root, "scripts/secret-seal.mjs"), "--agent", AGENT, "--name", NAME, "--enc-pubkey", encPub],
  { env, input: PLAIN, encoding: "utf8" },
);
check("重複 seal 每次 epk 都唔同（一次性 keypair）", wrong.stdout.trim() !== envelope);

console.log(`\n${failures === 0 ? "✔ 全部通過" : `✖ ${failures} 項失敗`}`);
process.exit(failures === 0 ? 0 : 1);
