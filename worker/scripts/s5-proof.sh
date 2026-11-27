#!/bin/bash
# S5 Proof script — V3（token 真係用到）+ V4（同一張 token 一小時後失效）
# 用法：scripts/s5-proof.sh v3     # 立即跑 V3
#       scripts/s5-proof.sh v4     # 等到 expires_at 之後，用同一張 token 重試
# 憑證唔會出現在命令行參數：token 由 600-perm 檔案讀入 curl config。
set -u
TOKEN_FILE=${TOKEN_FILE:-/tmp/.s5/token}
META_FILE=${META_FILE:-/tmp/.s5/meta.json}
LOG=${LOG:-/tmp/.s5/proof.log}
REPO=${REPO:-nine-ai-2046-1/agent-playground}
WORK=${WORK:-/tmp/.s5}
MODE=${1:-v3}

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { printf '%s %s\n' "$(ts)" "$*" | tee -a "$LOG"; }

[ -r "$TOKEN_FILE" ] || { echo "missing $TOKEN_FILE"; exit 1; }
umask 077
CFG="$WORK/.curlcfg"
{
  printf 'header = "Authorization: Bearer %s"\n' "$(cat "$TOKEN_FILE")"
  printf 'header = "Accept: application/vnd.github+json"\n'
  printf 'header = "X-GitHub-Api-Version: 2022-11-28"\n'
  printf 'silent\n'
} > "$CFG"
chmod 600 "$CFG"
trap 'rm -f "$CFG"' EXIT

BODY="$WORK/.body"
code() { curl -o "$BODY" -w '%{http_code}' --config "$CFG" "https://api.github.com$1"; }
tprefix=$(head -c 8 "$TOKEN_FILE"); tlen=$(wc -c < "$TOKEN_FILE" | tr -d ' ')

if [ "$MODE" = "v3" ]; then
  log "V3 START token=${tprefix}... len=$tlen repo=$REPO"
  c=$(code "/repos/$REPO")
  summary=$(python3 -c "import json;d=json.load(open('$BODY'));print('full_name='+str(d.get('full_name')),'private='+str(d.get('private')),'pushed_at='+str(d.get('pushed_at')),sep=' ')" 2>/dev/null || echo "parse_failed")
  log "V3-a GET /repos/$REPO -> $c | $summary"
  c=$(code "/repos/$REPO/pulls?per_page=5")
  log "V3-b GET /pulls -> $c count=$(python3 -c "import json;print(len(json.load(open('$BODY'))))" 2>/dev/null)"
  c=$(code "/repos/$REPO/branches?per_page=10")
  log "V3-b2 GET /branches -> $c count=$(python3 -c "import json;print(len(json.load(open('$BODY'))))" 2>/dev/null)"
  c=$(code "/installation/repositories")
  log "V3-c GET /installation/repositories (installation token 應該無權) -> $c $(head -c 120 "$BODY")"
  log "V3 END"
  exit 0
fi

exp=$(python3 -c "import json,datetime;print(datetime.datetime.fromisoformat(json.load(open('$META_FILE'))['expires_at'].replace('Z','+00:00')).timestamp())")
now=$(date -u +%s)
sleep_for=$(( ${exp%.*} + 90 - now ))
if [ "$sleep_for" -lt 0 ]; then sleep_for=0; fi
log "V4 WAIT expires_at=$(python3 -c "import json;print(json.load(open('$META_FILE'))['expires_at'])") sleep=${sleep_for}s"
sleep "$sleep_for"
log "V4 START same-token=${tprefix}... len=$tlen (T1 after expiry)"
c=$(code "/repos/$REPO")
msg=$(python3 -c "import json;print(json.load(open('$BODY')).get('message'))" 2>/dev/null)
log "V4-a GET /repos/$REPO -> $c message=$msg"
c2=$(code "/repos/$REPO/pulls?per_page=5")
msg2=$(python3 -c "import json;print(json.load(open('$BODY')).get('message'))" 2>/dev/null)
log "V4-b GET /pulls -> $c2 message=$msg2"
log "V4 END"
rm -f "$TOKEN_FILE" "$CFG"
log "V4 token_file_removed=$(test ! -f "$TOKEN_FILE" && echo yes)"
