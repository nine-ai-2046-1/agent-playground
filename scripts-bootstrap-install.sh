#!/usr/bin/env bash
# bootstrap-install.sh — 在 agent 機器上由 clone 安裝 broker CLI（唔需要 build、唔需要網絡）
#
# 用法（有 repo 讀取權限的 token，只限 Contents:Read）：
#   GH_TOKEN=<token> ./scripts-bootstrap-install.sh
# 或用已 clone 的目錄：
#   ./scripts-bootstrap-install.sh --dir /path/to/agent-playground
#
# 設計要點：
#   * token 只經 GIT_ASKPASS 傳遞，唔入 argv / shell history
#   * 用 npm pack → 裝 tarball，避免 npm 直連 GitHub（亦避開 install-links 的 ENOTEMPTY）
#   * 安裝後自動驗證 broker 可執行
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/nine-ai-2046-1/agent-playground.git}"
REF="${REF:-main}"
DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DIR="$2"; shift 2 ;;
    *) echo "未知參數: $1" >&2; exit 2 ;;
  esac
done

TMP="$(mktemp -d)"
cleanup() { [ -n "${ASKPASS:-}" ] && rm -f "$ASKPASS"; rm -rf "$TMP"; }
trap cleanup EXIT

if [ -z "$DIR" ]; then
  [ -n "${GH_TOKEN:-}" ] || { echo "需要 GH_TOKEN（只讀 token）或 --dir" >&2; exit 1; }
  ASKPASS="$TMP/.askpass"
  printf '#!/bin/sh\necho "$GH_TOKEN"\n' > "$ASKPASS"; chmod 700 "$ASKPASS"
  GIT_ASKPASS="$ASKPASS" git clone --depth 1 --branch "$REF" \
    "${REPO_URL/https:\/\//https:\/\/x-access-token@}" "$TMP/cli" >&2
  DIR="$TMP/cli"
fi

cd "$DIR"
TGZ="$(npm pack --silent | tail -1)"
npm i -g --no-audit --no-fund "./$TGZ" >&2
rm -f "./$TGZ"
command -v broker >/dev/null || { echo "安裝後找不到 broker" >&2; exit 1; }
echo "✔ broker 已安裝：$(command -v broker)"
broker --help | head -2
