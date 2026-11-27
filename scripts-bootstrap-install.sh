#!/usr/bin/env bash
# bootstrap-install.sh — 在 agent 機器安裝 broker CLI（預設走「已發佈 release」＋checksum 驗證）
#
# 三種模式：
#   1) 預設（推薦）：由 GitHub Release 下載已 pin 嘅 tarball，驗 sha256 後安裝
#        GH_TOKEN=<只讀 Contents:Read 的 token> ./scripts-bootstrap-install.sh
#        REL_TAG=v0.4.0 ./scripts-bootstrap-install.sh        # 指定 pin 到其他 release
#   2) --from-git    ：由 repo 指定 ref clone（唔 pin、無 checksum；只作應急）
#        GH_TOKEN=… REF=main ./scripts-bootstrap-install.sh --from-git
#   3) --dir <path>  ：由已 clone 的本地目錄 npm pack（完全離線）
#        ./scripts-bootstrap-install.sh --dir /path/to/agent-playground
#
# 設計要點：
#   * 預設唔跟 HEAD：pin 到 release tag，並用 release 內嘅 .sha256 驗證（供應鏈防護）
#   * token 只經 curl header / GIT_ASKPASS 傳遞，唔入 argv / shell history
#   * 用 npm pack → 裝 tarball，避免 npm 直連 GitHub（亦避開 install-links 的 ENOTEMPTY）
#   * 安裝後驗證 broker 可執行 + 版本符合 release tag
set -euo pipefail

REPO_SLUG="${REPO_SLUG:-nine-ai-2046-1/agent-playground}"
REPO_URL="${REPO_URL:-https://github.com/${REPO_SLUG}.git}"
BASE_URL="${BASE_URL:-https://github.com/${REPO_SLUG}/releases/download}"
REL_TAG="${REL_TAG:-v0.4.0}"   # 預設 pin 版本
REF="${REF:-main}"
MODE="release"
DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) MODE="dir"; DIR="$2"; shift 2 ;;
    --from-git) MODE="git"; shift ;;
    --release) MODE="release"; REL_TAG="$2"; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "未知參數: $1" >&2; exit 2 ;;
  esac
done

TMP="$(mktemp -d)"
cleanup() { [ -n "${ASKPASS:-}" ] && rm -f "$ASKPASS"; rm -rf "$TMP"; }
trap cleanup EXIT

sha256_check() { # $1=dir  $2=file  $3=checksum file
  if command -v sha256sum >/dev/null 2>&1; then ( cd "$1" && sha256sum -c "$3" >&2 )
  else ( cd "$1" && shasum -a 256 -c "$3" >&2 ); fi
}

case "$MODE" in
  dir)
    [ -d "$DIR" ] || { echo "--dir 路徑唔存在: $DIR" >&2; exit 1; }
    cd "$DIR"; TGZ_PATH="./$(npm pack --silent | tail -1)"
    ;;
  git)
    [ -n "${GH_TOKEN:-}" ] || { echo "需要 GH_TOKEN（只讀 token）或 --dir" >&2; exit 1; }
    ASKPASS="$TMP/.askpass"
    printf '#!/bin/sh\necho "$GH_TOKEN"\n' > "$ASKPASS"; chmod 700 "$ASKPASS"
    AUTH_URL="$(printf '%s' "$REPO_URL" | sed 's|https://|https://x-access-token@|')"
    GIT_ASKPASS="$ASKPASS" GIT_TERMINAL_PROMPT=0 git clone --depth 1 --branch "$REF" \
      "$AUTH_URL" "$TMP/cli" >&2
    cd "$TMP/cli"; TGZ_PATH="./$(npm pack --silent | tail -1)"
    ;;
  release)
    [ -n "${GH_TOKEN:-}" ] || { echo "需要 GH_TOKEN（只讀 token；private repo 必需）" >&2; exit 1; }
    VER="${REL_TAG#v}"
    ASSET="nine-ai-secret-broker-cli-${VER}.tgz"
    AUTH=(-H "Authorization: Bearer ${GH_TOKEN}" -H "Accept: application/octet-stream")
    echo "→ 下載 pin 版 ${REL_TAG}（${ASSET}）" >&2
    curl -fsSL --retry 3 -m 120 "${AUTH[@]}" -o "$TMP/$ASSET" "$BASE_URL/$REL_TAG/$ASSET"
    curl -fsSL --retry 3 -m 60  "${AUTH[@]}" -o "$TMP/$ASSET.sha256" "$BASE_URL/$REL_TAG/$ASSET.sha256"
    sha256_check "$TMP" "$ASSET" "$ASSET.sha256" || { echo "✖ checksum 唔符，已中止" >&2; exit 1; }
    echo "✔ checksum 通過：" >&2; cat "$TMP/$ASSET.sha256" >&2
    TGZ_PATH="$TMP/$ASSET"
    ;;
  *) echo "內部錯誤：未知模式 $MODE" >&2; exit 2 ;;
esac

npm i -g --no-audit --no-fund "$TGZ_PATH" >&2
command -v broker >/dev/null || { echo "安裝後找不到 broker" >&2; exit 1; }
INSTALLED="$(broker --version 2>/dev/null | tail -1 | awk '{print $NF}' | sed 's/^v//')"
if [ "$MODE" = "release" ] && [ "$INSTALLED" != "${REL_TAG#v}" ]; then
  echo "✖ 版本唔符：期望 ${REL_TAG#v}，實際 ${INSTALLED}" >&2; exit 1
fi
echo "✔ broker 已安裝：$(command -v broker)（版本 ${INSTALLED}）"
broker --help | head -2
