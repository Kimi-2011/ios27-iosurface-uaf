#!/bin/bash
# ucall 全流程：构建 → 签名 → 安装 → 推 plan → 启动 → 等待 → 取回
#
# 用法:
#   ./run.sh <plan.json>          # 全量跑
#   ./run.sh <plan.json> 3        # 只跑 idx 3（单条重试）
#
# 前置：设备已解锁并保持亮屏（锁屏会让 DDI 挂载失败 kAMDMobileImageMounterDeviceLocked）
# 约束：单次交互等待 <= 35s；app 内部看门狗 26s，落盘增量，panic 也能保住已跑完的条目。
set -e
DEV=${DEV:-DEVICE-UDID}
BID=com.example.ios27poc
IDENT="iPhone Distribution: <DEVELOPER> (<TEAMID>)"
KC="$HOME/Library/Keychains/dev.keychain-db"
ENTS=${ENTS:-/tmp/ents.plist}
PLAN=${1:?用法: ./run.sh <plan.json> [only_index]}
ONLY=${2:-}

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT/harness/ucall"

[ -f "$ENTS" ] || ENTS="$ROOT/out/ents.plist"

echo "== 1/6 构建"
xcrun -sdk iphoneos clang -arch arm64 -miphoneos-version-min=16.0 -fobjc-arc \
  main.m -o Payload/UC.app/UC \
  -framework UIKit -framework Foundation -framework IOKit -framework CoreGraphics

echo "== 2/6 签名"
security unlock-keychain -p "" "$KC"
codesign -s "$IDENT" --keychain "$KC" \
  --entitlements "$ENTS" --generate-entitlement-der -f Payload/UC.app

echo "== 3/6 安装"
xcrun devicectl device install app --device "$DEV" Payload/UC.app || {
  echo "!! 安装失败：若报 kAMDMobileImageMounterDeviceLocked 请先解锁设备"; exit 1; }

echo "== 4/6 推配置"
xcrun devicectl device copy to --device "$DEV" \
  --domain-type appDataContainer --domain-identifier "$BID" \
  --source "$PLAN" --destination tmp/plan.json

echo "== 5/6 启动"
xcrun devicectl device process launch --device "$DEV" --terminate-existing "$BID" || true
sleep 28   # 看门狗 26s + 收尾

echo "== 6/6 取回"
for f in ucall.ndjson ucall.json ucall.log; do
  xcrun devicectl device copy from --device "$DEV" --domain-type appDataContainer \
    --domain-identifier "$BID" --source "tmp/$f" --destination "/tmp/$f" || echo "  (缺 $f)"
done

# 落盘：默认只覆盖 out/ucall-last.ndjson，不污染基线
# APPEND=1 时才追加进 out/ucall-baseline.ndjson（基线文件应保持单次运行的纯净）
mkdir -p "$ROOT/out"
if [ -f /tmp/ucall.ndjson ]; then
  cp /tmp/ucall.ndjson "$ROOT/out/ucall-last.ndjson"
  echo "== 已写入 out/ucall-last.ndjson ($(wc -l < /tmp/ucall.ndjson) 行)"
  if [ "${APPEND:-0}" = "1" ]; then
    cat /tmp/ucall.ndjson >> "$ROOT/out/ucall-baseline.ndjson"
    echo "== APPEND=1：已追加进 out/ucall-baseline.ndjson"
  fi
fi
[ -f /tmp/ucall.log ] && cp /tmp/ucall.log "$ROOT/out/ucall-last.log"
echo "完成。"
