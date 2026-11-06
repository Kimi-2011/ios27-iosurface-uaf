#!/bin/bash
# fuzz2 一键：构建 → 签名 → 安装 → 推配置/累积结果 → 启动 → 等 → 回收
#   PLAN=/path/plan.json WAIT=32 ./run.sh
#   BUILD=0 跳过编译（同一批次循环里只编一次）
set -e
cd "$(dirname "$0")"
DEV="${DEV:-DEVICE-UDID}"
BUNDLE="${BUNDLE:-com.example.ios27poc}"
KC="${KC:-$HOME/Library/Keychains/dev.keychain-db}"
IDENT="${IDENT:-iPhone Distribution: <DEVELOPER> (<TEAMID>)}"
ENTS="${ENTS:-$(cd ../.. && pwd)/out/ents.plist}"
PLAN="${PLAN:-}"
WAIT="${WAIT:-32}"
BUILD="${BUILD:-1}"
ROOT="$(cd ../.. && pwd)"
OUTDIR="${OUTDIR:-$ROOT/out}"

if [ "$BUILD" = "1" ]; then
  echo "== 1/6 编译 =="
  xcrun -sdk iphoneos clang -arch arm64 -miphoneos-version-min=16.0 -fobjc-arc main.m \
    -o Payload/FZ.app/FZ -framework UIKit -framework Foundation -framework IOKit -framework CoreGraphics
  echo "== 2/6 签名 =="
  security unlock-keychain -p "" "$KC"
  codesign -s "$IDENT" --keychain "$KC" --entitlements "$ENTS" --generate-entitlement-der -f Payload/FZ.app
  echo "== 3/6 安装 =="
  xcrun devicectl device install app --device "$DEV" Payload/FZ.app 2>&1 | grep -E "bundleID|rror" || true
else
  echo "== 1-3/6 跳过编译/签名/安装（BUILD=0）=="
fi

mkdir -p "$OUTDIR"
if [ -n "$PLAN" ]; then
  echo "== 4/6 推配置 =="
  xcrun devicectl device copy to --device "$DEV" --domain-type appDataContainer \
    --domain-identifier "$BUNDLE" --source "$PLAN" --destination tmp/fuzz2.json 2>&1 | grep -E "Path|rror" || true
fi

# 把本地累积结果推回设备：保证上一个 app 被换掉 / 容器被清后仍能断点续跑。
# 重复的 end 行对去重无害（loadDone 用 set）。
if [ "${RESET:-0}" = "1" ]; then
  echo "== 复位设备端 ndjson（RESET=1，key 方案变更后必须做）=="
  : > /tmp/fz2-empty.ndjson
  xcrun devicectl device copy to --device "$DEV" --domain-type appDataContainer \
    --domain-identifier "$BUNDLE" --source /tmp/fz2-empty.ndjson --destination tmp/fuzz2.ndjson \
    2>&1 | grep -E "Path|rror" || true
elif [ -f "$OUTDIR/fuzz2.ndjson" ] && [ "$(wc -c < "$OUTDIR/fuzz2.ndjson")" -gt 0 ]; then
  xcrun devicectl device copy to --device "$DEV" --domain-type appDataContainer \
    --domain-identifier "$BUNDLE" --source "$OUTDIR/fuzz2.ndjson" --destination tmp/fuzz2.ndjson \
    2>&1 | grep -E "Path|rror" || true
fi

echo "== 5/6 启动（等 ${WAIT}s）=="
xcrun devicectl device process launch --device "$DEV" --terminate-existing "$BUNDLE" 2>&1 | tail -1
sleep "$WAIT"

echo "== 6/6 回收 =="
for f in fuzz2.ndjson fuzz2.log; do
  rm -f "/tmp/fz2-$f"
  xcrun devicectl device copy from --device "$DEV" --domain-type appDataContainer \
    --domain-identifier "$BUNDLE" --source "tmp/$f" --destination "/tmp/fz2-$f" 2>&1 | tail -1 || true
done
[ -f /tmp/fz2-fuzz2.ndjson ] && mv /tmp/fz2-fuzz2.ndjson "$OUTDIR/fuzz2.ndjson"
if [ -f /tmp/fz2-fuzz2.log ]; then
  cat /tmp/fz2-fuzz2.log >> "$OUTDIR/fuzz2-run.log"
  cp /tmp/fz2-fuzz2.log "$OUTDIR/fuzz2-last.log"
fi
echo "落盘: $OUTDIR/fuzz2.ndjson ($(wc -l < "$OUTDIR/fuzz2.ndjson" 2>/dev/null || echo 0) 行)"
