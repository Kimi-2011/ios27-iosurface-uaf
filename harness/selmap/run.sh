#!/bin/bash
# selmap 一键：构建 → 签名 → 安装 → 推配置 → 启动 → 等 → 回收
#
# 用法:
#   ./run.sh              # 跑默认目标清单
#   PLAN=/path/plan.json ./run.sh
#   WAIT=20 ./run.sh
set -e
cd "$(dirname "$0")"

DEV="${DEV:-DEVICE-UDID}"
BUNDLE="${BUNDLE:-com.example.ios27poc}"
KC="${KC:-$HOME/Library/Keychains/dev.keychain-db}"
IDENT="${IDENT:-iPhone Distribution: <DEVELOPER> (<TEAMID>)}"
ENTS="${ENTS:-/tmp/ents.plist}"
PLAN="${PLAN:-}"
WAIT="${WAIT:-16}"
ROOT="$(cd "$2>/dev/null" && pwd)"

echo "== 1/6 编译 =="
xcrun -sdk iphoneos clang -arch arm64 -miphoneos-version-min=16.0 -fobjc-arc main.m \
  -o Payload/SM.app/SM \
  -framework UIKit -framework Foundation -framework IOKit -framework CoreGraphics

echo "== 2/6 签名 =="
security unlock-keychain -p "" "$KC"
codesign -s "$IDENT" --keychain "$KC" --entitlements "$ENTS" \
  --generate-entitlement-der -f Payload/SM.app

echo "== 3/6 安装 =="
xcrun devicectl device install app --device "$DEV" Payload/SM.app 2>&1 | grep -E "bundleID|rror" || true

if [ -n "$PLAN" ]; then
  echo "== 4/6 推送配置 $PLAN =="
  xcrun devicectl device copy to --device "$DEV" \
    --domain-type appDataContainer --domain-identifier "$BUNDLE" \
    --source "$PLAN" --destination tmp/selmap.json 2>&1 | grep -E "Path|rror" || true
else
  echo "== 4/6 沿用设备上已有的 tmp/selmap.json =="
fi

echo "== 5/6 启动 =="
xcrun devicectl device process launch --device "$DEV" --terminate-existing "$BUNDLE" 2>&1 | tail -1
sleep "$WAIT"

echo "== 6/6 回收 =="
OUTDIR="${OUTDIR:-$(dirname "$(pwd)")/../out}"
mkdir -p "$OUTDIR"
for f in selmap.ndjson selmap.log; do
  xcrun devicectl device copy from --device "$DEV" \
    --domain-type appDataContainer --domain-identifier "$BUNDLE" \
    --source "tmp/$f" --destination "/tmp/sm-$f" 2>&1 | tail -1
done
cp /tmp/sm-selmap.ndjson "$OUTDIR/selmap.ndjson"
cp /tmp/sm-selmap.log    "$OUTDIR/selmap.log"
echo "落盘: $OUTDIR/selmap.ndjson ($(wc -l < "$OUTDIR/selmap.ndjson") 条)"
