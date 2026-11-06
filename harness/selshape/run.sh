#!/bin/bash
# selshape 一键：构建 → 签名 → 安装 → 推配置 → 启动 → 等 → 回收
#   PLAN=/path/cfg.json WAIT=16 ./run.sh
set -e
cd "$(dirname "$0")"
DEV="${DEV:-DEVICE-UDID}"
BUNDLE="${BUNDLE:-com.example.ios27poc}"
KC="${KC:-$HOME/Library/Keychains/dev.keychain-db}"
IDENT="${IDENT:-iPhone Distribution: <DEVELOPER> (<TEAMID>)}"
ENTS="${ENTS:-/tmp/ents.plist}"
PLAN="${PLAN:-}"; WAIT="${WAIT:-16}"

echo "== 1/6 编译 =="
xcrun -sdk iphoneos clang -arch arm64 -miphoneos-version-min=16.0 -fobjc-arc main.m \
  -o Payload/SH.app/SH -framework UIKit -framework Foundation -framework IOKit -framework CoreGraphics

echo "== 2/6 签名 =="
security unlock-keychain -p "" "$KC"
codesign -s "$IDENT" --keychain "$KC" --entitlements "$ENTS" --generate-entitlement-der -f Payload/SH.app

echo "== 3/6 安装 =="
xcrun devicectl device install app --device "$DEV" Payload/SH.app 2>&1 | grep -E "bundleID|rror" || true

if [ -n "$PLAN" ]; then
  echo "== 4/6 推配置 =="
  xcrun devicectl device copy to --device "$DEV" --domain-type appDataContainer \
    --domain-identifier "$BUNDLE" --source "$PLAN" --destination tmp/selshape.json 2>&1 | grep -E "Path|rror" || true
fi

echo "== 5/6 启动 =="
xcrun devicectl device process launch --device "$DEV" --terminate-existing "$BUNDLE" 2>&1 | tail -1
sleep "$WAIT"

echo "== 6/6 回收 =="
OUTDIR="${OUTDIR:-$(cd ../.. && pwd)/out}"
mkdir -p "$OUTDIR"
for f in selshape.ndjson selshape.log; do
  xcrun devicectl device copy from --device "$DEV" --domain-type appDataContainer \
    --domain-identifier "$BUNDLE" --source "tmp/$f" --destination "/tmp/sh-$f" 2>&1 | tail -1 || true
done
cp /tmp/sh-selshape.ndjson "$OUTDIR/selshape.ndjson"
cp /tmp/sh-selshape.log    "$OUTDIR/selshape.log"
echo "落盘: $OUTDIR/selshape.ndjson ($(wc -l < "$OUTDIR/selshape.ndjson") 条)"
