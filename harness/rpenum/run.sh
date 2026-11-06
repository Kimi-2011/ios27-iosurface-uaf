#!/bin/bash
# rpenum 全流程：构建 → 签名 → 装 → 启 → 取回 → 交叉 → 出报告
# 前置：设备已解锁并保持亮屏（DDI 挂载需要解锁）
set -e
DEV=${DEV:-DEVICE-UDID}
BID=com.example.ios27poc
IDENT="iPhone Distribution: <DEVELOPER> (<TEAMID>)"
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT/harness/rpenum"

xcrun -sdk iphoneos clang -arch arm64 -miphoneos-version-min=16.0 -fobjc-arc \
  main.m -o Payload/RP.app/RP \
  -framework UIKit -framework Foundation -framework IOKit -framework CoreGraphics

security unlock-keychain -p "" ~/Library/Keychains/dev.keychain-db
codesign -s "$IDENT" --keychain ~/Library/Keychains/dev.keychain-db \
  --entitlements /tmp/ents.plist --generate-entitlement-der -f Payload/RP.app

xcrun devicectl device install app --device "$DEV" Payload/RP.app
xcrun devicectl device process launch --device "$DEV" --terminate-existing "$BID"
sleep 22   # app 内部枚举 + 24s 打开预算 + 32s 看门狗，22s 足够取到完成态

for f in reach.json reach-meta.json reach.log reach.ndjson; do
  xcrun devicectl device copy from --device "$DEV" --domain-type appDataContainer \
    --domain-identifier "$BID" --source "tmp/$f" --destination "/tmp/$f"
done

cd "$ROOT"
cp /tmp/reach.json out/reach.json
cp /tmp/reach-meta.json out/reach-meta.json
cp /tmp/reach.log out/reach.log
cp /tmp/reach.ndjson out/reach.ndjson
python3 harness/rpenum/xref.py --reach out/reach.json --out out/reach-xref.json
python3 harness/rpenum/gen_report.py
