#!/bin/bash
# israce — 构建 → 签名 → 安装 → 启动 → 取回。单次交互等待 <= 35s。
#
#   ./run.sh          一次完整回合
#   ./run.sh 1        同上（显式模式，便于 xargs 循环）
#
# 前置：设备已解锁并保持亮屏。
# 断点续跑：app 读容器内 tmp/israce.ndjson，跳过已有 end 的 key；
#           run.sh 每回合把取回的结果并入 out/israce.ndjson。
set -e
# 设备独占：整轮（build→sign→install→launch→copy）持有排他锁。
# macOS 没有 flock(1)（实测 `exec: flock: not found`），改用原子 mkdir 锁：
#   /tmp/ios27-device.lock.d 存在 = 有别的 harness 在跑，等待；退出时 trap 删除。
# 若对侧用 flock /tmp/ios27-device.lock，请改用同一把 mkdir 锁，否则不互斥。
LOCKDIR=/tmp/ios27-device.lock.d
if [ "${ISRACE_LOCKED:-0}" != "1" ]; then
  export ISRACE_LOCKED=1
  N=0
  while ! mkdir "$LOCKDIR" 2>/dev/null; do
    N=$((N+1))
    if [ $N -gt 120 ]; then echo "!! 设备锁等待超过 240s，放弃本轮"; exit 1; fi
    sleep 2
  done
  printf '%s pid=%s at %s\n' "israce" "$$" "$(date +%H:%M:%S)" > "$LOCKDIR/owner" 2>/dev/null || true
  trap 'rm -rf "$LOCKDIR"' EXIT INT TERM
fi
DEV=${DEV:-DEVICE-UDID}
BID=com.example.ios27poc
IDENT="iPhone Distribution: <DEVELOPER> (<TEAMID>)"
KC="$HOME/Library/Keychains/dev.keychain-db"
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
ENTS="$ROOT/out/ents.plist"
HERE="$ROOT/harness/israce"
cd "$HERE"

echo "== 1/5 构建"
xcrun -sdk iphoneos clang -arch arm64 -miphoneos-version-min=16.0 -fobjc-arc \
  main.m -o Payload/UC.app/UC \
  -framework UIKit -framework Foundation -framework IOKit \
  -framework CoreFoundation -framework CoreGraphics -framework Metal

echo "== 2/5 签名"
security unlock-keychain -p "" "$KC" >/dev/null 2>&1 || true
codesign -s "$IDENT" --keychain "$KC" --entitlements "$ENTS" \
  --generate-entitlement-der -f Payload/UC.app 2>&1 | tail -3

echo "== 3/5 安装"
xcrun devicectl device install app --device "$DEV" Payload/UC.app

echo "== 4/5 启动"
xcrun devicectl device process launch --device "$DEV" --terminate-existing "$BID" || true
sleep 31     # 看门狗 27s + 收尾；< 35s 硬上限

echo "== 5/5 取回"
rm -f /tmp/israce.ndjson /tmp/israce.log
for f in israce.ndjson israce.log; do
  xcrun devicectl device copy from --device "$DEV" --domain-type appDataContainer \
    --domain-identifier "$BID" --source "tmp/$f" --destination "/tmp/$f" \
    >/dev/null 2>&1 || echo "  (缺 $f)"
done

if [ -f /tmp/israce.ndjson ]; then
  # 每回合独立存一份，再把 end 行并进总文件（同一 key 只留一次，按出现顺序）
  STAMP=$(date +%H%M%S)
  cp /tmp/israce.ndjson "$ROOT/out/israce/round-$STAMP.ndjson" 2>/dev/null || {
    mkdir -p "$ROOT/out/israce"; cp /tmp/israce.ndjson "$ROOT/out/israce/round-$STAMP.ndjson"; }
  echo "== 本回合 $(wc -l < /tmp/israce.ndjson) 行 -> out/israce/round-$STAMP.ndjson"
  python3 "$HERE/merge.py" "$ROOT/out/israce.ndjson" "$ROOT/out/israce/round-$STAMP.ndjson"
fi
[ -f /tmp/israce.log ] && cp /tmp/israce.log "$ROOT/out/israce/last.log"
echo "完成。"
