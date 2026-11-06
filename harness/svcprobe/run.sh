#!/bin/bash
# run.sh — svcprobe：build → 指纹校验 → 签名 → 安装 → launch --console（等进程自己退出）→ 取回。
# 不动 harness/israce/main.m，不动 israce/Payload，不动 out/ 既有文件。
#
#   ./run.sh
#
# 前置：设备解锁亮屏。脚本先查 lockState，锁屏直接退出（exit 2）。
set -uo pipefail

# 设备独占锁，与 israce/run.sh、israce/probe-run.sh 同一把 mkdir 锁
LOCKDIR=/tmp/ios27-device.lock.d
if [ "${SVCPROBE_LOCKED:-0}" != "1" ]; then
  export SVCPROBE_LOCKED=1
  N=0
  while ! mkdir "$LOCKDIR" 2>/dev/null; do
    N=$((N+1))
    if [ $N -gt 90 ]; then echo "!! 设备锁等待超过 180s，放弃"; exit 1; fi
    sleep 2
  done
  printf '%s pid=%s at %s\n' "svcprobe" "$$" "$(date +%H:%M:%S)" > "$LOCKDIR/owner" 2>/dev/null || true
  trap 'rm -rf "$LOCKDIR"' EXIT INT TERM
fi

DEV=${DEV:-DEVICE-UDID}
BID=com.example.ios27poc
IDENT="iPhone Distribution: <DEVELOPER> (<TEAMID>)"
KC="$HOME/Library/Keychains/dev.keychain-db"
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
ENTS="$ROOT/out/ents.plist"
HERE="$ROOT/harness/svcprobe"
FP="SVCPROBE-20261101-matrix-9f4a21"
APP="$HERE/Payload/UC.app"
cd "$HERE" || exit 1

echo "== 0/8 设备锁状态"
LS=$(xcrun devicectl device info lockState --device "$DEV" 2>&1)
echo "$LS" | grep -E "passcodeRequired|unlockedSinceBoot|deviceIdentifier" | sed 's/^/   /'
if echo "$LS" | grep -q "passcodeRequired: true"; then
  echo "!! 设备锁屏（passcodeRequired: true）——请解锁亮屏后重跑"; exit 2
fi

echo "== 1/8 构建 main.m"
BUILD_ERR=$(xcrun -sdk iphoneos clang -arch arm64 -miphoneos-version-min=16.0 -fobjc-arc \
  main.m -o "$APP/UC" \
  -framework UIKit -framework Foundation -framework IOKit 2>&1)
BRC=$?
if [ $BRC -ne 0 ] || [ ! -s "$APP/UC" ]; then
  echo "!! build 失败 (rc=$BRC)"; echo "$BUILD_ERR"; exit 1
fi
[ -n "$BUILD_ERR" ] && echo "$BUILD_ERR" | sed 's/^/   warn: /'

echo "== 2/8 指纹校验（装的必须是 svcprobe 的新二进制）"
NEWFP=$(strings "$APP/UC" | grep -c "$FP")
OLD=$(strings "$APP/UC" | grep -c "diag1-portdiag")
OLDPORT=$(strings "$APP/UC" | grep -c "PORTPROBE-20261101-7c3f9d")
echo "   ${FP} 命中=${NEWFP}   israce/main.m 残留 diag1-portdiag=${OLD}  portprobe=${OLDPORT}"
echo "   sha256 $(shasum -a 256 "$APP/UC" | awk '{print $1}')  size=$(stat -f%z "$APP/UC")"
echo "   名字表命中 IOSurfaceRoot=$(strings "$APP/UC" | grep -c IOSurfaceRoot) IOMobileGraphicsFamily=$(strings "$APP/UC" | grep -c IOMobileGraphicsFamily)"
if [ "$NEWFP" -lt 1 ] || [ "$OLD" -ne 0 ] || [ "$OLDPORT" -ne 0 ]; then
  echo "!! 二进制与源码不一致，停止"; exit 1
fi

echo "== 3/8 签名"
security unlock-keychain -p "" "$KC" >/dev/null 2>&1 || true
SIGN_ERR=$(codesign -s "$IDENT" --keychain "$KC" --entitlements "$ENTS" \
  --generate-entitlement-der -f "$APP" 2>&1)
SRC=$?
if [ $SRC -ne 0 ]; then echo "!! 签名失败 (rc=$SRC):"; echo "$SIGN_ERR"; exit 1; fi
echo "$SIGN_ERR" | tail -3 | sed 's/^/   /'
codesign -dv "$APP" 2>&1 | grep -E "Identifier|TeamIdentifier" | sed 's/^/   /'

echo "== 4/8 安装"
INST=$(xcrun devicectl device install app --device "$DEV" "$APP" 2>&1)
IRC=$?
echo "$INST" | tail -8 | sed 's/^/   /'
if [ $IRC -ne 0 ]; then echo "!! install 失败 (rc=$IRC)"; exit 1; fi

echo "== 5/8 启动（--console，阻塞到进程自己退出；不 sleep 不轮询）"
xcrun devicectl device process launch --device "$DEV" --terminate-existing \
  --console "$BID" 2>&1 | sed 's/^/   /'
LRC=${PIPESTATUS[0]}
echo "   launch/console rc=$LRC"

echo "== 6/8 取回（copy 的 stderr 单独打印，不吞）"
rm -f /tmp/svcprobe.log /tmp/svcprobe.ndjson
for f in svcprobe.ndjson svcprobe.log; do
  # stdout 丢弃，stderr 单独捕获并原样打印：copy 失败不能被当成空文件
  ERR=$(xcrun devicectl device copy from --device "$DEV" --domain-type appDataContainer \
        --domain-identifier "$BID" --source "tmp/$f" --destination "/tmp/$f" 2>&1 >/dev/null)
  CPYRC=$?
  echo "   $f copy rc=$CPYRC size=$(stat -f%z "/tmp/$f" 2>/dev/null || echo MISSING)"
  if [ -n "$ERR" ]; then echo "   copy-stderr($f):"; echo "$ERR" | sed 's/^/     /'; fi
done

echo "== 7/8 结果"
if [ ! -s /tmp/svcprobe.ndjson ]; then
  echo "!! 零记录：没取到 svcprobe.ndjson（区分：install 已成功、launch rc=$LRC）"
  exit 3
fi
LINES=$(grep -c '"k":"@svc"' /tmp/svcprobe.ndjson || true)
echo "   @svc 行数=$LINES  总行数=$(wc -l < /tmp/svcprobe.ndjson)"
grep -q '"s":"@done"' /tmp/svcprobe.ndjson && echo "   有 @done 尾标记 -> 跑完了" || echo "   !! 没有 @done -> 中途崩溃/看门狗"
[ -n "${ERR:-}" ] && echo "   (最后一处 copy stderr 已在上方打印)"

echo "== 8/8 归档副本（不覆盖 out/ 既有文件）"
mkdir -p "$HERE/results"
STAMP=$(date +%Y%m%d-%H%M%S)
cp /tmp/svcprobe.ndjson "$HERE/results/svcprobe-$STAMP.ndjson"
[ -f /tmp/svcprobe.log ] && cp /tmp/svcprobe.log "$HERE/results/svcprobe-$STAMP.log"
echo "   -> $HERE/results/svcprobe-$STAMP.ndjson"

echo
echo "===== svcprobe.ndjson ====="
cat /tmp/svcprobe.ndjson
echo
echo "完成。"
