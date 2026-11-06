#!/bin/bash
# run.sh — svc2probe：build → 指纹校验 → 签名 → 安装 → 启动 → 取回 → panic 计数 → 归档。
#
#   ./run.sh <stage> [from] [to] [watchdogSec]
#   stage ∈ hid | jpeg | msc | mfb | clcd | all
#
# 一个 stage 一次进程运行：某个 selector 把内核调用挂死，只影响这一个 stage，
# 后面还有新进程可跑（app 内还有 3s/次 的线程级超时和 3 次超时即弃的 stage 熔断）。
#
# 五态分开写：build / sign / install / launch / 跑完。copy 的 stderr 单独打印，绝不 2>/dev/null。
set -uo pipefail

LOCKDIR=/tmp/ios27-device.lock.d
if [ "${SVC2PROBE_LOCKED:-0}" != "1" ]; then
  export SVC2PROBE_LOCKED=1
  N=0
  while ! mkdir "$LOCKDIR" 2>/dev/null; do
    N=$((N+1))
    if [ $N -gt 90 ]; then echo "!! 设备锁等待超过 180s，放弃"; exit 1; fi
    sleep 2
  done
  printf '%s pid=%s at %s\n' "svc2probe" "$$" "$(date +%H:%M:%S)" > "$LOCKDIR/owner" 2>/dev/null || true
  trap 'rm -rf "$LOCKDIR"' EXIT INT TERM
fi

DEV=${DEV:-DEVICE-UDID}
BID=com.example.ios27poc
IDENT="iPhone Distribution: <DEVELOPER> (<TEAMID>)"
KC="$HOME/Library/Keychains/dev.keychain-db"
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
ENTS="$ROOT/out/ents.plist"
HERE="$ROOT/harness/svc2probe"
FP="SVC2PROBE-20261101-extmethod-d7b3e2"
APP="$HERE/Payload/UC.app"
cd "$HERE" || exit 1

STAGE=${1:-hid}
FROM=${2:-0}
TO=${3:-4096}
WD=${4:-300}
TS() { date +%H:%M:%S; }
PCOUNT() { ls -1 "$ROOT"/out/panics/*.ips 2>/dev/null | wc -l | tr -d ' '; }

echo "== 0/7 设备锁状态 + panic 基线   stage=$STAGE range=[$FROM,$TO] wd=${WD}s"
LS=$(xcrun devicectl device info lockState --device "$DEV" 2>&1)
echo "$LS" | grep -E "passcodeRequired|unlockedSinceBoot|deviceIdentifier" | sed 's/^/   /'
if echo "$LS" | grep -q "passcodeRequired: true"; then
  echo "!! 设备锁屏（passcodeRequired: true）——解锁亮屏后重跑"; exit 2
fi
P0=$(PCOUNT)
echo "   panic .ips 基线 = $P0"

echo "== 1/7 [build] 编译 main.m   开始 $(TS)"
BUILD_ERR=$(xcrun -sdk iphoneos clang -arch arm64 -miphoneos-version-min=16.0 -fobjc-arc \
  main.m -o "$APP/UC" \
  -framework UIKit -framework Foundation -framework IOKit 2>&1)
BRC=$?
if [ $BRC -ne 0 ] || [ ! -s "$APP/UC" ]; then
  echo "   [build] FAILED rc=$BRC"; echo "$BUILD_ERR"; exit 1
fi
[ -n "$BUILD_ERR" ] && echo "$BUILD_ERR" | sed 's/^/   warn: /'
echo "   [build] OK size=$(stat -f%z "$APP/UC") sha256=$(shasum -a 256 "$APP/UC" | awk '{print $1}')"

echo "== 2/7 指纹校验（装的必须是本次二进制）"
NEWFP=$(strings "$APP/UC" | grep -c "$FP")
OLD1=$(strings "$APP/UC" | grep -c "GPUDUMP-20261101-bufdump-c3f7a1")
OLD2=$(strings "$APP/UC" | grep -c "SVCPROBE-20261101-matrix-9f4a21")
echo "   strings | grep $FP -> 命中=$NEWFP  (需 >=1)"
echo "   残留 gpuprobe=$OLD1  残留 svcprobe=$OLD2"
if [ "$NEWFP" -lt 1 ] || [ "$OLD1" -ne 0 ] || [ "$OLD2" -ne 0 ]; then
  echo "   !! 二进制与源码不一致，停止（不装）"; exit 1
fi

echo "== 3/7 [sign] 签名   开始 $(TS)"
security unlock-keychain -p "" "$KC" >/dev/null 2>&1 || true
SIGN_ERR=$(codesign -s "$IDENT" --keychain "$KC" --entitlements "$ENTS" \
  --generate-entitlement-der -f "$APP" 2>&1)
SRC=$?
if [ $SRC -ne 0 ]; then echo "   [sign] FAILED rc=$SRC:"; echo "$SIGN_ERR"; exit 1; fi
echo "$SIGN_ERR" | tail -3 | sed 's/^/   /'
echo "   [sign] OK"; codesign -dv "$APP" 2>&1 | grep -E "Identifier|TeamIdentifier" | sed 's/^/   /'

echo "== 4/7 [install] 安装   开始 $(TS)"
INST=$(xcrun devicectl device install app --device "$DEV" "$APP" 2>&1)
IRC=$?
echo "$INST" | tail -8 | sed 's/^/   /'
if [ $IRC -ne 0 ]; then echo "   [install] FAILED rc=$IRC"; exit 1; fi
echo "   [install] OK"

echo "== 5/7 [launch] 启动（--console，阻塞到进程退出）  $STAGE $FROM $TO $WD  开始 $(TS)"
xcrun devicectl device process launch --device "$DEV" --terminate-existing \
  --console "$BID" "$STAGE" "$FROM" "$TO" "$WD" 2>&1 | sed 's/^/   /'
LRC=${PIPESTATUS[0]}
echo "   [launch] console rc=$LRC   结束 $(TS)"

echo "== 6/7 取回（copy 的 stderr 单独打印）"
NB="$HERE/results/$STAGE.ndjson"
rm -f /tmp/svc2probe.ndjson /tmp/svc2probe.log /tmp/svc2probe.hb
for f in svc2probe.ndjson svc2probe.log svc2probe.hb; do
  ERR=$(xcrun devicectl device copy from --device "$DEV" --domain-type appDataContainer \
        --domain-identifier "$BID" --source "tmp/$f" --destination "/tmp/$f" 2>&1 >/dev/null)
  CPYRC=$?
  echo "   $f copy rc=$CPYRC size=$(stat -f%z "/tmp/$f" 2>/dev/null || echo MISSING)"
  if [ -n "$ERR" ]; then echo "   copy-stderr($f):"; echo "$ERR" | sed 's/^/     /'; fi
done

echo "== 7/7 [跑完] 判定 + panic 计数 + 归档"
P1=$(PCOUNT)
echo "   panic .ips：基线=$P0 现在=$P1"
if [ "$P1" -gt "$P0" ]; then
  echo "   !!!!! 新增 panic $((P1-P0)) 个 !!!!!"
  ls -1t "$ROOT"/out/panics/*.ips | head -n $((P1-P0)) | sed 's/^/     NEW: /'
fi

mkdir -p "$HERE/results"
STAMP=$(date +%Y%m%d-%H%M%S)
if [ -s /tmp/svc2probe.ndjson ]; then
  cp /tmp/svc2probe.ndjson "$HERE/results/$STAGE-$STAMP.ndjson"
  [ -f /tmp/svc2probe.log ] && cp /tmp/svc2probe.log "$HERE/results/$STAGE-$STAMP.log"
  [ -f /tmp/svc2probe.hb ]  && cp /tmp/svc2probe.hb  "$HERE/results/$STAGE-$STAMP.hb"
  echo "   @pre=$(grep -c '\"k\":\"@pre\"' /tmp/svc2probe.ndjson)  @r=$(grep -c '\"k\":\"@r\"' /tmp/svc2probe.ndjson)  @timeout=$(grep -c '\"k\":\"@timeout\"' /tmp/svc2probe.ndjson)  总行=$(wc -l < /tmp/svc2probe.ndjson)"
  grep -q '"k":"@done"' /tmp/svc2probe.ndjson && echo "   有 @done -> 跑完" || echo "   !! 没有 @done -> 中途崩溃/看门狗/panic"
  echo "   -> $HERE/results/$STAGE-$STAMP.ndjson"
else
  echo "   !! 零记录：没取到 svc2probe.ndjson（install 已成功、launch rc=$LRC）"
fi

echo; echo "===== $STAGE ndjson（逐字）====="; cat /tmp/svc2probe.ndjson 2>/dev/null
echo; echo "===== hb 尾部 3 行 ====="; tail -3 /tmp/svc2probe.hb 2>/dev/null
echo "完成。"
