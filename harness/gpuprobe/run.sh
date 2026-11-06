#!/bin/bash
# run.sh — gpuprobe：build → 指纹校验 → 签名 → 安装 → 启动 → 取回 → panic 计数。
# 五态分开写：build / sign / install / launch / 跑完。
# 不动 harness/israce/main.m，不动 israce/Payload，不改 out/ 既有文件。
#
#   ./run.sh            一次完整回合
#
# 前置：设备解锁亮屏（脚本自己查 lockState，锁屏直接 exit 2，不瞎跑）。
set -uo pipefail

LOCKDIR=/tmp/ios27-device.lock.d
if [ "${GPUPROBE_LOCKED:-0}" != "1" ]; then
  export GPUPROBE_LOCKED=1
  N=0
  while ! mkdir "$LOCKDIR" 2>/dev/null; do
    N=$((N+1))
    if [ $N -gt 90 ]; then echo "!! 设备锁等待超过 180s，放弃"; exit 1; fi
    sleep 2
  done
  printf '%s pid=%s at %s\n' "gpuprobe" "$$" "$(date +%H:%M:%S)" > "$LOCKDIR/owner" 2>/dev/null || true
  trap 'rm -rf "$LOCKDIR"' EXIT INT TERM
fi

DEV=${DEV:-DEVICE-UDID}
BID=com.example.ios27poc
IDENT="iPhone Distribution: <DEVELOPER> (<TEAMID>)"
KC="$HOME/Library/Keychains/dev.keychain-db"
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
ENTS="$ROOT/out/ents.plist"
HERE="$ROOT/harness/gpuprobe"
FP="GPUPROBE-20261101-sel168-a71c4e"
APP="$HERE/Payload/UC.app"
cd "$HERE" || exit 1

# 可选选段：./run.sh [from] [to]   （缺省 0 168 = 全量）
FROM=${1:-0}
TO=${2:-168}
WD=${3:-150}     # watchdog 秒
MODE=${4:-0}     # 0=两遍 1=只第一遍 2=只第二遍
RANGE_ARGS=""
if [ "${1:-}" != "" ]; then RANGE_ARGS="$FROM $TO $WD $MODE"; fi
TS() { date +%H:%M:%S; }

PCOUNT() { ls -1 "$ROOT"/out/panics/*.ips 2>/dev/null | wc -l | tr -d ' '; }

echo "== 0/7 设备锁状态 + panic 基线"
LS=$(xcrun devicectl device info lockState --device "$DEV" 2>&1)
echo "$LS" | grep -E "passcodeRequired|unlockedSinceBoot|deviceIdentifier" | sed 's/^/   /'
if echo "$LS" | grep -q "passcodeRequired: true"; then
  echo "!! 设备锁屏（passcodeRequired: true）——请解锁亮屏后重跑"; exit 2
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
echo "   [build] OK  size=$(stat -f%z "$APP/UC")  sha256=$(shasum -a 256 "$APP/UC" | awk '{print $1}')"

echo "== 2/7 指纹校验（装的必须是本次二进制）"
NEWFP=$(strings "$APP/UC" | grep -c "$FP")
OLDOLD=$(strings "$APP/UC" | grep -c "diag1-portdiag")
OLD2=$(strings "$APP/UC" | grep -c "SVCPROBE-20261101-matrix-9f4a21")
echo "   strings | grep $FP  -> 命中=$NEWFP   (需 =1)"
echo "   残留 israce(diag1-portdiag)=$OLDOLD  残留 svcprobe=$OLD2"
if [ "$NEWFP" -lt 1 ] || [ "$OLDOLD" -ne 0 ] || [ "$OLD2" -ne 0 ]; then
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

echo "== 5/7 [launch] 启动（--console，阻塞到进程自己退出）  range=[${FROM},${TO}) wd=${WD}s mode=${MODE}  开始 $(TS)"
if [ -n "$RANGE_ARGS" ]; then
  xcrun devicectl device process launch --device "$DEV" --terminate-existing \
    --console "$BID" $RANGE_ARGS 2>&1 | sed 's/^/   /'
else
  xcrun devicectl device process launch --device "$DEV" --terminate-existing \
    --console "$BID" 2>&1 | sed 's/^/   /'
fi
LRC=${PIPESTATUS[0]}
echo "   [launch] console rc=$LRC   结束 $(TS)"

echo "== 6/7 取回（copy 的 stderr 单独打印，绝不 2>/dev/null）"
rm -f /tmp/gpuprobe.ndjson /tmp/gpuprobe.log /tmp/gpuprobe.hb
for f in gpuprobe.ndjson gpuprobe.log gpuprobe.hb; do
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
  NEW=$(ls -1t "$ROOT"/out/panics/*.ips | head -n $((P1-P0)))
  echo "$NEW" | sed 's/^/     NEW: /'
fi

mkdir -p "$HERE/results"
STAMP=$(date +%Y%m%d-%H%M%S)
if [ -s /tmp/gpuprobe.ndjson ]; then
  cp /tmp/gpuprobe.ndjson "$HERE/results/gpuprobe-$STAMP.ndjson"
  [ -f /tmp/gpuprobe.log ] && cp /tmp/gpuprobe.log "$HERE/results/gpuprobe-$STAMP.log"
  [ -f /tmp/gpuprobe.hb ] && cp /tmp/gpuprobe.hb "$HERE/results/gpuprobe-$STAMP.hb"
  echo "   @pre 行数=$(grep -c '\"k\":\"@pre\"' /tmp/gpuprobe.ndjson)  @sel 行数=$(grep -c '\"k\":\"@sel\"' /tmp/gpuprobe.ndjson)  总行数=$(wc -l < /tmp/gpuprobe.ndjson)"
  grep -q '"k":"@done"' /tmp/gpuprobe.ndjson && echo "   有 @done -> 第一遍+第二遍都跑完" || echo "   !! 没有 @done -> 中途崩溃/看门狗/panic"
  echo "   -> $HERE/results/gpuprobe-$STAMP.ndjson"
else
  echo "   !! 零记录：没取到 gpuprobe.ndjson（install 已成功、launch rc=$LRC）"
fi

echo; echo "===== gpuprobe.ndjson（逐字）====="; cat /tmp/gpuprobe.ndjson 2>/dev/null
echo; echo "===== gpuprobe.hb 尾部 5 行 ====="; tail -5 /tmp/gpuprobe.hb 2>/dev/null
echo "完成。"
