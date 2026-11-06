#!/bin/bash
# run.sh — svcreenum：build → 指纹 → 签名 → 安装 → 启动 → 取回 → panic 计数 → 归档。
#
#   ./run.sh <tag> <svc> <type> [key=val ...]
#     例：./run.sh msc AppleM2ScalerCSCDriver 0 from=0 to=31
#         ./run.sh agx1 AGXAcceleratorG18P 1 from=0 to=255
#
# 纪律：
#   - 装前 strings 指纹必须命中 >=1 且残余旧指纹为 0（不一致就不装）
#   - copy from 的 stderr 单独打印，绝不 2>/dev/null
#   - 不重启设备
#   - 五态分开写：build / sign / install / launch / 跑完
#   - 锁屏（SBMainWorkspace reason: Locked）不反复硬重试：写一行 @locked，等 60s 再来，最多 10 分钟
#   - 一个 selector 挂死不影响后面（app 内 3s 线程级超时 + 同 selector 2 次即跳过）
set -uo pipefail

LOCKDIR=/tmp/ios27-device.lock.d
if [ "${SVCR_LOCKED:-0}" != "1" ]; then
  export SVCR_LOCKED=1
  N=0
  while ! mkdir "$LOCKDIR" 2>/dev/null; do
    N=$((N+1))
    if [ $N -gt 90 ]; then echo "!! 设备锁等待超过 180s，放弃"; exit 1; fi
    sleep 2
  done
  printf '%s pid=%s at %s\n' "svcreenum" "$$" "$(date +%H:%M:%S)" > "$LOCKDIR/owner" 2>/dev/null || true
  trap 'rm -rf "$LOCKDIR"' EXIT INT TERM
fi

DEV=${DEV:-DEVICE-UDID}
BID=com.example.ios27poc
IDENT="iPhone Distribution: <DEVELOPER> (<TEAMID>)"
KC="$HOME/Library/Keychains/dev.keychain-db"
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
ENTS="$ROOT/out/ents.plist"
HERE="$ROOT/harness/svcreenum"
FP="REENUM-20261101-svcladder-b7f2e1"
APP="$HERE/Payload/UC.app"
cd "$HERE" || exit 1

TAG=${1:-msc}
SVC=${2:-AppleM2ScalerCSCDriver}
TYPE=${3:-0}
STAGE=${STAGE:-exist}   # app argv[1]：exist | contract | dense | warm
shift 3 2>/dev/null || true
EXTRA=("$@")
WD=$(printf '%s\n' "${EXTRA[@]:-}" | sed -n 's/^wd=//p' | head -1); WD=${WD:-900}

# SELRANGE=0-31 时自动展开成 sels=0,1,...,31（contract 阶段需要显式列表）
if [ -n "${SELRANGE:-}" ]; then
  LO=${SELRANGE%-*}; HI=${SELRANGE#*-}
  EXTRA+=("sels=$(seq -s, "$LO" "$HI")")
fi

TS() { date +%H:%M:%S; }
PCOUNT() { ls -1 "$ROOT"/out/panics/*.ips 2>/dev/null | wc -l | tr -d ' '; }
mkdir -p "$HERE/results"

echo "== 0/7 设备锁状态 + panic 基线   tag=$TAG stage=$STAGE svc=$SVC type=$TYPE wd=${WD}s extra=${EXTRA[*]:-无}"
LS=$(xcrun devicectl device info lockState --device "$DEV" 2>&1)
echo "$LS" | grep -E "passcodeRequired|unlockedSinceBoot|deviceIdentifier" | sed 's/^/   /'
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
OLD1=$(strings "$APP/UC" | grep -c "M2RE-20261101-reenum-c4d81b")
OLD2=$(strings "$APP/UC" | grep -c "SVC2PROBE-20261101-extmethod-d7b3e2")
OLD3=$(strings "$APP/UC" | grep -c "M2OP-20261101-sel11opcode-a91f4c")
echo "   strings | grep REENUM-... -> 命中=$NEWFP  (需 >=1)"
echo "   残留 m2reenum=$OLD1 svc2probe=$OLD2 m2op=$OLD3  (需全 0)"
if [ "$NEWFP" -lt 1 ] || [ "$OLD1" -ne 0 ] || [ "$OLD2" -ne 0 ] || [ "$OLD3" -ne 0 ]; then
  echo "   !! 二进制与源码不一致，停止（不装）"; exit 1
fi

echo "== 3/7 [sign] 签名   开始 $(TS)"
security unlock-keychain -p "" "$KC" >/dev/null 2>&1 || true
SIGN_ERR=$(codesign -s "$IDENT" --keychain "$KC" --entitlements "$ENTS" \
  --generate-entitlement-der -f "$APP" 2>&1)
SRC=$?
if [ $SRC -ne 0 ]; then echo "   [sign] FAILED rc=$SRC:"; echo "$SIGN_ERR"; exit 1; fi
[ -n "$SIGN_ERR" ] && echo "$SIGN_ERR" | tail -3 | sed 's/^/   /'
echo "   [sign] OK"; codesign -dv "$APP" 2>&1 | grep -E "Identifier|TeamIdentifier" | sed 's/^/   /'

echo "== 4/7 [install] 安装   开始 $(TS)"
INST=$(xcrun devicectl device install app --device "$DEV" "$APP" 2>&1)
IRC=$?
echo "$INST" | tail -6 | sed 's/^/   /'
if [ $IRC -ne 0 ]; then echo "   [install] FAILED rc=$IRC"; exit 1; fi
echo "   [install] OK"

echo "== 5/7 [launch] 启动（--console，阻塞到进程退出）  stage=$STAGE $SVC type=$TYPE ${EXTRA[*]:-}  开始 $(TS)"
LOCKLOG="$HERE/results/locked.log"
WAITED=0; TRY=0; LAUNCH_OK=0
while :; do
  LO=$(xcrun devicectl device process launch --device "$DEV" --terminate-existing \
        --console "$BID" "$STAGE" "$SVC" "$TYPE" ${EXTRA[@]+"${EXTRA[@]}"} 2>&1)
  LRC=$?
  if echo "$LO" | grep -qi "reason: Locked\|is locked\|device was locked"; then
    printf '{"k":"@locked","tag":"%s","svc":"%s","type":%s,"t":"%s","waited_s":%d}\n' \
      "$TAG" "$SVC" "$TYPE" "$(date +%H:%M:%S)" "$WAITED" | tee -a "$LOCKLOG"
    if [ "$WAITED" -ge 600 ]; then echo "   !! 锁屏已等 600s，放弃本 stage"; break; fi
    sleep 60; WAITED=$((WAITED+60)); continue
  fi
  # 瞬时隧道抖动（Device disconnected during socket operation）不是锁屏，也不是「跑完」。
  # 只重试 3 次、每次 5s，避免把陈旧结果当成新结果。
  if [ $LRC -ne 0 ] && echo "$LO" | grep -qi "disconnected during socket\|SocketManagerError\|error 10002"; then
    TRY=$((TRY+1))
    if [ "$TRY" -le 3 ]; then
      echo "   [launch] 瞬时隧道错误，5s 后重试 ($TRY/3)"
      sleep 5; continue
    fi
  fi
  echo "$LO" | sed 's/^/   /'
  if [ $LRC -eq 0 ]; then LAUNCH_OK=1; fi
  echo "   [launch] console rc=$LRC   结束 $(TS)"
  break
done
if [ "$LAUNCH_OK" != "1" ]; then
  echo "   !! launch 未成功 —— 本轮不产出结果（incomplete 状态）"
fi

echo "== 6/7 取回（copy 的 stderr 单独打印）"
rm -f /tmp/svcreenum.ndjson /tmp/svcreenum.log /tmp/svcreenum.hb
for f in svcreenum.ndjson svcreenum.log svcreenum.hb; do
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

STAMP=$(date +%Y%m%d-%H%M%S)
META=$(grep -m1 '"k":"@meta"' /tmp/svcreenum.ndjson 2>/dev/null)
if [ -n "$META" ]; then
  META_OK=$(printf '%s' "$META" | grep -c "\"svc\":\"$SVC\",\"type\":$TYPE")
else
  META_OK=0
fi
echo "   取回内容 @meta 与本次请求一致: ${META_OK:-0} (需 1)"
if [ "$META_OK" != "1" ]; then
  echo "   !! 取回的是陈旧/异常文件（svc=$SVC type=$TYPE 没出现）—— 不归档，标记 incomplete"
fi

if [ "$META_OK" = "1" ] && [ -s /tmp/svcreenum.ndjson ]; then
  cp /tmp/svcreenum.ndjson "$HERE/results/$TAG-$STAGE-$STAMP.ndjson"
  [ -f /tmp/svcreenum.log ] && cp /tmp/svcreenum.log "$HERE/results/$TAG-$STAGE-$STAMP.log"
  [ -f /tmp/svcreenum.hb ]  && cp /tmp/svcreenum.hb  "$HERE/results/$TAG-$STAGE-$STAMP.hb"
  echo "   @pre=$(grep -c '"k":"@pre"' /tmp/svcreenum.ndjson)  @r=$(grep -c '"k":"@r"' /tmp/svcreenum.ndjson)  @sel=$(grep -c '"k":"@sel"' /tmp/svcreenum.ndjson)  @h=$(grep -c '"k":"@h"' /tmp/svcreenum.ndjson)  @hang=$(grep -c '"k":"@hang"' /tmp/svcreenum.ndjson)  @timeout=$(grep -c '"k":"@timeout"' /tmp/svcreenum.ndjson)  总行=$(wc -l < /tmp/svcreenum.ndjson)"
  grep -q '"k":"@done"' /tmp/svcreenum.ndjson && echo "   有 @done -> 跑完" || echo "   !! 没有 @done -> 中途崩溃/看门狗/panic"
  echo "   -> $HERE/results/$TAG-$STAGE-$STAMP.ndjson"
else
  echo "   !! 零记录：没取到 svcreenum.ndjson"
fi

echo; echo "===== @open / @meta / @warm / @plan ====="
grep -E '"k":"@(open|meta|warm|plan)"' /tmp/svcreenum.ndjson 2>/dev/null | head -12
echo; echo "===== @sel 汇总（存在的）====="
grep '"k":"@sel"' /tmp/svcreenum.ndjson 2>/dev/null | grep '"exists":1' | head -60
echo; echo "===== @stat / @done / @hang ====="
grep -E '"k":"@(stat|done|hang|abort|watchdog)"' /tmp/svcreenum.ndjson 2>/dev/null | head -20
echo "完成。"
