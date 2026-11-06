#!/bin/bash
# run.sh — mfbcontract：三个 IOVA-like 返回值控制性判定 + MFB 47 selector 契约 + dump。
#
#   ./run.sh prep                      build → 指纹 → 签名 → 安装（只做一次）
#   ./run.sh stage <name> [k=v ...]    启动一个 stage（独立进程）→ 取回 → 归档
#
# 五态分开写：build / sign / install / launch / 跑完。copy 的 stderr 单独打印，绝不 2>/dev/null。
# 不重启设备。不改 out/ 既有文件。不 git。
set -uo pipefail

DEV=${DEV:-DEVICE-UDID}
BID=com.example.ios27poc
IDENT="iPhone Distribution: <DEVELOPER> (<TEAMID>)"
KC="$HOME/Library/Keychains/dev.keychain-db"
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
ENTS="$ROOT/out/ents.plist"
HERE="$ROOT/harness/mfbcontract"
FP="MFBCON-20261101-contract-9c4e17"
APP="$HERE/Payload/UC.app"
cd "$HERE" || exit 1

TS() { date +%H:%M:%S; }
PCOUNT() { ls -1 "$ROOT"/out/panics/*.ips 2>/dev/null | wc -l | tr -d ' '; }

lock_acquire() {
  LOCKDIR=/tmp/ios27-device.lock.d
  if [ "${MFBCON_LOCKED:-0}" = "1" ]; then return 0; fi
  export MFBCON_LOCKED=1
  N=0
  while ! mkdir "$LOCKDIR" 2>/dev/null; do
    N=$((N+1))
    if [ $N -gt 90 ]; then echo "!! 设备锁等待超过 180s，放弃"; exit 1; fi
    sleep 2
  done
  printf '%s pid=%s at %s\n' "mfbcontract" "$$" "$(date +%H:%M:%S)" > "$LOCKDIR/owner" 2>/dev/null || true
  trap 'rm -rf "$LOCKDIR"' EXIT INT TERM
}
lock_acquire

check_lock() {
  LS=$(xcrun devicectl device info lockState --device "$DEV" 2>&1)
  echo "$LS" | grep -E "passcodeRequired|unlockedSinceBoot" | sed 's/^/   /'
  if echo "$LS" | grep -q "passcodeRequired: true"; then
    echo "!! 设备锁屏（passcodeRequired: true）——解锁亮屏后重跑"; exit 2
  fi
}

CMD=${1:-prep}

if [ "$CMD" = "prep" ]; then
  rm -f "$HERE/.buildstamp"
  echo "== 0/6 设备锁状态 + panic 基线"
  check_lock
  P0=$(PCOUNT); echo "   panic .ips 基线 = $P0"

  echo "== 1/6 [build] 编译 main.m   开始 $(TS)"
  BUILD_ERR=$(xcrun -sdk iphoneos clang -arch arm64 -miphoneos-version-min=16.0 -fobjc-arc \
    main.m -o "$APP/UC" \
    -framework UIKit -framework Foundation -framework IOKit 2>&1)
  BRC=$?
  if [ $BRC -ne 0 ] || [ ! -s "$APP/UC" ]; then
    echo "   [build] FAILED rc=$BRC"; echo "$BUILD_ERR"; exit 1
  fi
  [ -n "$BUILD_ERR" ] && echo "$BUILD_ERR" | sed 's/^/   warn: /'
  echo "   [build] OK size=$(stat -f%z "$APP/UC") sha256=$(shasum -a 256 "$APP/UC" | awk '{print $1}')"
  # 把嵌进二进制的 __DATE__ __TIME__ 戳记下来，stage 侧用它校验取回文件确实来自这个二进制
  strings "$APP/UC" | grep -E '^[A-Z][a-z]{2} [ 0-9][0-9] [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}$' | head -1 > "$HERE/.buildstamp"
  echo "   [build] 二进制内建戳记 = $(cat "$HERE/.buildstamp")"

  echo "== 2/6 指纹校验（装的必须是本次二进制）"
  NEWFP=$(strings "$APP/UC" | grep -c "$FP")
  OLD1=$(strings "$APP/UC" | grep -c "SEL7-20261101-addrprobe")
  OLD2=$(strings "$APP/UC" | grep -c "REENUM-20261101-svcladder")
  echo "   strings | grep $FP -> 命中=$NEWFP  (需 >=1)"
  echo "   残留 sel7addr=$OLD1 svcreenum=$OLD2"
  if [ "$NEWFP" -lt 1 ] || [ "$OLD1" -ne 0 ] || [ "$OLD2" -ne 0 ]; then
    echo "   !! 二进制与源码不一致，停止（不装）"; exit 1
  fi

  echo "== 3/6 [sign]   开始 $(TS)"
  security unlock-keychain -p "" "$KC" >/dev/null 2>&1 || true
  SIGN_ERR=$(codesign -s "$IDENT" --keychain "$KC" --entitlements "$ENTS" \
    --generate-entitlement-der -f "$APP" 2>&1)
  SRC=$?
  if [ $SRC -ne 0 ]; then echo "   [sign] FAILED rc=$SRC:"; echo "$SIGN_ERR"; exit 1; fi
  [ -n "$SIGN_ERR" ] && echo "$SIGN_ERR" | tail -3 | sed 's/^/   /'
  echo "   [sign] OK"; codesign -dv "$APP" 2>&1 | grep -E "Identifier|TeamIdentifier" | sed 's/^/   /'

  echo "== 4/6 [install]   开始 $(TS)"
  INST=$(xcrun devicectl device install app --device "$DEV" "$APP" 2>&1)
  IRC=$?
  echo "$INST" | tail -6 | sed 's/^/   /'
  if [ $IRC -ne 0 ]; then echo "   [install] FAILED rc=$IRC"; exit 1; fi
  echo "   [install] OK"
  echo "prep 完成 $P0"
  exit 0
fi

if [ "$CMD" = "stage" ]; then
  STAGE=${2:-iova}; shift 2 || true
  EXTRA=("$@")
  check_lock >/dev/null
  P0=$(PCOUNT)
  echo "== stage=$STAGE args=${EXTRA[*]:-无}   panic 基线=$P0   开始 $(TS)"

  rm -f /tmp/mfbcon.ndjson /tmp/mfbcon.log /tmp/mfbcon.hb
  xcrun devicectl device process launch --device "$DEV" --terminate-existing \
    --console "$BID" "$STAGE" ${EXTRA[@]+"${EXTRA[@]}"} 2>&1 | sed 's/^/   /'
  LRC=${PIPESTATUS[0]:-1}
  echo "   [launch] console rc=$LRC   结束 $(TS)"

  for f in mfbcon.ndjson mfbcon.log mfbcon.hb; do
    ERR=$(xcrun devicectl device copy from --device "$DEV" --domain-type appDataContainer \
          --domain-identifier "$BID" --source "tmp/$f" --destination "/tmp/$f" 2>&1 >/dev/null)
    CPYRC=$?
    echo "   $f copy rc=$CPYRC size=$(stat -f%z "/tmp/$f" 2>/dev/null || echo MISSING)"
    if [ -n "$ERR" ]; then echo "   copy-stderr($f):"; echo "$ERR" | sed 's/^/     /'; fi
  done

  # @meta 校验：取回文件的 stage 必须等于本次请求的 stage
  if [ -s /tmp/mfbcon.ndjson ]; then
    MF=$(grep -m1 '"k":"@meta"' /tmp/mfbcon.ndjson | sed -E 's/.*"stage":"([^"]*)".*/\1/')
    MF_FP=$(grep -m1 '"k":"@meta"' /tmp/mfbcon.ndjson | sed -E 's/.*"fp":"([^"]*)".*/\1/')
    echo "   @meta 校验：file.stage=$MF  要求=$STAGE  fp=$MF_FP"
    if [ "$MF" != "$STAGE" ] || [ "$MF_FP" != "$FP" ]; then
      echo "   !! @meta 不匹配 —— 这是旧文件，不归档"
      exit 1
    fi
  fi

  P1=$(PCOUNT)
  echo "   panic .ips：基线=$P0 现在=$P1"
  if [ "$P1" -gt "$P0" ]; then
    echo "   !!!!! 新增 panic $((P1-P0)) 个 !!!!!"
    ls -1t "$ROOT"/out/panics/*.ips | head -n $((P1-P0)) | sed 's/^/     NEW: /'
  fi

  STAMP=$(date +%Y%m%d-%H%M%S)
  SAFE=$(echo "$STAGE" | tr -c 'a-zA-Z0-9._-' '_')
  if [ -s /tmp/mfbcon.ndjson ]; then
    cp /tmp/mfbcon.ndjson "$HERE/results/$SAFE-$STAMP.ndjson"
    [ -f /tmp/mfbcon.log ] && cp /tmp/mfbcon.log "$HERE/results/$SAFE-$STAMP.log"
    [ -f /tmp/mfbcon.hb ]  && cp /tmp/mfbcon.hb  "$HERE/results/$SAFE-$STAMP.hb"
    echo "   总行=$(wc -l < /tmp/mfbcon.ndjson)  @iova=$(grep -c '"k":"@iova"' /tmp/mfbcon.ndjson)  @hit=$(grep -c '"k":"@hit"' /tmp/mfbcon.ndjson)  @kscan=$(grep -c '"k":"@kscan"' /tmp/mfbcon.ndjson)  @timeout=$(grep -c '"k":"@timeout"' /tmp/mfbcon.ndjson)"
    grep -q '"k":"@done"' /tmp/mfbcon.ndjson && echo "   有 @done -> 跑完" || echo "   !! 没有 @done -> 中途崩溃/看门狗/panic"
    echo "   -> $HERE/results/$SAFE-$STAMP.ndjson"
  else
    echo "   !! 零记录：没取到 mfbcon.ndjson（launch rc=$LRC）"
  fi

  echo "----- @done -----"
  grep '"k":"@done"' /tmp/mfbcon.ndjson 2>/dev/null | sed 's/^/   /'
  echo "----- 尾 4 行 -----"
  tail -4 /tmp/mfbcon.ndjson 2>/dev/null | sed 's/^/   /'
  exit 0
fi

echo "用法: $0 prep | $0 stage <name> [k=v ...]"
exit 2
