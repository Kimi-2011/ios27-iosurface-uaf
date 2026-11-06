#!/bin/bash
# run.sh — OOLPROBE 单次完整回合：build → 指纹 → 签名 → 安装 → 启动 → 取回 → panic 归档
#
#   一次装一个二进制，把 A/B/C/D 四个假设全跑完（不再分轮 install）。
#
# 设备 panic 是预期结果：脚本会等设备重启回来，再把 progress.txt / 日志取回，
# 并把新增的 panic .ips 全文复制到 harness/oolprobe/panic-<触发参数>.ips
#
#   ./run.sh            跑一轮
set -uo pipefail

LOCKDIR=/tmp/ios27-device.lock.d
if [ "${OOLP_LOCKED:-0}" != "1" ]; then
  export OOLP_LOCKED=1
  n=0
  while ! mkdir "$LOCKDIR" 2>/dev/null; do
    n=$((n+1)); [ $n -gt 150 ] && { echo "!! 设备锁等待超过 300s，放弃"; exit 1; }
    sleep 2
  done
  printf 'oolprobe pid=%s at %s\n' "$$" "$(date +%H:%M:%S)" > "$LOCKDIR/owner" 2>/dev/null || true
  trap 'rm -rf "$LOCKDIR"' EXIT INT TERM
fi

DEV=${DEV:-DEVICE-UDID}
BID=com.example.ios27poc
IDENT="iPhone Distribution: <DEVELOPER> (<TEAMID>)"
KC="$HOME/Library/Keychains/dev.keychain-db"
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
HERE="$ROOT/harness/oolprobe"
APP="$HERE/Payload/UC.app"
ENTS="$ROOT/out/ents.plist"
FP="OOLPROBE-20261101-a91f3c7e"
PAN="$ROOT/out/panics"

cd "$HERE" || exit 1
TS=$(date '+%Y-%m-%d %H:%M:%S')

PCOUNT() { ls -1 "$PAN"/*.ips 2>/dev/null | wc -l | tr -d ' '; }

# 设备是否在线（available）
DEVLIVE() {
  xcrun devicectl list devices 2>/dev/null | grep -F "DEVICE-UDID" | grep -q "available"
}

echo "================= OOLPROBE $(date '+%H:%M:%S') ================="
P0=$(PCOUNT)
echo "[基线] panic .ips 个数 = $P0"

echo "== 0/9 设备锁状态"
LS=$(xcrun devicectl device info lockState --device "$DEV" 2>&1)
echo "$LS" | grep -E "passcodeRequired" | sed 's/^/   /'
if echo "$LS" | grep -q "passcodeRequired: true"; then
  echo "!! 设备锁屏，停止（不解锁、不瞎跑）"; exit 2
fi

echo "== 1/9 构建"
xcrun -sdk iphoneos clang -arch arm64 -miphoneos-version-min=16.0 -fobjc-arc \
  -Wno-deprecated-declarations -Wno-unused-function \
  main.m -o "$APP/UC" -framework UIKit -framework Foundation 2>&1 | tail -20
[ -s "$APP/UC" ] || { echo "!! 构建产物为空"; exit 1; }

echo "== 2/9 指纹校验（装的必须是 oolprobe）"
NF=$(strings "$APP/UC" | grep -c "$FP")
OLD=$(strings "$APP/UC" | grep -c "diag1-portdiag")
echo "   $FP 命中=$NF   (旧 main.m 标记 diag1-portdiag 命中=${OLD}，应为 0)"
echo "   sha256 $(shasum -a 256 "$APP/UC" | awk '{print $1}')  size=$(stat -f%z "$APP/UC")"
if [ "$NF" -lt 1 ] || [ "$OLD" -ne 0 ]; then echo "!! 二进制与源码不一致，停止"; exit 1; fi

# @meta 第二重校验用：从二进制里抽出真实的 __DATE__ __TIME__ 戳记
BST=$(strings "$APP/UC" | grep -E "^[A-Z][a-z]{2} [ 0-9][0-9] 20[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}$" | head -1)
printf '%s' "$BST" > "$HERE/.buildstamp"
echo "   构建戳记(从二进制提取) = '$BST'"

echo "== 3/9 签名"
security unlock-keychain -p "" "$KC" >/dev/null 2>&1 || true
SIGN_ERR=$(codesign -s "$IDENT" --keychain "$KC" --entitlements "$ENTS" \
  --generate-entitlement-der -f "$APP" 2>&1)
SRC=$?
echo "$SIGN_ERR" | tail -3 | sed 's/^/   /'
[ $SRC -eq 0 ] || { echo "!! 签名失败"; exit 1; }
codesign -dv "$APP" 2>&1 | grep -E "Identifier=|TeamIdentifier=" | sed 's/^/   /'

echo "== 4/9 安装"
xcrun devicectl device install app --device "$DEV" "$APP" 2>&1 | tail -4 | sed 's/^/   /'
INS=${PIPESTATUS[0]:-0}
[ "$INS" -eq 0 ] || { echo "!! 安装失败 rc=$INS"; }

# 清掉旧结果，避免取回陈旧文件
for f in progress.txt oolprobe.log oolprobe.ndjson; do
  xcrun devicectl device copy from --device "$DEV" --domain-type appDataContainer \
    --domain-identifier "$BID" --source "tmp/$f" --destination "/tmp/oolprobe.old.$f" \
    >/dev/null 2>&1 || true
done
rm -f /tmp/oolprobe.progress.txt /tmp/oolprobe.log /tmp/oolprobe.ndjson

echo "== 5/9 启动（--console；看门狗 170s，硬上限 210s）"
: > /tmp/oolprobe.console
( xcrun devicectl device process launch --device "$DEV" --terminate-existing \
    --console "$BID" > /tmp/oolprobe.console 2>&1; echo "LRC=$?" > /tmp/oolprobe.lrc ) &
LPID=$!

PANIC=0
for i in $(seq 1 70); do        # 70 * 3s = 210s
  sleep 3
  kill -0 $LPID 2>/dev/null || break
  if ! DEVLIVE; then echo "   !!! $(date '+%H:%M:%S') 设备掉线 —— 判定 panic"; PANIC=1; break; fi
done
if [ $PANIC -eq 0 ] && kill -0 $LPID 2>/dev/null; then
  echo "   硬上限到，结束 launch 前台进程"; kill $LPID 2>/dev/null; 
fi
wait $LPID 2>/dev/null
echo "   [launch] $(cat /tmp/oolprobe.lrc 2>/dev/null || echo 'LRC=?')"
tail -25 /tmp/oolprobe.console | sed 's/^/   | /'

if [ $PANIC -eq 1 ] || ! DEVLIVE; then
  echo "== 6/9 设备已掉线，等它回来（最长 10 分钟）"
  PANIC=1
  back=0
  for i in $(seq 1 60); do
    sleep 10
    if DEVLIVE; then back=1; echo "   设备回来了（$(date '+%H:%M:%S')）"; break; fi
    [ $((i % 6)) -eq 0 ] && echo "   ...等待 $((i*10))s"
  done
  [ $back -eq 1 ] || echo "   !! 10 分钟内没回来，仍尝试取回"
  sleep 5
else
  echo "== 6/9 设备在线（未 panic）"
fi

echo "== 7/9 取回（copy 的 stderr 单独打印）"
for f in progress.txt oolprobe.log oolprobe.ndjson; do
  rm -f "/tmp/oolprobe.$f"
  ERR=$(xcrun devicectl device copy from --device "$DEV" --domain-type appDataContainer \
        --domain-identifier "$BID" --source "tmp/$f" --destination "/tmp/oolprobe.$f" 2>&1 >/dev/null)
  CPYRC=$?
  SZ=$(stat -f%z "/tmp/oolprobe.$f" 2>/dev/null || echo MISSING)
  echo "   $f copy rc=$CPYRC size=$SZ"
  [ -n "$ERR" ] && { echo "   copy-stderr($f):"; echo "$ERR" | sed 's/^/     /'; }
done

echo "== 8/9 @meta 双校验"
if [ -s /tmp/oolprobe.ndjson ]; then
  MF_FP=$(grep -m1 '"k":"@meta"' /tmp/oolprobe.ndjson | sed -E 's/.*"fp":"([^"]*)".*/\1/')
  MF_PR=$(grep -m1 '"k":"@meta"' /tmp/oolprobe.ndjson | sed -E 's/.*"probe":"([^"]*)".*/\1/')
  MF_BD=$(grep -m1 '"k":"@meta"' /tmp/oolprobe.ndjson | sed -E 's/.*"build":"([^"]*)".*/\1/')
  echo "   @meta probe='$MF_PR' fp='$MF_FP' build='$MF_BD' ; 本地 build='$BST'"
  if [ "$MF_FP" != "$FP" ] || [ "$MF_BD" != "$BST" ]; then
    echo "   !! @meta 不匹配 —— 这是旧文件，不归档"
  else
    echo "   @meta 校验通过"
  fi
else
  echo "   !! 没取到 ndjson"
fi

echo "== 9/9 panic 归档"
P1=$(PCOUNT)
echo "   panic .ips：基线=$P0 现在=$P1"
if [ "$P1" -gt "$P0" ]; then
  PANIC=1
  echo "   !!!!! 新增 $((P1-P0)) 个 panic !!!!!"
  LASTTAG=$(tail -1 /tmp/oolprobe.progress.txt 2>/dev/null | cut -f2 | tr -c 'a-zA-Z0-9._=-' '_')
  [ -z "$LASTTAG" ] && LASTTAG="unknown"
  echo "   progress.txt 最后一行 tag = $LASTTAG"
  NEW=$(ls -1t "$PAN"/*.ips | head -n $((P1-P0)))
  idx=0
  for f in $NEW; do
    idx=$((idx+1))
    echo "     NEW: $f"
    cp "$f" "$HERE/panic-${LASTTAG}.ips" && echo "       全文 -> $HERE/panic-${LASTTAG}.ips ($(stat -f%z "$HERE/panic-${LASTTAG}.ips") bytes)"
  done
else
  # 本地没有新文件：可能是还没同步，尝试从设备 systemCrashLogs 拉
  echo "   本地无新增；尝试从设备 systemCrashLogs 拉取"
  rm -rf /tmp/oolprobe.crash
  mkdir -p /tmp/oolprobe.crash
  ERR=$(xcrun devicectl device copy from --device "$DEV" --domain-type systemCrashLogs \
        --source . --destination /tmp/oolprobe.crash 2>&1 >/dev/null)
  RC=$?
  echo "   systemCrashLogs copy rc=$RC  files=$(ls -1 /tmp/oolprobe.crash 2>/dev/null | wc -l | tr -d ' ')"
  [ -n "$ERR" ] && echo "   copy-stderr:" && echo "$ERR" | sed 's/^/     /'
  ls -1t /tmp/oolprobe.crash/*.ips 2>/dev/null | head -1 | while read -r nf; do
    [ -n "$nf" ] || continue
    echo "   最新: $nf"
    grep -m1 -o '"panicString":"[^"]\{0,200\}' "$nf" | head -2 | sed 's/^/     /'
  done
fi

echo
echo "===== progress.txt（最后 40 行；全文见 /tmp/oolprobe.progress.txt）====="
tail -40 /tmp/oolprobe.progress.txt 2>/dev/null
echo
echo "===== oolprobe.log 尾部 ====="
tail -60 /tmp/oolprobe.log 2>/dev/null
echo
echo "[五态] build=ok  sign=$([ $SRC -eq 0 ] && echo ok || echo FAIL)  install=$([ "${INS:-1}" -eq 0 ] && echo ok || echo FAIL)  launch=$(cat /tmp/oolprobe.lrc 2>/dev/null)  panic=$PANIC"
echo "[完成] $(date '+%H:%M:%S')  panic 计数 $P0 -> $P1"
