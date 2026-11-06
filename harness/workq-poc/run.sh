#!/bin/bash
# run.sh <mode> [KEY=VAL ...]   — launch the app with WQPOC_MODE and extra env vars,
# wait, fetch the device log, print (and append to results/<mode>.log) the last run block.
set -uo pipefail
cd "$(dirname "$0")"

DEV="DEVICE-UDID"
BUNDLE="com.example.ios27poc"
MODE="$1"; shift || true

JSON="{\"WQPOC_MODE\":\"$MODE\""
for kv in "$@"; do
	k="${kv%%=*}"; v="${kv#*=}"
	JSON="$JSON,\"$k\":\"$v\""
done
JSON="$JSON}"

mkdir -p results
LOG="results/${MODE}${RESULT_SUFFIX:-}.log"

xcrun devicectl device process launch --device "$DEV" -e "$JSON" "$BUNDLE" >/dev/null 2>&1
rc=$?
sleep "${WAIT_S:-2}"
rm -f /tmp/wq_pull.log
xcrun devicectl device copy from --device "$DEV" --domain-type appDataContainer \
	--domain-identifier "$BUNDLE" --source tmp/workq.log --destination /tmp/wq_pull.log >/dev/null 2>&1

# last run block: everything after the last "=== start"
python3 - "$LOG" <<'PY'
import sys, os
p='/tmp/wq_pull.log'
try:
    lines=open(p, errors='replace').read().splitlines()
except FileNotFoundError:
    print("NO_LOG"); sys.exit(0)
starts=[i for i,l in enumerate(lines) if l.startswith('=== start')]
ctors=[i for i,l in enumerate(lines) if l.startswith('=== ctorstart')]
if not starts:
    print("NO_START_MARKER"); sys.exit(0)
last=starts[-1]
if ctors and ctors[-1] < last and (last - ctors[-1]) < 40:
    last=ctors[-1]
blk=lines[last:]
txt='\n'.join(blk)
print(txt)
with open(sys.argv[1],'a') as f:
    f.write(txt+'\n---\n')
PY
