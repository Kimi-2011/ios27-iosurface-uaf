"""Classify an extracted iOS tree into 'can diff' vs 'cannot diff' buckets.

The point of L0: never waste time diffing ciphertext. iBoot/LLB/iBSS/iBEC/SEP and
production kernelcache are GID-encrypted on A19; only the system volume,
cryptexes, dyld shared cache and userspace binaries are plaintext.

Usage: python3 ipsw_inventory.py ROOT [--json OUT]
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from machoparse import parse_file  # noqa: E402

ENCRYPTED_HINTS = ("iboot", "llb", "ibss", "ibec", "sep-firmware", "kernelcache", "devicetree", "restore")
PLAINTEXT_HINTS = ("/System/Library/", "/usr/", "/bin/", "/sbin/", "dyld_shared_cache", "/System/Cryptexes/")


def bucket(rel):
    low = rel.lower()
    base = os.path.basename(low)
    if any(h in base for h in ENCRYPTED_HINTS):
        return "boot-or-kernel"
    if "dyld_shared_cache" in low:
        return "dyld-cache"
    if low.startswith("system/library/launchdaemons") or low.startswith("system/library/launchagents"):
        return "daemons"
    if "/xpc/" in low:
        return "xpc"
    if low.startswith("system/library/frameworks") or low.startswith("system/library/privateframeworks"):
        return "frameworks"
    if any(low.startswith(p.lstrip("/").lower()) for p in PLAINTEXT_HINTS):
        return "userspace"
    return "other"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--json")
    a = ap.parse_args()

    rows, counts = [], {}
    for dirpath, _dirs, files in os.walk(a.root):
        for fn in files:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, a.root)
            b = bucket(rel)
            size = os.path.getsize(full)
            enc = None
            if size > 0 and b in ("userspace", "xpc", "frameworks", "daemons", "dyld-cache"):
                try:
                    info = parse_file(full)
                    enc = info.get("encrypted") if isinstance(info, dict) else None
                except Exception:
                    enc = None
            counts[b] = counts.get(b, 0) + 1
            rows.append({"path": rel, "bucket": b, "size": size, "encrypted": enc})

    print(f"{'bucket':16} {'files':>6}  {'bytes':>12}  diffable")
    for b in sorted(counts):
        subset = [r for r in rows if r["bucket"] == b]
        total = sum(r["size"] for r in subset)
        diffable = "no" if b == "boot-or-kernel" else ("ciphertext-only" if any(r["encrypted"] for r in subset) else "yes")
        print(f"{b:16} {counts[b]:6}  {total:12,}  {diffable}")

    hard = [r["path"] for r in rows if r["bucket"] == "boot-or-kernel"]
    if hard:
        print(f"\nundiffable (GID-encrypted on A19): {len(hard)} components")
        for p in hard[:5]:
            print("  - " + p)

    if a.json:
        with open(a.json, "w") as fh:
            json.dump(rows, fh, indent=1)
        print(f"json -> {a.json}")


if __name__ == "__main__":
    main()
