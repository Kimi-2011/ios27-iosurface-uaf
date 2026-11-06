"""L0 attack-surface map for an extracted iOS tree.

Walks LaunchDaemons / LaunchAgents / *.xpc, resolves the backing binary,
reads Mach-O entitlements, and scores each service as a candidate target.

Usage:
  python3 surface_map.py ROOT [--baseline OTHER_ROOT] [--json OUT] [--top N]
"""
import argparse
import json
import os
import plistlib
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from machoparse import parse_file  # noqa: E402

LAUNCH_DIRS = [
    "System/Library/LaunchDaemons",
    "System/Library/LaunchAgents",
    "Library/LaunchDaemons",
]


def _load_plist(path):
    try:
        with open(path, "rb") as fh:
            return plistlib.load(fh)
    except Exception:
        return None


def _resolve_binary(root, prog_args):
    if not prog_args:
        return None
    cand = prog_args[0]
    if not cand.startswith("/"):
        return None
    p = os.path.join(root, cand.lstrip("/"))
    return p if os.path.isfile(p) else None


def collect(root):
    services = {}
    for d in LAUNCH_DIRS:
        base = os.path.join(root, d)
        if not os.path.isdir(base):
            continue
        for name in sorted(os.listdir(base)):
            if not name.endswith(".plist"):
                continue
            pl = _load_plist(os.path.join(base, name))
            if not isinstance(pl, dict):
                continue
            label = pl.get("Label") or name[:-6]
            mach = pl.get("MachServices") or {}
            binpath = _resolve_binary(root, pl.get("ProgramArguments"))
            info = {}
            if binpath:
                info = parse_file(binpath)
            ents = (info.get("entitlements") or []) if isinstance(info, dict) else []
            ents = ents[0] if ents and isinstance(ents[0], str) else ""
            services[label] = {
                "label": label,
                "plist": os.path.join(d, name),
                "services": sorted(mach.keys()) if isinstance(mach, dict) else [],
                "user": pl.get("UserName", "mobile"),
                "binary": binpath,
                "binary_present": bool(binpath),
                "encrypted": bool(info.get("encrypted")) if info else None,
                "private_ents": [e for e in ents.split("\n") if "private" in e],
                "has_private_ent": "private" in ents,
            }

    xpc_base = os.path.join(root, "System/Library/xpc")
    if os.path.isdir(xpc_base):
        for name in sorted(os.listdir(xpc_base)):
            info_pl = os.path.join(xpc_base, name, "Info.plist")
            if not os.path.isfile(info_pl):
                continue
            pl = _load_plist(info_pl) or {}
            bundle = pl.get("CFBundleIdentifier", name)
            exe = os.path.join(xpc_base, name, name[:-4] if name.endswith(".xpc") else name)
            minfo = parse_file(exe) if os.path.isfile(exe) else {}
            services[bundle] = {
                "label": bundle,
                "plist": os.path.relpath(info_pl, root),
                "services": [bundle],
                "user": "per-connection",
                "binary": exe if os.path.isfile(exe) else None,
                "binary_present": os.path.isfile(exe),
                "encrypted": bool(minfo.get("encrypted")) if minfo else None,
                "private_ents": [],
                "has_private_ent": bool(minfo.get("entitlements")),
            }
    return services


def score(svc, is_new):
    s = 0
    s += 3 * len(svc["services"])          # each Mach service is an entry point
    s += 2 if svc.get("has_private_ent") else 0
    s += 2 if is_new else 0                 # new code in this version
    s += 1 if svc["user"] == "root" else 0
    s -= 4 if not svc["binary_present"] else 0
    s -= 2 if svc.get("encrypted") else 0
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--baseline")
    ap.add_argument("--json")
    ap.add_argument("--top", type=int, default=20)
    a = ap.parse_args()

    cur = collect(a.root)
    base = collect(a.baseline) if a.baseline else {}

    rows = []
    for label, svc in cur.items():
        is_new = bool(base) and label not in base
        rows.append((score(svc, is_new), "A-ONLY" if is_new else "", svc))
    rows.sort(key=lambda r: -r[0])

    print(f"{'score':>5}  {'flag':4} {'label':34} {'svcs':>4} {'user':10} {'enc':4} priv")
    for s, flag, svc in rows[: a.top]:
        print(f"{s:5}  {flag:4} {svc['label'][:34]:34} {len(svc['services']):4} "
              f"{svc['user'][:10]:10} {str(svc.get('encrypted'))[:4]:4} "
              f"{'y' if svc.get('has_private_ent') else '-'}")

    removed = [l for l in base if l not in cur]
    if base:
        print(f"\nonly_in_A={sum(1 for r in rows if r[1] == 'A-ONLY')}  only_in_baseline={len(removed)}  total={len(rows)}")
        if removed:
            print("only in baseline: " + ", ".join(sorted(removed)[:10]))

    if a.json:
        with open(a.json, "w") as fh:
            json.dump([{"score": s, "flag": f, **v} for s, f, v in rows], fh, indent=1, ensure_ascii=False)
        print(f"json -> {a.json}")


if __name__ == "__main__":
    main()
