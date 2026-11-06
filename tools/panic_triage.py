"""Cluster panic logs: the only kernel observability you get before L4.

Handles iOS .ips (JSON header line + JSON body) and legacy .panic text.

Usage: python3 panic_triage.py DIR [--json OUT]
"""
import argparse
import json
import os
import re

HEX = re.compile(r"0x[0-9a-fA-F]+")
NUM = re.compile(r"\d+")


def load(path):
    with open(path, "rb") as fh:
        raw = fh.read().decode("utf-8", "replace")
    if raw.lstrip().startswith("{"):
        first, _, rest = raw.partition("\n")
        try:
            header = json.loads(first)
        except Exception:
            header = {}
        try:
            body = json.loads(rest) if rest.strip() else {}
        except Exception:
            body = {}
        exc = body.get("exception") or {}
        term = body.get("termination") or {}
        proc = body.get("procName") or header.get("app_name") or ""
        # kernel panic  vs  userspace crash
        if body.get("panicString") or body.get("panic_string"):
            kind = "panic"
            sig = body.get("panicString") or body.get("panic_string")
        else:
            kind = "crash"
            frames = []
            threads = body.get("threads") or []
            idx = body.get("faultingThread")
            if isinstance(idx, int) and idx < len(threads):
                frames = (threads[idx].get("frames") or [])[:2]
            top = " <- ".join(f"{f.get('imageIndex','?')}+{f.get('imageOffset','?')}" for f in frames)
            sig = (f"{exc.get('type','?')} {exc.get('signal','')} "
                   f"{term.get('indicator','')} {top}").strip()
        return {
            "bug_type": header.get("bug_type") or body.get("bug_type"),
            "build": body.get("build") or header.get("build"),
            "product": body.get("product") or header.get("product"),
            "kind": kind,
            "panic": sig,
            "proc": proc,
        }
    return {"panic": raw[:4000], "bug_type": "panic-text", "build": None, "product": None, "proc": ""}


def signature(panic):
    line = panic.strip().splitlines()[0] if panic.strip() else "(empty)"
    line = HEX.sub("<ADDR>", line)
    line = NUM.sub("<N>", line)
    return line[:110]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--json")
    a = ap.parse_args()

    clusters = {}
    for dirpath, _dirs, files in os.walk(a.dir):
        for fn in files:
            if not (fn.endswith(".ips") or fn.endswith(".panic") or "panic" in fn.lower()):
                continue
            rec = load(os.path.join(dirpath, fn))
            sig = signature(rec["panic"])
            c = clusters.setdefault(sig, {"count": 0, "files": [], "builds": set(), "procs": set()})
            c["count"] += 1
            c["files"].append(fn)
            if rec["build"]:
                c["builds"].add(str(rec["build"]))
            c.setdefault("kinds", set()).add(rec["kind"])
            if rec["proc"]:
                c["procs"].add(rec["proc"])

    print(f"{len(clusters)} clusters / {sum(c['count'] for c in clusters.values())} reports\n")
    for sig, c in sorted(clusters.items(), key=lambda kv: -kv[1]["count"]):
        print(f"[{c['count']:3}] {sig}")
        if c["procs"]:
            print(f"      procs={','.join(sorted(c['procs'])[:4])}")
        if c["builds"]:
            print(f"      build={','.join(sorted(c['builds']))}  proc={','.join(sorted(c['procs'])[:4])}")

    if a.json:
        out = [{"signature": k, "count": v["count"], "files": v["files"],
                "builds": sorted(v["builds"]), "procs": sorted(v["procs"])} for k, v in clusters.items()]
        with open(a.json, "w") as fh:
            json.dump(out, fh, indent=1, ensure_ascii=False)
        print(f"\njson -> {a.json}")


if __name__ == "__main__":
    main()
