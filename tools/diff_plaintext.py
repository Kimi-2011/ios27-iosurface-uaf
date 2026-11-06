"""Diff two extracted iOS trees, plaintext only.

Ranks changed files by "patch delta": new strings + size change. Ciphertext
(cryptid != 0) is skipped and counted, because block-level ciphertext diff
carries no semantics.

Usage: python3 diff_plaintext.py A B [--top N] [--json OUT]
"""
import argparse
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from machoparse import parse_file  # noqa: E402

STR_RE = re.compile(rb"[ -~]{6,}")


def walk(root):
    out = {}
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            out[rel] = full
    return out


def digest(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def strings(path):
    with open(path, "rb") as fh:
        return {s.decode("ascii", "replace") for s in STR_RE.findall(fh.read(32 * 1024 * 1024))}


def is_encrypted(path):
    try:
        info = parse_file(path)
        return bool(info.get("encrypted")) if isinstance(info, dict) else False
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--json")
    a = ap.parse_args()

    A, B = walk(a.a), walk(a.b)
    added = sorted(set(B) - set(A))
    removed = sorted(set(A) - set(B))
    common = sorted(set(A) & set(B))

    skipped = 0
    changed = []
    for rel in common:
        if os.path.getsize(A[rel]) == os.path.getsize(B[rel]) and digest(A[rel]) == digest(B[rel]):
            continue
        if is_encrypted(A[rel]) or is_encrypted(B[rel]):
            skipped += 1
            continue
        sa, sb = strings(A[rel]), strings(B[rel])
        new = sb - sa
        gone = sa - sb
        same = len(sa & sb)
        sim = same / max(1, len(sa | sb))
        delta = len(new) + abs(os.path.getsize(B[rel]) - os.path.getsize(A[rel])) // 1024
        changed.append({
            "path": rel, "delta": delta, "similarity": round(sim, 3),
            "size_a": os.path.getsize(A[rel]), "size_b": os.path.getsize(B[rel]),
            "new_strings": sorted(new)[:8], "removed_strings": sorted(gone)[:4],
        })
    changed.sort(key=lambda r: -r["delta"])

    print(f"added={len(added)} removed={len(removed)} changed={len(changed)} skipped(ciphertext)={skipped}\n")
    print(f"{'delta':>6} {'sim':>5} {'size a>b':>18}  path")
    for r in changed[: a.top]:
        print(f"{r['delta']:6} {r['similarity']:5.2f} {r['size_a']:>8}->{r['size_b']:<8}  {r['path']}")
        for s in r["new_strings"][:3]:
            print(f"         + {s[:70]}")
    if added:
        print("\nnew files (highest prior):")
        for p in added[:10]:
            print("  + " + p)
    if removed:
        print("\nremoved files:")
        for p in removed[:10]:
            print("  - " + p)

    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"added": added, "removed": removed, "changed": changed}, fh, indent=1, ensure_ascii=False)
        print(f"\njson -> {a.json}")


if __name__ == "__main__":
    main()
