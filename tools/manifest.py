"""Parse BuildManifest.plist: the authoritative component list of an IPSW.

Tells you, before you extract anything:
  - which components exist (iBoot, LLB, SEP, kernelcache, DeviceTree, ...)
  - their build identity / path
  - which are personalizable (i.e. signed per-device)

Usage: python3 manifest.py BuildManifest.plist [--component kernel] [--json OUT]
"""
import argparse
import json
import plistlib

INTEREST = ("kernel", "iboot", "llb", "ibss", "ibec", "sep", "devicetree", "restore", "trustcache", "os")


def load(path):
    with open(path, "rb") as fh:
        return plistlib.load(fh)


def summarize(manifest):
    rows = []
    for identity in manifest.get("BuildIdentities", []):
        info = identity.get("Info", {})
        device = identity.get("Ap,ProductType", identity.get("ProductType", "?"))
        for name, comp in (identity.get("Manifest") or {}).items():
            if not isinstance(comp, dict):
                continue
            di = comp.get("Digest") or {}
            rows.append({
                "identity": info.get("Variant", "?"),
                "device": device,
                "component": name,
                "path": comp.get("Info", {}).get("Path", ""),
                "personalize": bool(comp.get("Personalize", False)),
                "digest_len": len(di) if isinstance(di, dict) else 0,
            })
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest")
    ap.add_argument("--component", help="substring filter")
    ap.add_argument("--json")
    a = ap.parse_args()

    m = load(a.manifest)
    print(f"product={m.get('ProductVersion')} build={m.get('ProductBuildVersion')} "
          f"platform={m.get('ProductType', '?')}")
    rows = summarize(m)
    ids = sorted({r["identity"] for r in rows})
    print(f"identities={len(ids)} components={len(rows)}")
    print("variants: " + ", ".join(ids[:6]) + (" ..." if len(ids) > 6 else ""))

    if a.component:
        rows = [r for r in rows if a.component.lower() in r["component"].lower()]

    seen = set()
    print(f"\n{'component':22} {'path':44} {'pers':5}")
    for r in rows:
        key = (r["component"], r["path"])
        if key in seen:
            continue
        seen.add(key)
        print(f"{r['component'][:22]:22} {r['path'][:44]:44} {str(r['personalize'])[:5]:5}")

    if a.json:
        with open(a.json, "w") as fh:
            json.dump(rows, fh, indent=1)
        print(f"\njson -> {a.json}")


if __name__ == "__main__":
    main()
