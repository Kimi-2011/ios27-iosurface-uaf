"""Surgical ZIP member fetch: pull one file out of a remote IPSW via range requests.

Downloading 12.7 GB to get a 23 MB kernelcache is waste. An IPSW is a ZIP, and
Apple's CDN honours Range, so we can:
  1. fetch the last 64 KiB -> End Of Central Directory
  2. fetch the central directory -> offsets/sizes
  3. fetch just the member's local header + data
  4. inflate if the method is deflate

Usage:
  python3 zipfetch.py URL MEMBER OUT [--size 12725905286]
"""
import argparse
import struct
import sys
import urllib.request
import zlib

UA = {"User-Agent": "Mozilla/5.0"}


def get(url, start, end):
    req = urllib.request.Request(url, headers={**UA, "Range": f"bytes={start}-{end}"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def remote_size(url):
    req = urllib.request.Request(url, headers=UA, method="HEAD")
    with urllib.request.urlopen(req, timeout=60) as r:
        return int(r.headers["Content-Length"])


def find_eocd(tail):
    i = tail.rfind(b"PK\x05\x06")
    if i < 0:
        raise SystemExit("EOCD not found (not a zip, or tail too small)")
    return i


def parse_central(cd):
    out = []
    i = 0
    while i + 46 <= len(cd) and cd[i:i + 4] == b"PK\x01\x02":
        (method,) = struct.unpack_from("<H", cd, i + 10)
        comp, uncomp = struct.unpack_from("<II", cd, i + 20)
        nlen, elen, clen = struct.unpack_from("<HHH", cd, i + 28)
        (lho,) = struct.unpack_from("<I", cd, i + 42)
        name = cd[i + 46: i + 46 + nlen].decode("utf-8", "replace")
        extra_start = i + 46 + nlen
        zoff = None
        if comp == 0xFFFFFFFF or uncomp == 0xFFFFFFFF or lho == 0xFFFFFFFF:
            j = extra_start
            while j + 4 <= extra_start + elen:
                tag, dlen = struct.unpack_from("<HH", cd, j)
                if tag == 0x0001:
                    q = j + 4
                    if uncomp == 0xFFFFFFFF:
                        uncomp = struct.unpack_from("<Q", cd, q)[0]; q += 8
                    if comp == 0xFFFFFFFF:
                        comp = struct.unpack_from("<Q", cd, q)[0]; q += 8
                    if lho == 0xFFFFFFFF:
                        zoff = struct.unpack_from("<Q", cd, q)[0]
                    break
                j += 4 + dlen
        out.append({"name": name, "method": method, "comp": comp,
                    "uncomp": uncomp, "lho": zoff if zoff is not None else lho})
        i += 46 + nlen + elen + clen
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("member")
    ap.add_argument("out")
    ap.add_argument("--size", type=int)
    a = ap.parse_args()

    size = a.size or remote_size(a.url)
    print(f"remote size: {size:,}")

    tail = get(a.url, max(0, size - 65536), size - 1)
    e = find_eocd(tail)
    cd_size, cd_off = struct.unpack_from("<II", tail, e + 12)

    if cd_off == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
        # ZIP64: locator sits 20 bytes before the EOCD record
        loc = tail.rfind(b"PK\x06\x07", 0, e)
        if loc < 0:
            raise SystemExit("ZIP64 locator not found")
        (z64_off,) = struct.unpack_from("<Q", tail, loc + 8)
        rec = get(a.url, z64_off, z64_off + 55)
        if rec[:4] != b"PK\x06\x06":
            raise SystemExit("bad ZIP64 EOCD")
        cd_size, cd_off = struct.unpack_from("<QQ", rec, 40)
        print(f"ZIP64: central dir {cd_size:,} bytes @ {cd_off:,}")
    else:
        print(f"central dir: {cd_size:,} bytes @ {cd_off:,}")

    entries = parse_central(get(a.url, cd_off, cd_off + cd_size - 1))

    if a.member == "--list":
        for x in entries:
            print(f"{x['uncomp']:>12,}  {x['name']}")
        return
    hit = next((x for x in entries if x["name"] == a.member), None)
    if not hit:
        near = [x["name"] for x in entries if a.member.split("/")[-1] in x["name"]][:5]
        raise SystemExit(f"member not found. near: {near}")

    lh = get(a.url, hit["lho"], hit["lho"] + 29)
    (nlen, elen) = struct.unpack_from("<HH", lh, 26)
    data_start = hit["lho"] + 30 + nlen + elen
    blob = get(a.url, data_start, data_start + hit["comp"] - 1)
    print(f"fetched {len(blob):,} compressed bytes (method={hit['method']})")

    if hit["method"] == 8:
        blob = zlib.decompress(blob, -15)
    elif hit["method"] != 0:
        raise SystemExit(f"unsupported method {hit['method']}")

    with open(a.out, "wb") as fh:
        fh.write(blob)
    print(f"wrote {len(blob):,} bytes -> {a.out}")


if __name__ == "__main__":
    main()
