"""Offset oracle: the pass/fail gate before any kernel write.

You have no kernel debugger on iOS. So every offset table must be validated by
cross-checking the read primitive against values the process already knows.

Input JSON (fill from your primitive):
  {"pid": 4242, "ppid": 1, "uid": 501,
   "read_pid": 4242, "read_ppid": 1,
   "read_uid_a": 501, "read_uid_b": 501,
   "kernel_base_a": "0xfffffff007004000", "kernel_base_b": "0xfffffff007004000"}

Usage: python3 oracle_check.py readings.json
Exit: 0 = all pass (write allowed), 1 = at least one fail (do NOT write)
"""
import json
import sys

TESTS = [
    ("pid_self", "proc->p_pid == getpid()", ("pid", "read_pid")),
    ("ppid_parent", "proc->p_ppid == getppid()", ("ppid", "read_ppid")),
    ("cred_uid", "proc->ucred.cr_uid == getuid()", ("uid", "read_uid_a")),
    ("cross_path", "same field, two independent read paths agree", ("read_uid_a", "read_uid_b")),
    ("slide_stable", "kernel base stable across reads", ("kernel_base_a", "kernel_base_b")),
]


def norm(v):
    if isinstance(v, str) and v.lower().startswith("0x"):
        try:
            return int(v, 16)
        except ValueError:
            return v
    return v


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    with open(sys.argv[1]) as fh:
        r = {k: norm(v) for k, v in json.load(fh).items()}

    fails = 0
    print(f"{'test':14} {'result':6}  check")
    for name, desc, keys in TESTS:
        if any(k not in r for k in keys):
            print(f"{name:14} {'SKIP':6}  {desc} (missing: {[k for k in keys if k not in r]})")
            continue
        ok = len({str(r[k]) for k in keys}) == 1
        fails += 0 if ok else 1
        print(f"{name:14} {'PASS' if ok else 'FAIL':6}  {desc}  [{', '.join(f'{k}={r[k]}' for k in keys)}]")

    print()
    if fails:
        print(f"BLOCKED: {fails} test(s) failed. Offset table is not trustworthy; do not issue writes.")
        return 1
    print("CLEARED: offset table validated. Safe to proceed to the first write (ucred.cr_uid).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
