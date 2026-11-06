"""Pair functions between two versions by instruction-sequence similarity.

Positional pairing inside a replaced block drifts as soon as one function is
inserted. This matches by normalized instruction sequence instead and only
accepts pairs above a ratio threshold, so a real patch (95% similar) survives
while unrelated neighbours (<50%) are dropped.

Usage (library):
    from pairing import pair
    for fa, fb, ratio in pair(funcs_a, funcs_b):
        ...
"""
import difflib

NUM_CHARS = set("0123456789abcdefx#-,")


def normalize(text):
    """Collapse immediates so layout shifts do not affect similarity."""
    out = []
    i = 0
    while i < len(text):
        if text[i] == "#" or text.startswith("0x", i):
            j = i + 1
            while j < len(text) and (text[j] in NUM_CHARS or text[j] == "x"):
                j += 1
            out.append("#")
            i = j
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def ops_of(insns):
    return [normalize(f"{i.mnemonic} {i.op_str}") for i in insns]


def ratio(a_ops, b_ops):
    if not a_ops or not b_ops:
        return 0.0
    sm = difflib.SequenceMatcher(a=a_ops, b=b_ops, autojunk=False)
    return sm.ratio()


def pair(funcs_a, funcs_b, threshold=0.55):
    """Greedy best-match pairing, prefiltered by size to stay fast.

    Only functions whose body hash is absent on the other side should be passed
    in, otherwise this is O(n*m) over thousands of untouched functions.
    """
    pairs = []
    used_b = set()
    for fa in funcs_a:
        cands = [j for j, fb in enumerate(funcs_b)
                 if j not in used_b and abs(fb["size"] - fa["size"]) <= max(64, fa["size"] * 0.5)]
        if not cands:
            continue
        scored = sorted(((ratio(fa["ops"], funcs_b[j]["ops"]), j) for j in cands), reverse=True)
        r, j = scored[0]
        if r >= threshold:
            pairs.append((fa, funcs_b[j], r))
            used_b.add(j)
    return pairs
