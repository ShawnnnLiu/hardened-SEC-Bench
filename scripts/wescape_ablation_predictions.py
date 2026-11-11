#!/usr/bin/env python3
"""Predictions for the ablation of the developer patch of
libredwg.cve-2020-21814 (e8c3edb9, htmlwescape) and of its candidate minimal
patch, for the cases of scripts/escape_cases.py.

This file was written on 2026-10-28 at 03:05 EDT (07:05 UTC), before any
ablation variant and before any variant of this instance was built or run
(the stage build_before was running). Known results: the ablation of the
developer patch of libredwg.cve-2020-21816 (7e4c59b6, htmlescape;
logs/libredwg.cve-2020-21816/ablation.log), whose analogous lines gave a
LeakSanitizer report on every allocating call when malloc and calloc both
stay (its L3, M1), a SEGV on every allocating call when neither stays (L4,
M2) and a timeout on every non-empty input without the pointer increment
(L58, M10); those observations are the basis of the predictions for L1, L2,
M1, M2 below, which the source alone does not determine for L2 and M2.

Usage: python3 wescape_ablation_predictions.py > wescape_ablation_predictions.tsv

Changed lines of patches/libredwg.cve-2020-21814.diff, numbered as in
scripts/ablate_patch.py:
  1 -  d = dest = malloc (len);     2 +  d = dest = calloc (len, 1);
  3 -  while (*wstr++)              4 +  while (*wstr)
  5 +  *d = 0;   (after realloc)    6 +  *d = 0;   (after sprintf)
  7 -  *d++ = *wstr;                8 +  {   9 +  *d++ = *wstr;   10 +  *d = 0;   11 +  }
  12 +  wstr++;   (end of the loop body)
Variants: L<i> drops line i; the groups drop calloc 1,2; loop 3,4,12;
plainbrace 7-11; min10 5,6 (the candidate minimal patch, 10 changed lines);
min10_nocalloc 1,2,5,6; min10_noloop 3,4,5,6,12; min10_noplain 5,6,7-11.
M<i> drops line i of min10 (its lines, in order: 1 -malloc, 2 +calloc,
3 -while (*wstr++), 4 +while (*wstr), 5 -*d++ = *wstr;, 6 +{, 7 +*d++ = *wstr;,
8 +*d = 0;, 9 +}, 10 +wstr++;). min is the minimal patch run as a variant
with the full case set and the corpus.
Predicted builds: L8, L11, M6 and M9 (a brace without its partner) fail to
compile and have no column; every other variant builds.

Model (the invariants I1, I2, I3 of scripts/wescape_predictions.py): a
byte-level simulation of htmlwescape (run() below). The output block has
len = units + 16 bytes; it holds zeros (calloc) or the AddressSanitizer
fill byte 0xBE (malloc; fresh blocks are filled up to 4096 bytes, and no
block of this case set is larger). A growth (off >= len - 8, len += 16)
copies the old block and adds 16 fill bytes, as realloc does under the
sanitizer. strcat (d, x) appends x and a NUL at the first NUL at or after
d; if there is none before the end of the block, or a write falls past it,
the class is ASAN. sprintf writes its text and a NUL. The loop forms: fixed
(`while (*wstr)` with `wstr++` at the end), skip (`while (*wstr++)`: the
body sees units 2..n and the terminator), outer (L3, M3: `while (*wstr++)`
around the fixed loop: units 2..n), once (L4, M4: no loop, the body runs
once on the first unit or the terminator), stuck (L12, M10: no increment;
a non-empty input never ends: timeout, class WRONG). Plain-store forms:
nul (store and NUL), plain (store only: L10, plainbrace, min10_noplain,
M8), twice (L7, M5: the original store stays and the braces follow it, so
every unit that reaches `default:` is stored once more as its low byte,
followed by a NUL, which also makes a unit of 0x1000 or more write 10
bytes where the capacity rule reserves 9), none (L9, M7: only `*d = 0;`).
The class is OK when the output equals spec() of the whole input, WRONG
otherwise. Checked before writing: with malloc, the skip loop, the plain
store and no NUL stores the model gives the class of
scripts/wescape_predictions.py (base machine) on all 325 non-NULL w_ cases,
and with every line kept it gives OK on all of them.
L1 and M1 (malloc and calloc both stay) leak the malloc block: ASAN
(LeakSanitizer) on every non-NULL call. L2 and M2 (neither stays) leave d
and dest unassigned: ASAN on every non-NULL call. The NULL argument
returns before the allocation: OK in every variant.
No variant changes htmlescape: the a_* cases, the blk12 and txt files
(R2000) and the reproducers r1 to r4 and r7 keep their base class (r5:
no prediction). The reproducers r6 and r8 (class by sanitizer report only;
their strings are not known) are predicted where no input can fault (OK)
or every non-empty input faults or hangs; otherwise -. The case poc
(reproducer r8 with the reference check) is predicted OK only for the
variants whose output equals the developer patch for every input (L5, L6,
min10, min), ASAN for L1, L2, M1, M2, WRONG for L12 and M10, and - for the
others, because whether its strings can be read from the file is not
known.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import escape_cases as ec  # noqa: E402
import wescape_predictions as wp  # noqa: E402

FILL = 0xBE
FULL = dict(alloc="calloc", loop="fixed", nul_realloc=True, nul_sprintf=True, plain="nul")
NO56 = dict(nul_realloc=False, nul_sprintf=False)
VARIANTS = {
    "L1": dict(alloc="both"), "L2": dict(alloc="none"), "L3": dict(loop="outer"),
    "L4": dict(loop="once"), "L5": dict(nul_realloc=False), "L6": dict(nul_sprintf=False),
    "L7": dict(plain="twice"), "L9": dict(plain="none"), "L10": dict(plain="plain"),
    "L12": dict(loop="stuck"),
    "calloc": dict(alloc="malloc"), "loop": dict(loop="skip"), "plainbrace": dict(plain="plain"),
    "min10": dict(NO56), "min10_nocalloc": dict(NO56, alloc="malloc"),
    "min10_noloop": dict(NO56, loop="skip"), "min10_noplain": dict(NO56, plain="plain"),
    "M1": dict(NO56, alloc="both"), "M2": dict(NO56, alloc="none"), "M3": dict(NO56, loop="outer"),
    "M4": dict(NO56, loop="once"), "M5": dict(NO56, plain="twice"), "M7": dict(NO56, plain="none"),
    "M8": dict(NO56, plain="plain"), "M10": dict(NO56, loop="stuck"),
    "min": dict(NO56),
}
# output equal to the developer patch for every input (redundant NUL stores)
EQUIV = {"L5", "L6", "min10", "min"}
# no input can give a sanitizer report: calloc, a NUL after every store or no
# plain store, and no write beyond the reserved 9 bytes
SAFE = EQUIV | {"L3", "L4", "L9", "loop", "min10_noloop", "M3", "M4", "M7"}


class Fault(Exception):
    pass


def run(us, alloc="calloc", loop="fixed", nul_realloc=True, nul_sprintf=True, plain="nul"):
    """Class of one htmlwescape call on the units us: OK, WRONG, ASAN or HANG."""
    if alloc == "none":
        return "ASAN"
    st = {"d": 0, "len": len(us) + 16}
    st["mem"] = [0 if alloc in ("calloc", "both") else FILL] * st["len"]

    def write(i, b):
        if i >= st["len"]:
            raise Fault
        st["mem"][i] = b

    def body(c):
        d = st["d"]
        if d >= st["len"] - 8:
            st["len"] += 16
            st["mem"] = st["mem"] + [FILL] * 16
            if nul_realloc:
                write(d, 0)
        if chr(c) in ec.ENTITY:
            x = ec.ENTITY[chr(c)].encode()
            p = d
            while True:
                if p >= st["len"]:
                    raise Fault
                if st["mem"][p] == 0:
                    break
                p += 1
            for i, b in enumerate(x):
                write(p + i, b)
            write(p + len(x), 0)
            st["d"] = d + len(x)
            return
        if c >= 127:
            s = ("&#x%X;" % c).encode()
            for i, b in enumerate(s):
                write(d + i, b)
            write(d + len(s), 0)
            d += len(s)
            if nul_sprintf:
                write(d, 0)
        elif c >= 20:
            if plain in ("nul", "plain", "twice"):
                write(d, c & 0xFF)
                d += 1
                if plain == "nul":
                    write(d, 0)
            elif plain == "none":
                write(d, 0)
        if plain == "twice":
            write(d, c & 0xFF)
            d += 1
            write(d, 0)
        st["d"] = d

    if loop == "fixed":
        seq = list(us)
    elif loop == "skip":
        seq = list(us[1:]) + [0] if us else []
    elif loop == "outer":
        seq = list(us[1:])
    elif loop == "once":
        seq = [us[0] if us else 0]
    elif loop == "stuck":
        if us:
            return "HANG"
        seq = []
    else:
        raise ValueError(loop)
    try:
        for c in seq:
            body(c)
        write(st["d"], 0)
    except Fault:
        return "ASAN"
    if alloc == "both":
        return "ASAN"
    out = bytes(st["mem"][:st["mem"].index(0)])
    want = "".join(ec.spec_unit(c) for c in us).encode("latin-1")
    return "OK" if out == want else "WRONG"


def pred(case, variant):
    cfg = dict(FULL, **VARIANTS[variant])
    if "func" in case:
        if case["text"] is None:
            return "OK"
        if case["func"] in "aA":
            return wp.base_class(ec.units(case["text"], False))
        cls = run(ec.units(case["text"], True), **cfg)
        return "WRONG" if cls == "HANG" else cls
    kind = case["kind"]
    if kind == "issue" and wp.ISSUE[case["report"]][1] == "e":
        return wp.ISSUE[case["report"]][0] or "-"
    if kind in ("issue", "poc"):
        if cfg["alloc"] in ("both", "none"):
            return "ASAN"
        if cfg["loop"] == "stuck":
            return "WRONG"
        if kind == "poc":
            return "OK" if variant in EQUIV else "-"
        return "OK" if variant in SAFE else "-"
    # blk12 and txt: R2000 files, htmlescape, base class
    return "ASAN" if wp.base_class(ec.units(case["value"], False)) == "ASAN" else "WRONG"


def main():
    cases = ec.unit_cases() + ec.file_cases()
    cols = list(VARIANTS)
    print("case\t" + "\t".join("ours:" + v for v in cols))
    for case in cases:
        print(case["name"] + "\t" + "\t".join(pred(case, v) for v in cols))


if __name__ == "__main__":
    main()
