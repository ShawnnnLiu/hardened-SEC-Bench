#!/usr/bin/env python3
"""Predictions for the ablation variants of the developer patch of
libredwg.cve-2020-21816, for the cases of scripts/escape_cases.py.

Written 2026-10-13 at 16:18 EDT (20:18 UTC), before any ablation variant was
built or run (the base, developer-patch and upstream builds had been run by
then). The model was checked against the base model of
scripts/escape_predictions.py (identical on the 305 htmlescape unit cases) and
against the all-fixed setting (all OK).

Usage: python3 escape_ablation_predictions.py > escape_ablation_predictions.tsv

The invariants are those of scripts/escape_predictions.py: I1 (the byte at d
is NUL when strcat runs) and I3 (every character is examined, from the
first). The 58 changed lines of the developer patch (numbered as in
`scripts/ablate_patch.py`) are, by function:
  3,4        malloc -> calloc: the byte at d is NUL at the start (I1)
  5,7,58     `while (*s++)` -> `while (*s)` plus `s++` at the end (I3)
  53-57      braces and `*d = 0;` after a plain character (I1)
  10         `*d = 0;` after realloc (redundant when 53-57 are present)
  52         `*d = 0;` after sprintf (redundant: sprintf ends with NUL)
  1,2,6,8,9,11  the `end` pointer; `end - d <= 8` equals `off >= len - 8`
  12-51      the eight case lines reformatted (no change of behavior)
Variants (groups of ablate_patch.py; all drop the lines listed):
  style 12-51; endvar 1,2,6,8,9,11; style_endvar both; nulrealloc 10;
  nulsprintf 52; nul2 10,52; calloc 3,4; loop 5,7,58; plainbrace 53-57;
  min10 = style + endvar + 10 + 52 (the 10 lines 3,4,5,7,53-57,58 remain);
  min10_nocalloc, min10_noloop, min10_noplain = min10 without the lines of
  calloc, loop, plainbrace; min = min10 as the final minimal patch.
Model: a machine over the input characters with four switches (skip_first:
the first character is not examined, I3 violated; init_t: the byte at d is
NUL at the start; plain_nul: a plain character is followed by a NUL;
grow_nul: the buffer grows with `*d = 0;`) and the capacity logic of the
source (len = n + 10, grown by 10 when len - off <= 8). A character with an
entity met when the byte at d is not NUL is ASAN; otherwise the output is
OK when it equals the table applied to the whole input and WRONG otherwise.
htmlwescape is not changed by any of these variants (base class).
File cases: ASAN if the injected string faults under the machine, else
WRONG when skip_first (every name of the file loses its first character),
else OK. The reproducers of #182 are predicted only where the class does
not depend on their unknown strings (no switch can fault: OK for htmlescape
reports; unchanged for htmlwescape reports); - otherwise.
Single-line variants L1..L58 have no prediction.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import escape_cases as ec  # noqa: E402
import escape_predictions as ep  # noqa: E402

# name: (skip_first, init_t, plain_nul, grow_nul)
FIXED = (False, True, True, True)
VARIANTS = {
    "min": (False, True, True, False),
    "min10": (False, True, True, False),
    "style": FIXED, "endvar": FIXED, "style_endvar": FIXED,
    "nulrealloc": (False, True, True, False), "nulsprintf": FIXED, "nul2": (False, True, True, False),
    "calloc": (False, False, True, True),
    "loop": (True, True, True, True),
    "plainbrace": (False, True, False, True),
    "min10_nocalloc": (False, False, True, False),
    "min10_noloop": (True, True, True, False),
    "min10_noplain": (False, True, False, False),
}


def machine(us, skip_first, init_t, plain_nul, grow_nul):
    length = len(us) + 10
    off = 0
    t = init_t
    seq = us[1:] if skip_first else us
    for c in seq:
        if length - off <= 8:
            length += 10
            if grow_nul:
                t = True
        k = ep.kind(c)
        if k == "S":
            if not t:
                return "ASAN"
            off += len(ec.ENTITY[chr(c)])
            t = True
        elif k == "H":
            off += len("&#x%X;" % c)
            t = True
        elif k == "P":
            off += 1
            t = bool(plain_nul)
    return "OK" if ep.spec_of(seq) == ep.spec_of(us) else "WRONG"


def pred(case, variant):
    sw = VARIANTS[variant]
    if "func" in case:
        if case["text"] is None:
            return "OK"
        if case["func"] in "wW":
            return ep.base_class(ec.units(case["text"], True))
        return machine(ec.units(case["text"], False), *sw)
    if case["kind"] == "issue":
        base_cls, fn = ep.ISSUE[case["report"]]
        if base_cls is None:
            return "-"
        if fn == "w" or base_cls == "OK":
            return base_cls
        # a setting with the byte at d always NUL cannot fault whatever the strings are
        return "-" if not (sw[1] and sw[2]) else "OK"
    value = "*P`per_Space" if case["kind"] == "poc" else case["value"]
    cls = machine(ec.units(value, False), *sw)
    if cls == "ASAN":
        return "ASAN"
    return "WRONG" if sw[0] else "OK"


def main():
    cases = ec.unit_cases() + ec.file_cases()
    cols = list(VARIANTS)
    print("case\t" + "\t".join("ours:" + v for v in cols))
    for case in cases:
        print(case["name"] + "\t" + "\t".join(pred(case, v) for v in cols))


if __name__ == "__main__":
    main()
