"""Residual predictions for njs.cve-2022-29780, written 2026-10-28 before the
resid_before/resid_after/resid_master variants of scripts/sortconv_residual_cases.py ran.

ours: the write-back fast branch uses the pre-sort len against array->start.
A comparator (or toString) that SHIFTS the receiver advances array->start
while the array stays fast, so the write-back overflows (heap-buffer-overflow);
the developer patch's njs_is_fast_array check does not catch a fast resize, so
the two shift cases crash on both the base build and the developer-patch build
and are fixed only at master (5f4b5f27 adds the length-equality check).
A pop (length decremented, start not advanced) and a push (grow, start re-read)
do not overflow on any build.
  resid_shift_tostr, resid_shift_cmp: resid_before ASAN, resid_after ASAN, resid_master OK.
  resid_pop_cmp, resid_push_cmp:      OK on all three.

Column ours:resid_root added 2026-11-06, before the resid_root variant ran:
the root patch (patches/njs.cve-2022-29780.root.diff) adds the 5f4b5f27
length-equality check before the developer line, so a shifted receiver takes
the slow write-back path, as at master; every case is predicted OK.
"""
COLUMNS = ["ours:resid_before", "ours:resid_after", "ours:resid_master",
           "ours:resid_root"]
ROWS = {
    "resid_shift_tostr": ["ASAN", "ASAN", "OK", "OK"],
    "resid_shift_cmp":   ["ASAN", "ASAN", "OK", "OK"],
    "resid_pop_cmp":     ["OK", "OK", "OK", "OK"],
    "resid_push_cmp":    ["OK", "OK", "OK", "OK"],
}
print("\t".join(["case"] + COLUMNS))
for k in sorted(ROWS):
    print("\t".join([k] + ROWS[k]))
