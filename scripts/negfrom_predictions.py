"""Predicted result class of every scripts/negfrom_cases.py case under each
hypothesis, for scripts/check_predictions.py (njs.cve-2022-31307).

Usage: python3 negfrom_predictions.py > negfrom_predictions.tsv

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG,
ASAN, INV (a NEGFROM-INVARIANT check fired) or - (no prediction).

Written on 2026-10-14 at about 02:14 EDT, before any case of the families
that reach the faulty state (viol = 1) had run in a variant.

Definitions. n is the length of the string, `from` the start index that
Array.prototype.lastIndexOf() hands to njs_object_iterate_reverse():
from = n + fromIndex for a negative fromIndex, min(fromIndex, n - 1)
otherwise, to = 0 (src/njs_array.c, njs_array_prototype_reverse_iterator()).

ours: the invariant is stated on the call, not on the symptom.
  H1 (the reported failure). For a UTF-8 string (length != size in bytes),
  njs_object_iterate_reverse() must pass njs_string_offset() an index
  inside the string, 0 <= from < n; njs_string_offset() "assumes that
  index is correct" (src/njs_string.c) and has no check of its own. The
  base build calls it before it knows whether the loop `i = from + 1;
  while (i-- > to)` runs, so every case with from < 0 (fromIndex <
  -length, including -Infinity) and a UTF-8 receiver (string primitive,
  String object, or the PoC shape, a String object with an array as
  prototype) reaches the faulty state. The instrumented build
  (negfrom_invariant_before.diff) therefore fires on exactly these cases
  (class INV) and on no other, whatever the symptom.
  H2 (the symptom is not determined by H1). The call turns the negative
  int64 into a huge size_t, reads the offset-map entry at map + 4 *
  (index / 32 - 1) (a wrapped address), adds the value read to the start
  pointer, and walks njs_utf8_next() from there. Whether that read and the
  walk fault depends on the bytes and the mapping around the string, which
  H1 does not model; the base-build class of a violating case is therefore
  not predicted (-) in ours:before and ours:cvenvd_base. The dataset PoC
  is the one violating case whose class was observed before this file was
  written (poc_before.log: ASan SEGV), and it is predicted ASAN.
  H3 (the patch). The developer patch computes the byte pointer only when
  i = from + 1 > to, that is from >= 0 (to = 0), so no violating case
  reaches njs_string_offset(); with from >= 0 the single caller guarantees
  from <= n - 1. Every case is then OK (equal to the reference) after the
  patch, and the guarded call is never reached with an invalid index
  (ours:assert_after, the same check inside the guard,
  negfrom_invariant_after.diff, never fires).
  H4 (scope). Nothing else changes: reduceRight (from = n - 1), ASCII and
  byte strings (another branch, no offset), arrays and array-likes, and
  the other callers of njs_string_offset() exercised by the d_* cases are
  OK on every build. A non-OK result in these families is an independent
  defect, not a part of H1.
  Variants: before (base), after (developer patch), assert_before (base +
  negfrom_invariant_before.diff), assert_after (developer patch +
  negfrom_invariant_after.diff), cvenvd_base / cvenvd_after (the CVE_NVD
  base commit 982100ba without / with the developer patch), upstream_master
  (origin/master, where the guard is kept and njs_string_offset() was
  generalised in ea0a09cd).

dev: the developer's model, from the message of eafe4c7a: "when
  lastIndexOf() was called with unicode string as "this" argument and a
  negative "fromIndex" argument null-pointer dererence might occur because
  njs_string_offset() was called with invalid index value ... The fix is
  to verify that from index is valid." Read literally, a negative fromIndex
  with a UTF-8 receiver crashes the base build, whatever its size, and the
  patch removes every crash. It does not distinguish fromIndex = -n (from =
  0, valid) from fromIndex < -n.

x_* cases (the replacement templates $' and $` on a UTF-8 string, wrong on
the base build because of a character offset used as a byte offset, fixed
upstream in 485b3657) are not predicted.

Observations on the base build that precede this file (scripts not kept as
logs unless stated):
- poc_before.log and apply.log/poc_after.log: the dataset PoC crashes the
  base build (12 of 12 frames equal to the dataset report) and not the
  developer-patch build; the PoC passes `...-1000000000.0` and njs at the
  base commit passes a call-site spread as the single argument, so the
  call is lastIndexOf(s, -1000000000) (probe: f(...[7,8]) receives one
  argument).
- 12 exploratory scripts: a String object keeps its own `length` when its
  prototype is replaced by an array (so from <= n - 1 always); ASCII
  strings with the same negative fromIndex give the reference value; the
  UTF-8 string cases with from = -1, -2 and -999999999 crash on 1-, 2- and
  40-character strings; reduceRight over UTF-8 strings and the empty string
  gives the reference value; classes are not supported by this njs.
- a sweep of 117 UTF-8 inputs with from < 0 (9 string lengths from 1 to 100
  characters, 13 values of -from from 1 to 2^53 and -Infinity), one process
  each: 103 ASan SEGV reports at 8 distinct program counters and 14 runs
  that print the reference value (-1) without a report (excess 100 for
  strings of 1 to 3 characters, 10^6 for strings of 1 to 40 characters,
  1000 for 64 characters, -Infinity for 33 characters or more). This is the
  basis of H2.
- the disassembly of njs_string_offset() in the base build and the
  arithmetic of the PoC's fault address (the address read is the wrapped
  map entry, 0x2000524ff89a0a2c, of which the report shows the low 48 bits).
- a calibration run of the 246 cases that do not reach the faulty state on
  the base build against the reference: 244 equal, 2 different (x_*). Two
  deviations found in it were excluded from the case set: codePointAt()
  returns NaN where the reference returns undefined for an index outside
  the string (7 cases), and endsWith(t, p) with a negative end position p
  uses the length where the reference clamps p to 0 (4 cases; the index
  computed there is inside the string). No case crashed in the calibration
  run, so no call site other than the reverse iteration reached an invalid
  index with those arguments.
The predictions for the non-violating cases (OK everywhere) therefore
follow the calibration; the predictions for the violating cases and for
the instrumented and patched builds do not depend on any run of those
cases.

The expected values are the Node.js v22.22.2 outputs
(scripts/negfrom_expected.tsv).
"""
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from negfrom_cases import lio_cases, rr_cases, ctl_cases, d_cases, is_viol  # noqa: E402

COLS = ["dev:before", "dev:after", "ours:before", "ours:after", "ours:assert_before",
        "ours:assert_after", "ours:cvenvd_base", "ours:cvenvd_after", "ours:upstream_master"]

# fromIndex tokens that are negative numbers (the developer's trigger)
NEGATIVE_TOKENS = {"inf", "neg_n", "neg_1", "cstr", "cobj", "cflt"}


def negative_findex(name):
    if name == "viol_poc_nospread":
        return True
    tok = name.split("_", 3)[3]
    if tok.endswith("_tl"):
        tok = tok[:-3]
    return tok.startswith("v") or tok in NEGATIVE_TOKENS


def row(name, family, from_):
    if family == "x":
        return dict.fromkeys(COLS, "-")
    viol = family == "lio" and is_viol(from_)
    if not viol:
        c = dict.fromkeys(COLS, "OK")
        if family == "lio" and negative_findex(name):
            c["dev:before"] = "ASAN"        # negative fromIndex, valid from: the literal dev model still predicts a crash
        return c
    return {"dev:before": "ASAN", "dev:after": "OK",
            "ours:before": "-", "ours:after": "OK", "ours:assert_before": "INV",
            "ours:assert_after": "OK", "ours:cvenvd_base": "-", "ours:cvenvd_after": "OK",
            "ours:upstream_master": "OK"}


def main():
    w = csv.writer(sys.stdout, delimiter="\t", lineterminator="\n")
    w.writerow(["case"] + COLS)
    for gen in (lio_cases, rr_cases, ctl_cases, d_cases):
        for name, family, recv, sname, n, from_, _body in gen():
            c = row(name, family, from_)
            w.writerow([name] + [c[col] for col in COLS])
    # the dataset PoC, added by the runner as case "poc": observed to crash the
    # base build before this file was written, no output and no report after
    w.writerow(["poc", "ASAN", "OK", "ASAN", "OK", "INV", "OK", "ASAN", "OK", "OK"])


if __name__ == "__main__":
    main()
