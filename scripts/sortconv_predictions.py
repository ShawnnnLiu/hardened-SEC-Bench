"""Per-case predictions for njs.cve-2022-29780 (Array.prototype.sort with a
comparator that converts the receiving fast array to a slow array during the
sort).

Usage: python3 sortconv_predictions.py > scripts/sortconv_predictions.tsv

Prints a header `case<TAB><model>:<variant>...` and one row per case of
scripts/sortconv_cases.py plus the dataset PoC (case `poc`).  A cell is a
predicted result class: OK, WRONG, ASAN, INV or - (no prediction).  The
observed classes are read by scripts/check_predictions.py from
logs/njs.cve-2022-29780/variants/<variant>.cases.log.

dev model (commit 8b39afda, "Fixed Array.prototype.sort() when arr size is
changed in a comparator.", closes #468): the sort crashes when the array's
size is changed inside the comparator; the fix re-checks that the receiver
is still a fast array at the write-back.  The developer's own test changes
the size by a length set (a.length = 65535).  The model names the construct
(size changed in the comparator) exactly, so it predicts a sanitizer report
on the base build for every case whose comparator converts the array to a
slow array (the conv_ family and the PoC) and OK after the patch, and OK on
every other case.
  dev:before = ASAN on conv_*, poc; OK otherwise.
  dev:after  = OK on every case.

ours (the invariant the reported failure requires): at the write-back loop
(src/njs_array.c:2704, start[i] = slots[i].value) the local flag fast_path,
computed once before the comparator runs, must still describe the receiver.
A fast array is converted to a slow array (array->start freed and set to
NULL, array->fast_array cleared) by a length set above 32768 or an index
assignment with index >= 32768 performed inside the comparator; after that
the write-back fast branch, entered on the stale fast_path, dereferences the
NULL start as an element buffer and writes at address 0 (a SEGV).
  H1: a case reaches the faulty state exactly when its comparator runs
      (a JavaScript comparefn and >= 2 non-undefined elements) and converts
      the receiver to a slow array during the sort.
  ours:before = ASAN on conv_* and poc (converts during the comparator);
      OK on keep_* (mutates but stays fast), pre_* (already slow at
      read-in, so the slow branch is taken throughout) and ctl_* (no
      comparator or no mutation).
  ours:after  = OK on every case (the write-back re-checks njs_is_fast_array,
      so a converted receiver takes the slow write-back path).
  ours:assert_before = INV on exactly the cases that reach the NULL
      write-back on the base build (conv_*, poc); OK otherwise.  The
      instrumentation (scripts/sortconv_invariant.diff) aborts with
      SORTCONV-INVARIANT when the write-back fast branch sees start == NULL.
  ours:assert_after  = OK on every case (0 INV): the converted receiver
      never enters the fast branch after the patch.
  ours:upstream_master = OK on every case (the fix is retained upstream).

This file was written on 2026-10-28 before the before variant of
scripts/sortconv_cases.py ran.  The only prior observation is the dataset
PoC on the base build (poc_before.log: a SEGV at src/njs_array.c:2704).

Column ours:root added 2026-11-06, before the root variant ran, after the
user's review of 2026-11-06 flagged the resize-while-fast residual (issue
#594). The root patch (patches/njs.cve-2022-29780.root.diff) is the developer
patch plus an adapted backport of upstream 5f4b5f27 (its length-equality
check added as new lines before the developer line, its slow-path write of
every slot, its unit tests); every case of this set keeps the array length,
so each is predicted as ours:after.
"""
import sys

# families and their per-column class
# columns: dev:before dev:after ours:before ours:after
#          ours:assert_before ours:assert_after ours:upstream_master
CONV = ["conv_idx_big", "conv_idx_edge", "conv_len_big", "conv_len_edge"]
KEEP = ["keep_idx_edge", "keep_len_edge", "keep_set0"]
PRE = ["pre_idx", "pre_len"]
CTL = ["ctl_cmp", "ctl_like", "ctl_nocmp"]

COLUMNS = ["dev:before", "dev:after", "ours:before", "ours:after",
           "ours:assert_before", "ours:assert_after", "ours:upstream_master",
           "ours:root"]


def row(name, faulty):
    if faulty:
        # dev:before dev:after ours:before ours:after assert_before assert_after master root
        return [name, "ASAN", "OK", "ASAN", "OK", "INV", "OK", "OK", "OK"]
    return [name, "OK", "OK", "OK", "OK", "OK", "OK", "OK", "OK"]


def main():
    print("\t".join(["case"] + COLUMNS))
    rows = []
    for n in CONV:
        rows.append(row(n, True))
    for n in KEEP + PRE + CTL:
        rows.append(row(n, False))
    rows.append(row("poc", True))
    for r in sorted(rows):
        print("\t".join(r))


if __name__ == "__main__":
    main()
