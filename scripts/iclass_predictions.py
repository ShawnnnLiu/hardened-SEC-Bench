"""Predicted result class of every case of scripts/iclass_cases.tsv under each
hypothesis, for scripts/check_predictions.py (mruby.cve-2018-11743).

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG,
ASAN, INV (an ICLASS-INVARIANT runtime error from the assertion variant) or -.

dev: the developer's model, from the fix commit "Should not call
  initialize_copy for TT_ICLASS; fix #4027" and its body ("Since TT_ICLASS is a
  internal object that should never be revealed to Ruby world"). The model says
  init_copy must not call initialize_copy on a TT_ICLASS object; it predicts a
  crash on the base build for every duplication that re-enters init_copy on a
  prepended iclass (f1) and a complete fix by the patch (which copies the iclass
  with copy_class and returns before the mrb_funcall). It predicts no change for
  duplications that do not touch a prepended iclass (b, c).

ours: H1, the reported failure. init_copy() dispatches initialize_copy on a
  TT_ICLASS copy whose fields copy_class/mrb_obj_dup left uninitialized (the base
  switch has no MRB_TT_ICLASS case), so the method lookup on the uninitialized
  iclass runs a wild method that reaches mrb_hash_keys and reads a wild khash
  pointer: SEGV (ASAN) on the base build. Duplicating a class or module that
  carries a prepended module (dup or clone) re-enters init_copy on the prepended
  iclass, because copy_class's MRB_FLAG_IS_PREPENDED branch calls mrb_obj_dup on
  each prepended iclass; this is the f1 family (a user class, a user class with
  its own initialize_copy, Object, Hash, Array, String; one or two prepended
  modules; dup and clone; and the dataset PoC). The developer patch adds
  case MRB_TT_ICLASS: copy_class(mrb, dest, obj); return; so initialize_copy is
  never dispatched on the iclass and the copy is correct (the value matches
  CRuby 2.7): OK on the developer build.
  H2, scope: a duplication that does not dup a prepended iclass never reaches the
  faulty state. No prepend (b_dup_noprepend, b_clone_noprepend); include rather
  than prepend (b_include_dup: the included iclass sits in the shared super
  chain, not the MRB_FLAG_IS_PREPENDED branch, so it is not dup'd); prepend with
  no copy (b_prepend_nocopy); and an object dup whose init_copy copies ivars, not
  a class (b_extend_dup). The plain value copies (c) likewise. OK on every build.
  assert_before / assert_after: scripts/iclass_invariant_before.diff and
  iclass_invariant_after.diff make init_copy print ICLASS-INVARIANT and return
  before mrb_funcall when mrb_type(obj) == MRB_TT_ICLASS, changing nothing else.
  On the base build the marker fires on exactly the f1 cases (INV); with the
  patch the MRB_TT_ICLASS switch case returns before the inserted check is
  reached, so the marker never fires and the f1 cases are OK. The b and c cases
  never reach init_copy on an iclass: OK on both.
  H3, observability (noted, not deciding): whether an f1 case produces a
  sanitizer report on the uninstrumented base build depends on the garbage left
  in the uninitialized iclass copy; a case that does not fault would read OK or
  WRONG on `before` while still reaching the dispatch (INV on assert_before). The
  prediction is ASAN for every f1 case on `before`; a mismatch there is an
  observability mismatch, not an invariant mismatch, and the assert_before INV
  column is the sound, layout-independent oracle.

This file was written on 2026-11-04 before the before variant ran. Known when it
was written: poc_before.log (the SEGV in mrb_hash_keys) and poc_after.log (no
report), and the CRuby 2.7.0 values of scripts/iclass_expected.tsv; no case of
the table had been run with mruby.

Revision of 2026-11-04, after the first check (logs/mruby.cve-2018-11743/
predictions_run1.tsv and predictions_run1.log): H4, the method-table leak the
patch's remedy introduces. Run 1 predicted, for every f1 case, ASAN on before
and OK on after. The reach is confirmed (assert_before 19/19, all 11 f1 cases
INV), but the uninstrumented before/after columns diverge between the dataset
PoC and the user-module cases, so f1 is split into poc and f1_leak:
  - poc (the dataset (Hash prepend Enumerable).dup): before ASAN, after OK,
    assert_before INV, assert_after OK, as predicted; the Enumerable prepend
    does not reach the mt copy.
  - f1_leak (the 10 user-module dup/clone cases): on before the dispatch on the
    uninitialized iclass raises NoMethodError, not a sanitizer report (WRONG vs
    CRuby, observability per H3); on after and assert_after the patch routes the
    iclass to the base copy_class, which copies the iclass method table
    (src/kernel.c:269) that the iclass copy owns but mrb_close never frees, so
    LeakSanitizer reports a leak (ASAN) while the copy's value is still correct
    (e.g. d.new.w == :mw). The reported SEGV invariant (H1) is unchanged and is
    enforced by the patch (assert_after 0 INV); the leak is a different faulty
    state introduced by the remedy (the base copy_class's unconditional mt
    copy), fixed upstream later in copy_class (c0c4219b). This revision was made
    after the observations and is not a test of H4.
"""
import csv
import sys

COLS = ["dev:before", "dev:after", "ours:before", "ours:after",
        "ours:assert_before", "ours:assert_after"]

POC = ["poc"]
F1_LEAK = ["f1_user_dup", "f1_user_clone", "f1_user_super", "f1_two_dup",
           "f1_initcopy_dup", "f1_object_dup", "f1_hash_dup", "f1_hash_clone",
           "f1_array_dup", "f1_string_clone"]

#                  dev:b   dev:a  ours:b   ours:a  asb    asa
ROW = {
    "poc": ["ASAN", "OK", "ASAN", "OK", "INV", "OK"],
    "f1_leak": ["ASAN", "OK", "WRONG", "ASAN", "INV", "ASAN"],
    "ok": ["OK"] * 6,
}


def group(name):
    if name in POC:
        return "poc"
    if name in F1_LEAK:
        return "f1_leak"
    return "ok"  # b_* and c_*


cases = [r[0] for r in csv.reader(open(sys.argv[1] if len(sys.argv) > 1 else
                                       "scripts/iclass_cases.tsv"), delimiter="\t")]
for n in POC + F1_LEAK:
    assert n in cases, n
print("case\t" + "\t".join(COLS))
for n in cases:
    assert group(n) != "ok" or n.startswith(("b_", "c_")), n
    print(n + "\t" + "\t".join(ROW[group(n)]))
