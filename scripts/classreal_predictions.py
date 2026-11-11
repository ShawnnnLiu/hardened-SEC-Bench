"""Predicted result class of every case of scripts/classreal_cases.tsv under each
hypothesis, for scripts/check_predictions.py (mruby.cve-2018-12249).

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG,
ASAN, INV (a CLASSREAL-INVARIANT runtime error from the assertion variant) or -.

dev: the developer's model, from the fix commit "mrb_class_real() did not work
  for BasicObject; fix #4037". The model: mrb_class_real must work for a class
  (BasicObject) whose super chain, walked past singleton classes and iclasses,
  reaches a NULL super. It predicts a crash on the base build for reopening a
  prepended BasicObject with a declared superclass (family d, the reported path
  through mrb_vm_define_class) and a complete fix by the patch (after: OK). It
  predicts no change for inputs that do not walk a NULL-ending chain in
  mrb_class_real (families b, cons, c).

ours: H1, the reported failure. mrb_class_real (src/class.c:1764) strips
  SCLASS/ICLASS nodes with `while ((cl->tt==SCLASS)||(cl->tt==ICLASS)) cl=cl->super;`
  and reads cl->tt again after the assignment without checking cl. Prepending a
  module to BasicObject (the root class, own super NULL) inserts an iclass whose
  super is NULL, so mrb_class_real(BasicObject->super) walks ICLASS -> NULL and
  reads NULL->tt: the SEGV at class.c:1768. The reachable caller is
  mrb_vm_define_class (class.c:314), reopening `class BasicObject < Super`.
  Family d (the PoC and the Enumerable / user-module / two-module variants with
  super Class, Object or BasicObject): base ASAN (SEGV). The developer patch adds
  `if (cl==0) return NULL;` in the loop, so mrb_class_real returns NULL and the
  caller raises a TypeError (superclass mismatch), matching CRuby 2.7: after OK.
  H2, scope. The only Ruby-reachable NULL-walk in mrb_class_real is
  mrb_vm_define_class:314. The other callers do not reach it: define_class:230 is
  the C-API reopen branch (not taken from the VM path); mrb_class_inherited
  (class.c:321) receives mrb_class_real(c->super) for a freshly defined class
  whose super is a real class; mrb_obj_class:1863 walks the metaclass chain
  (ends at Class, not NULL); mrb_mod_const_missing:2369 passes a module (tt
  MODULE, loop body not entered). The Class query methods have their own
  NULL-safe loops and do not call mrb_class_real: Class#superclass
  (mrb_class_superclass, class.c:1649: `while (c && c->tt==ICLASS)`),
  Module#ancestors (mrb_mod_ancestors, class.c:1190: `while (c)`). So families b
  (reopen with no prepend or no super; prepend a user class whose original super
  is Object; a new subclass), cons (BasicObject.class / superclass / ancestors /
  inspect / singleton_class after prepend) and c (controls) are OK on every build.
  H3, assertion. scripts/classreal_invariant_before.diff and _after.diff restructure
  the mrb_class_real loop to print CLASSREAL-INVARIANT and return NULL when the
  walk is about to read cl->tt with cl==NULL (the faulty read). On the base build
  the marker fires on exactly the inputs that read a NULL class (family d): INV.
  With the developer patch the in-loop `if (cl==0) return NULL;` returns before
  the re-read, so the instrumentation never sees a NULL at the read point: no
  marker, and the cases are OK (TypeError, matching CRuby). The b, cons and c
  cases never reach a NULL read: OK on both.

This file was written on 2026-11-07 before the before variant ran. Known when it
was written: poc_before.log (the SEGV at class.c:1768 in mrb_class_real, frames
mrb_class_real / mrb_vm_define_class) and poc_after.log (no sanitizer report;
TypeError: superclass mismatch), and the CRuby 2.7.0 values of
scripts/classreal_expected.tsv; no case of the table had been run with mruby.
"""
import csv
import sys

COLS = ["dev:before", "dev:after", "ours:before", "ours:after",
        "ours:assert_before", "ours:assert_after"]

D_CRASH = ["d_poc", "d_enum_class", "d_enum_object", "d_enum_basicobj",
           "d_user_mod", "d_two_mods"]

#                 dev:b   dev:a  ours:b   ours:a  asb    asa
ROW = {
    "d":  ["ASAN", "OK", "ASAN", "OK", "INV", "OK"],
    "ok": ["OK"] * 6,
}


def group(name):
    if name in D_CRASH:
        return "d"
    return "ok"  # b_*, cons_*, c_*


cases = [r[0] for r in csv.reader(open(sys.argv[1] if len(sys.argv) > 1 else
                                       "scripts/classreal_cases.tsv"), delimiter="\t")]
for n in D_CRASH:
    assert n in cases, n
print("case\t" + "\t".join(COLS))
for n in cases:
    assert group(n) != "ok" or n.startswith(("b_", "cons_", "c_")), n
    print(n + "\t" + "\t".join(ROW[group(n)]))
