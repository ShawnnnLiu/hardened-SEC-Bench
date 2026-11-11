"""Predicted result class of every scripts/supernull_cases.sh case under each
hypothesis, for scripts/check_predictions.py (mruby.cve-2022-1201).

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG,
ASAN, INV (a SUPER-INVARIANT marker from the assertion variant) or - (not
modelled).

ours: the root cause is in the OP_SUPER handler (src/vm.c, base d1f1b4ea).
  When the proc target class is a module or a prepended class, it is replaced
  by mrb_vm_ci_target_class(ci), which returns NULL when the callinfo's
  backing env/target class is unset (a `super` reached through an eval frame
  on an immediate receiver). The reassigned class is then used without a NULL
  check: the MRB_TT_MODULE branch dereferences target_class->tt, and the
  MRB_FL_CLASS_IS_PREPENDED branch falls into mrb_obj_is_kind_of(recv,
  target_class), which does `switch (c->tt)` with no NULL check. Either is a
  SEGV. Invariant: the class returned by mrb_vm_ci_target_class(ci) may be
  NULL and must be checked before it is used, in BOTH branches.

  The developer patch adds `!target_class ||` to the MRB_TT_MODULE branch
  only, so it fixes the module-branch crashers (mod_init, mod_init2, poc) but
  leaves the prepended-branch crashers (prep_init, prep_init2) crashing. The
  root-cause patch keeps the developer line and adds the same NULL guard to
  the MRB_FL_CLASS_IS_PREPENDED branch, fixing both.

  assert_before: scripts/supernull_invariant_before.diff prints SUPER-INVARIANT
    (and raises the controlled super_typeerror instead of crashing) when the
    reassigned target_class is NULL at a use point, in both branches; it fires
    on exactly the crashers.
  assert_root: scripts/supernull_invariant_after.diff adds the same check at
    the common use point of the root-patched handler, where both branches
    already guard NULL, so it fires on no case.

dev: the developer's model, from the fix commit message 00acae117
  ("vm.c: target class may be NULL."). The explanation names the root cause
  correctly and predicts the base crashes; applied as a complete fix it would
  repair every NULL case. The developer patch realizes it for the module
  branch only, so the prepended-branch crashers contradict the patch's
  completeness on dev:after. There are no dev assert columns.

Crasher cases raise different errors on CRuby (e.g. a NoMethodError for a
private `initialize`), so their OK class means only "no sanitizer report, a
controlled Ruby exception"; the valid-super controls (ctrl_*) carry the
wrong-result class, compared with the CRuby 2.7 reference.

This file was written on 2026-10-13 during the root-cause analysis, after the
mechanism was read from the source but before the before/after/root/assert
variant case logs were read; the control values were validated against the
image CRuby 2.7 beforehand.
"""

cols = ["dev:before", "dev:after",
        "ours:before", "ours:after", "ours:root",
        "ours:assert_before", "ours:assert_root"]
rows = []


def add(name, dev_b, dev_a, before, after, root, a_before, a_root):
    rows.append([name, dev_b, dev_a, before, after, root, a_before, a_root])


# MRB_TT_MODULE branch crashers, including the dataset PoC: fixed by the
# developer patch and by the root patch.
for name in ("mod_init", "mod_init2", "poc"):
    add(name, "ASAN", "OK", "ASAN", "OK", "OK", "INV", "OK")

# MRB_FL_CLASS_IS_PREPENDED branch crashers: NOT fixed by the developer patch
# (dev:after predicts OK, observed ASAN), fixed by the root patch.
for name in ("prep_init", "prep_init2"):
    add(name, "ASAN", "OK", "ASAN", "ASAN", "OK", "INV", "OK")

# Boundary: a non-immediate (String) receiver gives a non-NULL ci target
# class, so no branch sees NULL; no crash on any build.
add("recv_string", "OK", "OK", "OK", "OK", "OK", "OK", "OK")
# Control caught earlier by `mid == 0 || !target_class`: super outside a
# method; never reaches the reassignment branches.
add("outside", "OK", "OK", "OK", "OK", "OK", "OK", "OK")
# Valid super (class, included module, two prepended): must keep its value.
for name in ("ctrl_class", "ctrl_module", "ctrl_prepend", "ctrl_prepend2"):
    add(name, "OK", "OK", "OK", "OK", "OK", "OK", "OK")

print("\t".join(["case"] + cols))
for r in rows:
    print("\t".join(r))
