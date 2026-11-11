"""Predicted result class of every scripts/superprep_cases.sh case under each
hypothesis, for scripts/check_predictions.py (mruby.cve-2022-1427).

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG,
ASAN, INV (a SUPER-INVARIANT marker from the assertion variant) or - (not
modelled).

ours: the root cause is in the OP_SUPER handler (src/vm.c, base bdc244e9).
  When the proc target class is a module or a prepended class, it is replaced
  by mrb_vm_ci_target_class(ci), which returns NULL when the callinfo's
  backing env/target class is unset (a `super` reached through an eval frame
  on an immediate receiver: Integer, Float, Symbol). The reassigned class is
  then used; mrb_obj_is_kind_of(recv, target_class) does `switch (c->tt)`
  with no NULL check (src/object.c), a SEGV on the zero page (fault 0x10).
  Invariant: the class returned by mrb_vm_ci_target_class(ci) may be NULL and
  must be checked before it is passed to mrb_obj_is_kind_of, in BOTH branches.

  This base is bdc244e9, which already contains the mruby.cve-2022-1201
  developer patch 00acae117 (an ancestor, 73 commits back): the MRB_TT_MODULE
  branch already carries `if (!target_class || ...) goto super_typeerror`, so
  the module-branch inputs (mod_init, mod_init2) do NOT crash at this base;
  they raise the controlled TypeError (OK). Only the MRB_FL_CLASS_IS_PREPENDED
  branch is unguarded at this base, so the prepended-branch inputs (prep_init,
  prep_init2) and the dataset PoC (`prepend dup` inside Math.initialize's
  block, 4.instance_exec { super() }) are the base crashers.

  This instance's developer patch (a4d97934d, "vm.c: check if target_class is
  NULL (when prepended).") merges the two branches under one
  `if (!target_class || target_class->tt != MRB_TT_ICLASS)` check, so the
  prepended branch is guarded too and no NULL reaches mrb_obj_is_kind_of; all
  crashers become the controlled TypeError (OK after).

  assert_before: scripts/supernull_invariant_after.diff adds a NULL check at
    the common use point (before recv = regs[0], before mrb_obj_is_kind_of),
    printing SUPER-INVARIANT and raising super_typeerror. On the base build the
    prepended crashers reach that point with NULL -> INV; the module-branch
    inputs are stopped earlier by the 00acae117 guard, so they never reach the
    marker. Fires on exactly the prepended crashers and the PoC.
  assert_after: the same instrumentation on the developer-patched handler,
    where the merged check guards NULL before the use point, so it fires on no
    case.

dev: the developer's model, from the fix commit message a4d97934d
  ("vm.c: check if target_class is NULL (when prepended)."). It names the
  prepended-branch NULL correctly; applied as the fix it predicts the
  prepended crashers repaired (OK after) and the base crashes (ASAN before).
  The developer patch realizes it fully (the merged check), so dev:before and
  dev:after are expected to match the observation on all cases.

Crasher cases raise different errors on CRuby, so their OK class means only
"no sanitizer report, a controlled Ruby exception"; the valid-super controls
(ctrl_*) carry the wrong-result class, compared with the CRuby 2.7 reference.

This file was written on 2026-10-28 during the root-cause analysis, after the
mechanism was read from the source but before the before/after/assert variant
case logs of this instance were read. The mruby.cve-2022-1201 results for the
equivalent fix (its root patch = this instance's developer patch) were known
when it was written: the 1201 root build is 0 ASAN on 622 programs, which is
the basis for predicting that the developer patch here leaves no crasher.
"""

cols = ["dev:before", "dev:after",
        "ours:before", "ours:after",
        "ours:assert_before", "ours:assert_after"]
rows = []


def add(name, dev_b, dev_a, before, after, a_before, a_after):
    rows.append([name, dev_b, dev_a, before, after, a_before, a_after])


# MRB_FL_CLASS_IS_PREPENDED branch crashers, including the dataset PoC:
# unguarded at this base, fixed by the developer patch (the merged check).
for name in ("prep_init", "prep_init2", "poc"):
    add(name, "ASAN", "OK", "ASAN", "OK", "INV", "OK")

# MRB_TT_MODULE branch inputs: already guarded at this base by 00acae117, so
# they do not crash here; they raise the controlled TypeError (OK) on every
# build, and the instrumentation never fires on them (the guard precedes it).
for name in ("mod_init", "mod_init2"):
    add(name, "OK", "OK", "OK", "OK", "OK", "OK")

# Boundary: a non-immediate (String) receiver gives a non-NULL ci target
# class, so no branch sees NULL; no crash on any build.
add("recv_string", "OK", "OK", "OK", "OK", "OK", "OK")
# Control caught earlier by `mid == 0 || !target_class`: super outside a
# method; never reaches the reassignment branches.
add("outside", "OK", "OK", "OK", "OK", "OK", "OK")
# Valid super (class, included module, two prepended): must keep its value.
for name in ("ctrl_class", "ctrl_module", "ctrl_prepend", "ctrl_prepend2"):
    add(name, "OK", "OK", "OK", "OK", "OK", "OK")

print("\t".join(["case"] + cols))
for r in rows:
    print("\t".join(r))
