#!/usr/bin/env python3
"""Predicted result class of every scripts/breakval_cases.tsv case under the
developer's model and ours, for scripts/check_predictions.py
(mruby.cve-2022-1212). Reads the case names and families from
scripts/breakval_cases.tsv so the two files stay in sync.

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG,
ASAN (an AddressSanitizer report), INV (a BREAKVAL-INVARIANT abort from the
assertion variant) or - (not modelled).

Columns: dev:before dev:after ours:before ours:after ours:stress_before
ours:stress_after ours:assert_before ours:assert_after.

dev: the developer's model, from the fix commit message "vm.c: create break
  object before clearing GC arena. Otherwise it possibly cause use-after-free."
  The break value v is held by the GC arena until mrb_gc_arena_restore; the
  base build restores the arena before break_new allocates the RBreak, so the
  allocation's GC step can free v; creating the break object first keeps v
  arena-reachable across the allocation. dev predicts the UAF on base for a
  heap break value broken through a C-called block, and a complete fix.

ours (arena-protection invariant, confirmed): a heap break value must be
  reachable from a GC root across break_new's MRB_OBJ_ALLOC. On the base build,
  after cipop the value's register is above the current frame and is not
  marked (mark_context_stack), and after mrb_gc_arena_restore the arena no
  longer holds it, so a GC step at break_new frees it. The developer patch runs
  break_new while the arena still holds the value (before the restore). The
  assertion variant shows this deterministically: assert_before fires INV on
  every faulty case, assert_after on none (the patch makes v reachable at
  break_new). H-window (that a register-only break value would stay unprotected
  after the patch) is refuted: assert_after has 0 INV and stress_after 0
  corruption.

Revision 2026-11-07 (after before/after/stress/assert; the earlier version is
logs/mruby.cve-2022-1212/predictions_run1.tsv, checked once). Three model
corrections the mismatches taught:
  1. Scope of the faulty set. The assertion variant shows the break value is
     unreachable at break_new only for some C block callers: Class.new,
     Module.new, ObjectSpace.each_object (families c1, c2 build on Class.new),
     c5_ensure and c5_nestc. The callers instance_exec, instance_eval,
     class_eval and module_exec keep the value reachable (a different yield
     path, mrb_yield_cont), so c3_instance_exec/instance_eval/class_eval/
     module_exec are reclassified not-faulty (assert_before OK, observed OK).
  2. Symptom class under GC stress. A freed mruby object slot is not
     AddressSanitizer-poisoned; break_new's own allocation reuses the freed
     slot, so the faulty cases read a corrupted value (WRONG), not an ASAN
     report. stress_before is predicted WRONG for the faulty value cases. It is
     a non-deterministic lower bound: a freed slot reused as a same-shaped
     value reads OK, so c1_strcat, c1_obj, c3_objspace and c5_ensure read OK in
     the recorded run though they are faulty by the deterministic assert
     oracle; these four are the expected stress_before mismatches. The
     deterministic oracle is assert_before/assert_after.
  3. The default (non-stress) build does not force a GC step at break_new even
     under the c2 pressure cases, so before is OK for every faulty value case;
     only the PoC (which piles allocations and whose freed value is a String
     whose malloc'd buffer str_escape reads, an ASan-poisoned read) is ASAN on
     before, and it is OK under stress (the reused-slot path avoids the
     poisoned-buffer read).
  c5_procreturn is a base mruby/CRuby divergence unrelated to the break UAF
  (`return` from a block called by a C method returns the class in mruby, from
  the enclosing method in CRuby); it is WRONG on every build, before and after
  the patch, and is predicted WRONG throughout.

This file was first written on 2026-11-07 before the before variant ran
(logs/mruby.cve-2022-1212/predictions_run1.tsv); this revised version was
written on 2026-11-07 after the before/after/stress/assert variants.
"""
import pathlib, sys

REPO = str(pathlib.Path(__file__).resolve().parent.parent)
tsv = REPO + "/scripts/breakval_cases.tsv"

cases = []
with open(tsv) as f:
    for line in f:
        line = line.rstrip("\n")
        if not line:
            continue
        name, family, _program = line.split("\t", 2)
        cases.append((name, family))

cols = ["dev:before", "dev:after", "ours:before", "ours:after",
        "ours:stress_before", "ours:stress_after",
        "ours:assert_before", "ours:assert_after"]

# Faulty value cases: a heap break value that is unreachable at break_new on
# the base build (deterministically INV on assert_before). c1 and c2 build on
# Class.new; c3_module_new (Module.new) and c3_objspace (ObjectSpace.each_object)
# are the other two faulty C callers; c5_ensure and c5_nestc too.
NOT_FAULTY_C3 = {"c3_instance_exec", "c3_instance_eval", "c3_class_eval", "c3_module_exec"}
FAULTY_VALUE = set()
for name, family in cases:
    if family in ("c1", "c2"):
        FAULTY_VALUE.add(name)
    elif family == "c3" and name not in NOT_FAULTY_C3:
        FAULTY_VALUE.add(name)
    elif name in ("c5_ensure", "c5_nestc"):
        FAULTY_VALUE.add(name)

rows = []
for name, family in cases:
    if name == "c5_procreturn":
        row = ["WRONG"] * 8
    elif name == "poc":
        #            dev:b  dev:a  o:b    o:a  o:sb o:sa o:ab  o:aa
        row = ["ASAN", "OK", "ASAN", "OK", "OK", "OK", "INV", "OK"]
    elif name in FAULTY_VALUE:
        row = ["OK", "OK", "OK", "OK", "WRONG", "OK", "INV", "OK"]
    else:  # not faulty (reachable value, immediate, or not a break-through-C)
        row = ["OK"] * 8
    rows.append([name] + row)

print("\t".join(["case"] + cols))
for r in rows:
    print("\t".join(r))
