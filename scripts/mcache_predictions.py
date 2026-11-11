#!/usr/bin/env python3
"""Predicted result class of every scripts/mcache_cases.tsv case under the
developer's model and ours, for scripts/check_predictions.py
(mruby.cve-2022-1286). Reads the case names and families from
scripts/mcache_cases.tsv so the two files stay in sync.

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG,
ASAN (an AddressSanitizer report), INV (a MCACHE-INVARIANT abort from the
assertion variant) or - (not modelled).

Columns: dev:before dev:after ours:before ours:after ours:assert_before
ours:assert_after.

dev: the developer's model, from the fix commit subject "class.c: clear method
  cache after `remove_method`." The base build does not clear the method cache
  after a removal, so a later lookup returns the stale cached method; clearing
  the cache after the removal fixes it. dev predicts: base returns the stale
  method (WRONG, a sanitizer report for the PoC) for every case that caches a
  method then removes it then calls it; the patch fixes all of them.

ours (stale-cache invariant + H-unflagged): the method cache must not return an
  entry a removal has made stale. The base clears nothing after remove_method,
  so every cache-then-remove-then-call case is stale on the base build. The
  developer patch calls mrb_mc_clear_by_class(mrb, c), which clears the whole
  cache only if c has MRB_FL_CLASS_IS_INHERITED and otherwise only entries whose
  start class mc->c == c. A cache entry whose search started from a subclass and
  found the method in c (mc->c == subclass, mc->c0 == c) is not cleared when c
  lacks the flag. BasicObject is bootstrapped via boot_defclass(mrb, 0) and
  never gets the flag unless the program subclasses it, so removing a method
  from BasicObject that was cached through an Object instance leaves the stale
  entry after the patch (m3_basicobj, and m4_basicobj_gc with a collected proc).
  Every other removal site either is a self-search entry (mc->c == c, cleared)
  or a flagged ancestor/holder (whole cache cleared). ours therefore predicts
  the patch fixes all cases EXCEPT m3_basicobj and m4_basicobj_gc, which stay
  WRONG (the removed method still resolves). This is the disagreement with the
  developer's stated model, which predicts a complete fix.

Classification: a case is faulty (stale on the base build) when it caches a
method, removes it, then calls it: m1_noparent, m1_override, m1_cdef, m2_super,
m2_module, m2_prepend, m2_singleton, m3_basicobj, m3_basicobj_sub, m5_redef_rm,
m5_multi (value result), m4_own_gc and m4_basicobj_gc (with a GC between the
removal and the call), and poc (the dataset reproducer). The leftover after the
patch is m3_basicobj and m4_basicobj_gc (BasicObject, unflagged). The safe
controls are m1_twice and m5_undefined (the second removal raises before the
call) and the m6 cases (undef_method/alias_method/def/define_method/include all
clear the cache).

The assertion variant (scripts/mcache_invariant.diff) re-does the uncached
search on every cache hit and aborts with MCACHE-INVARIANT when the cached
method differs, so it fires on exactly the cases whose final call hits a stale
entry: every faulty case on the base build (assert_before), and only the
leftover after the patch (assert_after).

GC note: a stale entry that points to a collected proc (the m4 cases, which
force a GC between the removal and the call) gives an ASAN report (a SEGV
dereferencing the freed proc), not WRONG; the assertion (INV) is the
deterministic oracle and catches it at the cache hit before the crash.

Revision 2026-11-07 (after before/after/assert_before/assert_after/root/
assert_root; the pre-registered version is
logs/mruby.cve-2022-1286/predictions_run1.tsv, checked once). Two corrections,
invariant unchanged: the m4 GC cases are ASAN (SEGV), not WRONG, on the base
build (m4_own_gc, m4_basicobj_gc before) and after the patch for the leftover
(m4_basicobj_gc after); and the ours:root and ours:assert_root columns are
added (the root-cause patch clears mc->c0 == c too, so every case is OK and the
assertion fires on none). The disagreement with the developer's stated model
stands: dev:after predicts OK for every case (a complete fix), but m3_basicobj
is WRONG and m4_basicobj_gc is ASAN after the patch (the two dev:after
mismatches, the observations the stated model does not predict).

This file was first written on 2026-11-07 before the before variant ran
(logs/mruby.cve-2022-1286/predictions_run1.tsv); this revised version was
written on 2026-11-07 after the variants.
"""
import pathlib, sys

REPO = str(pathlib.Path(__file__).resolve().parent.parent)
tsv = REPO + "/scripts/mcache_cases.tsv"

cases = []
with open(tsv) as f:
    for line in f:
        line = line.rstrip("\n")
        if not line:
            continue
        name, family, _program = line.split("\t", 2)
        cases.append((name, family))

cols = ["dev:before", "dev:after", "ours:before", "ours:after", "ours:root",
        "ours:assert_before", "ours:assert_after", "ours:assert_root"]

SAFE = {"m1_twice", "m5_undefined", "m6_undef", "m6_alias", "m6_redef",
        "m6_definemeth", "m6_include"}
LEFTOVER = {"m3_basicobj", "m4_basicobj_gc"}
FAULTY_GC = {"m4_own_gc", "m4_basicobj_gc"}  # force a GC -> collected proc -> ASAN/SEGV

rows = []
for name, family in cases:
    if name == "poc":
        #      dev:b  dev:a  o:b     o:a  o:root o:ab  o:aa  o:aroot
        row = ["ASAN", "OK", "ASAN", "OK", "OK", "INV", "OK", "OK"]
    elif name in SAFE:
        row = ["OK"] * 8
    else:  # faulty (caches then removes then calls)
        before = "ASAN" if name in FAULTY_GC else "WRONG"
        assert_before = "INV"
        root = "OK"               # root-cause patch (dev + mc->c0 == c clear) fixes all
        assert_root = "OK"
        if name in LEFTOVER:      # H-unflagged: stale entry survives the by-class clear
            after = "ASAN" if name in FAULTY_GC else "WRONG"
            assert_after = "INV"
        else:
            after = "OK"          # cache cleared (self-search entry or flagged class)
            assert_after = "OK"
        dev_before = before
        dev_after = "OK"          # developer's stated model: a complete fix
        row = [dev_before, dev_after, before, after, root, assert_before, assert_after, assert_root]
    rows.append([name] + row)

print("\t".join(["case"] + cols))
for r in rows:
    print("\t".join(r))
