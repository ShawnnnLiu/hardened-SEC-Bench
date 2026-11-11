"""Predicted result class of every scripts/nvalhash_cases.sh case under each
hypothesis, for scripts/check_predictions.py (mruby.cve-2022-0240).

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG,
ASAN, INV (a STACK-INVARIANT marker from the assertion variant, printed at
compile time) or - (not modelled).

ours: the root cause is in gen_hash()
  (mrbgems/mruby-compiler/core/codegen.c). When the hash value is discarded
  (val == 0, NOVAL) the function still emits OP_HASH / OP_HASHADD / OP_HASHCAT
  and the matching pop_n()/push() whenever a `**` splat (NODE_KW_REST_ARGS)
  makes `update` true with a pair, or a pair precedes a `**`. Those pop/push
  move the compiler stack pointer although nothing was pushed for the
  discarded value, so every following instruction is emitted one or two
  registers too low and overwrites locals and temporaries. The invariant: a
  gen_hash() call with val == 0 must not change the compiler stack pointer.
  The symptom is layout dependent (wrong value, runtime TypeError from
  OP_HASHADD on a non-hash register, compile-time "stack pointer underflow",
  or the SEGV in prepare_singleton_class when the shifted code reaches
  OP_SCLASS on an object with a NULL class pointer), but every reaching form
  is not OK on the base build and correct after the root-cause patch. The
  developer patch only guards one consumer (mrb_singleton_class_ptr returns
  NULL -> TypeError), so it leaves every reaching form wrong.

  root: the root-cause patch adds the upstream `val &&` guards to the three
    stack-emitting branches of gen_hash() (backport of b611c43a5 and
    ae3c99767), so a discarded value emits no stack op: every reaching form
    is correct.
  assert_before: scripts/nvalhash_invariant_before.diff fires
    codegen_error("STACK-INVARIANT ...") at the top of each of those three
    branches when val == 0, i.e. exactly when the base build would corrupt
    the stack; the reaching forms fail to compile with the marker (INV) and
    nothing else changes.
  assert_root: scripts/nvalhash_invariant_after.diff adds the same check
    inside the now val-guarded branches, where it is unreachable for a
    discarded value, so no case fires it (OK).

dev: the developer's model, from the fix commit message
  31fa3304 ("class.c: add `obj->c` check before `prepare_singleton_class()`"):
  an object with a NULL class pointer can reach prepare_singleton_class; guard
  it. This models only the one crash site, not the compiler corruption, so it
  predicts the PoC crash on the base build and its repair by the guard, and
  predicts nothing wrong for any other form (OK). The developer proposed no
  instrumentation, so there are no dev assert columns.

The dataset PoC does not separate the developer patch from the root-cause
patch: the PoC's `c` is the Integer 0 ({0=>0,nil=>nil}[0]), so `def c.e`
raises "can't define singleton (TypeError)" on CRuby; both the developer
patch (NULL-class guard) and the root-cause patch (no corruption, c == 0)
reach that same TypeError, which equals CRuby, so both are OK on the poc
case. The six reaching synthetic cases, where CRuby returns a value, are what
show the developer patch leaves wrong behaviour.

This file was written on 2026-10-13 during the root-cause analysis, after the
mechanism was read from the bytecode but before the before/after/root/assert
variant case logs were read; the synthetic case values were validated against
the image CRuby 2.7 beforehand (case_oracle).
"""

cols = ["dev:before", "dev:after",
        "ours:before", "ours:after", "ours:root",
        "ours:assert_before", "ours:assert_root"]
rows = []


def add(name, dev_b, dev_a, before, after, root, a_before, a_root):
    rows.append([name, dev_b, dev_a, before, after, root, a_before, a_root])


# Reaching forms: a `**` splat in a discarded hash/kw-hash literal makes
# gen_hash() emit stack ops with val == 0. Base and developer builds corrupt
# the stack (not OK); the root-cause patch is correct; the instrumentation
# fires STACK-INVARIANT on the base build and not after the fix. The developer
# model predicts nothing wrong here (OK), which the observations contradict.
for name in ("splat_pair", "pair_splat", "two_splat", "splat0_pair",
             "pair_splat_pair", "splat_pairs"):
    add(name, "OK", "OK", "WRONG", "WRONG", "OK", "INV", "OK")

# Controls that do not make gen_hash() emit a stack op with val == 0 (bare `**`
# with no following pair, or no splat at all): no corruption on any build, and
# the instrumentation never fires.
for name in ("bare_splat", "bare_splat0", "pair_only", "nohash"):
    add(name, "OK", "OK", "OK", "OK", "OK", "OK", "OK")

# Value-context controls: the same `**` forms with the value kept, so gen_hash
# runs with val == 1. The fix only adds `val &&` guards, so these paths are
# unchanged and correct on every build, and the `if (!val)` instrumentation is
# not taken (val == 1).
for name in ("val_arr_splat", "val_hash_splat"):
    add(name, "OK", "OK", "OK", "OK", "OK", "OK", "OK")

# The dataset PoC: base SEGV (ASAN); developer patch and root-cause patch both
# reach CRuby's "can't define singleton (TypeError)" (OK); the instrumentation
# fires STACK-INVARIANT at compile time on the base build (INV) and not after
# the fix (OK). The developer model predicts the crash and its repair.
add("poc", "ASAN", "OK", "ASAN", "OK", "OK", "INV", "OK")

# Columns added 2026-10-28 before the four variants below ran, to decide
# whether the defect left by the developer patch belongs to
# mruby.cve-2022-0326, whose CVE_NVD developers_patch is b611c43a5, one of the
# two upstream commits of the root-cause patch. Read from gen_hash() at
# 171d32c0, a discarded (val == 0) literal moves the stack pointer in three
# branches: K, the OP_HASH/OP_HASHADD flush of pending pairs before a `**`
# (-2*len+1, or -2*len after an update); C, the OP_HASHCAT after a `**` when
# pairs were pending or an update happened (-1); F, the final OP_HASHADD of
# pairs after an update (-2*len). b611c43a5 guards F only, ae3c99767 guards K
# and C. A reaching case is OK on a variant when every branch it takes is
# guarded and WRONG otherwise; the PoC line `[**0,m:0]` takes F only, so it
# is OK (CRuby's TypeError) wherever F is guarded or the developer guard is
# present, and ASAN otherwise. Controls take no branch.
#   cve0326_alone  base + scripts/nvalhash_cve0326.diff (b611c43a5)
#   ae_alone       base + scripts/nvalhash_ae3c99767.diff
#   dev_cve0326    developer patch + b611c43a5
#   dev_ae         developer patch + ae3c99767
BRANCHES = {"splat_pair": "F", "pair_splat": "KC", "two_splat": "C",
            "splat0_pair": "F", "pair_splat_pair": "KCF", "splat_pairs": "F",
            "poc": "F"}
EXTRA = [("cve0326_alone", "F", False), ("ae_alone", "KC", False),
         ("dev_cve0326", "F", True), ("dev_ae", "KC", True)]
for variant, guarded, dev in EXTRA:
    cols.append("ours:" + variant)
    for r in rows:
        taken = BRANCHES.get(r[0], "")
        if all(b in guarded for b in taken):
            r.append("OK")
        elif r[0] == "poc":
            r.append("OK" if dev else "ASAN")
        else:
            r.append("WRONG")

print("\t".join(["case"] + cols))
for r in rows:
    print("\t".join(r))
