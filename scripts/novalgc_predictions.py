"""Predicted result class of every scripts/novalgc_cases.sh case under each
hypothesis, for scripts/check_predictions.py (mruby.cve-2022-0326).

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG,
ASAN, INV (a STACK-INVARIANT marker from the assertion variant, printed at
compile time) or - (not modelled: the invariant predicts the faulty state is
reached, which the assert columns test, but the base consequence class is
layout dependent and not predicted).

ours: the root cause is in gen_hash()
  (mrbgems/mruby-compiler/core/codegen.c). When the hash value is discarded
  (val == 0, NOVAL) the function moves the compiler stack pointer in three
  branches, each with a `**` splat (NODE_KW_REST_ARGS) present:
    K  the OP_HASH/OP_HASHADD flush of pending pairs before a `**` (L1606),
    C  the OP_HASHCAT after a `**` when pairs were pending or an update
       happened (L1618),
    F  the final OP_HASHADD of pairs after an update (L1647).
  Those pop/push move the stack pointer although nothing was pushed for the
  discarded value, so every following instruction is emitted one or two
  registers too low and overwrites locals and temporaries. The invariant: a
  gen_hash() call with val == 0 must not change the compiler stack pointer.
  The symptom is layout dependent (wrong value, runtime TypeError from
  OP_HASHADD on a non-hash register, compile-time "stack pointer underflow",
  or a SEGV; the dataset PoC reaches the SEGV at exit-time GC in iv_free).
  The branch each case takes was read from gen_hash() at adb16fc6:
    F only:   splat_pair, splat0_pair (PoC form), splat_pairs,
              all sp_* surroundings, poc0240, poc
    K and C:  pair_splat, kc_ps_blk2
    C only:   two_splat, kc_ts_blk2
    K, C, F:  pair_splat_pair, kc_psp_blk2
    none:     bare_splat, bare_splat0, pair_only, nohash, val_* (controls)

  The developer patch (b611c43a5) adds `val &&` to F only, so after it the F
  forms are correct and the K/C forms stay wrong. The upstream commit
  ae3c99767 adds `val &&` to K and C. Variants:
    before        base adb16fc6, all three branches unguarded
    after         base + developer patch b611c43a5 (F guarded)
    assert_before base + nvalhash_invariant_before.diff: codegen_error
                  "STACK-INVARIANT" at the top of K, C and F when !val; fires
                  (INV) on any form that reaches K, C or F with val == 0.
    assert_after  developer patch + novalgc_invariant_after.diff: the same
                  check at the top of the still-unguarded K and C, and inside
                  the now val-guarded F (unreachable for val == 0); fires (INV)
                  on exactly the forms that still reach K or C after the patch.
    ae_alone      base + nvalhash_ae3c99767.diff (K and C guarded, F not)
    dev_ae        developer patch + ae3c99767 (all three guarded): correct.
  A reaching case is OK on a variant when every branch it takes is guarded
  there, WRONG/ASAN otherwise; the base consequence (WRONG vs ASAN) is layout
  dependent, so it is predicted (WRONG) only for the run_case synthetic forms
  whose wrapper layout gives a wrong sentinel (as mruby.cve-2022-0240
  established, 13/13), ASAN for the dataset PoC, and left `-` for the
  surroundings and the K/C crash-layout probes, where the invariant prediction
  is the assert column.

dev: the developer's model, from the fix commit message b611c43a5
  ("codegen.c: no `OP_HASHADD` required when `val` is false."). This names the
  final OP_HASHADD branch (F): for a discarded value F emits a spurious op.
  The model covers F; it is silent on the K and C branches. So it predicts the
  F forms are miscompiled on the base (WRONG, ASAN for the PoC) and that the
  patch completes the repair (after: OK for every form). It predicts OK on the
  base for the K/C-only forms (it does not model them). The observations it
  does not predict are the K/C leftover: wrong on the base for the K/C-only
  forms, and wrong after the patch for every form that reaches K or C.

Relation to mruby.cve-2022-0240: the base adb16fc6 already contains the 0240
developer fix (31fa3304, the class.c NULL-class guard), so poc0240 (the 0240
PoC) raises "can't define singleton (TypeError)" (= CRuby) on this base
instead of the 0240 SEGV, demonstrating the 0240 fix is in this tree. The
developer patch of this instance, b611c43a5, is the first of the two upstream
commits of the 0240 root-cause patch; the second, ae3c99767, is modelled by
the ae_alone and dev_ae columns.

This file was written on 2026-11-07 during the root-cause analysis, after the
mechanism was read from gen_hash() at adb16fc6 and the CRuby expected values
were validated (25 OK of 25 synthetic cases), but before the before, after,
assert_before, assert_after, ae_alone and dev_ae variant case logs were read.
The K/C leftover classes were derived from the invariant (which branch each
form takes, guarded or not), not from the 0240 case logs.
"""

cols = ["dev:before", "dev:after",
        "ours:before", "ours:after",
        "ours:assert_before", "ours:assert_after",
        "ours:ae_alone", "ours:dev_ae"]
rows = []


def add(name, devb, deva, before, after, ab, aa, ae, dae):
    rows.append([name, devb, deva, before, after, ab, aa, ae, dae])


# --- reaching forms, run_case wrapper (precise classes; wrapper layout gives a
#     wrong sentinel on the base, as mruby.cve-2022-0240 established). ---
# F only: fixed by the developer patch.
add("splat_pair",      "WRONG", "OK", "WRONG", "OK",    "INV", "OK",  "WRONG", "OK")
add("splat0_pair",     "WRONG", "OK", "WRONG", "OK",    "INV", "OK",  "WRONG", "OK")
add("splat_pairs",     "WRONG", "OK", "WRONG", "OK",    "INV", "OK",  "WRONG", "OK")
# K and C / C only: left by the developer patch, fixed by ae3c99767.
add("pair_splat",      "OK",    "OK", "WRONG", "WRONG", "INV", "INV", "OK",    "OK")
add("two_splat",       "OK",    "OK", "WRONG", "WRONG", "INV", "INV", "OK",    "OK")
# K, C, F: F fixed by the developer patch but K/C remain, so still wrong after.
add("pair_splat_pair", "WRONG", "OK", "WRONG", "WRONG", "INV", "INV", "WRONG", "OK")

# --- controls: take no stack-moving branch, correct on every build. ---
for n in ("bare_splat", "bare_splat0", "pair_only", "nohash"):
    add(n, "OK", "OK", "OK", "OK", "OK", "OK", "OK", "OK")

# --- value-context controls: val == 1, the `val &&` guards and the `if (!val)`
#     instrumentation do not change these paths. ---
for n in ("val_arr_splat", "val_hash_splat"):
    add(n, "OK", "OK", "OK", "OK", "OK", "OK", "OK", "OK")

# --- splat0_pair (F form) in the PoC surroundings: fixed by the developer
#     patch in every layout (after OK, assert_after OK, dev_ae OK); the base
#     consequence is layout dependent (`-`), the invariant prediction is
#     assert_before INV. ae_alone leaves F unguarded (`-`). ---
for n in ("sp_top", "sp_top_gc", "sp_blk1", "sp_blk1_gc", "sp_blk2",
          "sp_blk2_gc", "sp_loop", "sp_loop_gc", "sp_str", "sp_str_gc"):
    add(n, "-", "OK", "-", "OK", "INV", "OK", "-", "OK")

# --- K/C leftover forms in the crash-prone layout: the developer patch does
#     not fix them (assert_after INV: they still reach K or C with val == 0),
#     ae3c99767 and dev_ae do. Base/after consequence layout dependent (`-`).
#     kc_psp also takes F, so ae_alone (F unguarded) leaves it `-`. The dev
#     model predicts OK (it does not cover K/C): mismatches on after. ---
add("kc_ps_blk2",  "OK", "OK", "-", "-", "INV", "INV", "OK", "OK")
add("kc_ts_blk2",  "OK", "OK", "-", "-", "INV", "INV", "OK", "OK")
add("kc_psp_blk2", "-",  "OK", "-", "-", "INV", "INV", "-",  "OK")

# --- poc0240: the 0240 PoC on this base. The class.c guard (present at
#     adb16fc6) turns the 0240 SEGV into "can't define singleton (TypeError)"
#     (= CRuby, OK) on base and after. It is an F form, so assert_before fires
#     (INV, compile error) and assert_after does not (F guarded). ae_alone
#     leaves F unguarded but the class.c guard still yields the TypeError (OK). ---
add("poc0240", "-", "OK", "OK", "OK", "INV", "OK", "OK", "OK")

# --- the dataset PoC (F form). Base ASAN (iv_free at exit-time GC); clean
#     (OK) after the developer patch; assert_before INV (compile error);
#     assert_after OK (F guarded, no K/C taken); ae_alone ASAN (F unguarded);
#     dev_ae OK. The dev model predicts the crash and its repair. ---
add("poc", "ASAN", "OK", "ASAN", "OK", "INV", "OK", "ASAN", "OK")

print("\t".join(["case"] + cols))
for r in rows:
    print("\t".join(r))
