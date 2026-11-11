"""Predicted result class of every scripts/hashcat_cases.sh case under each
hypothesis, for scripts/check_predictions.py (mruby.cve-2022-0630).

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG,
ASAN, INV (a HASHCAT-INVARIANT marker from the assertion variant) or - (not
modelled by that model).

Variants (columns):
  before            base commit ecb28f4b, no patch.
  after             base + developer patch (OP_HASHCAT: mrb_ensure_hash_type on
                    regs[a] before mrb_hash_merge).
  assert_before     base + HASHCAT instrumentation (raise if !mrb_hash_p(regs[a])
                    at OP_HASHCAT, before the compiled-out assert).
  assert_after      base + developer patch + the instrumentation, placed after
                    the patch's mrb_ensure_hash_type (which raises first).
  gold              base + the SEC-bench gold patch (hash.c hash_modify skips
                    mrb_check_frozen for a non-hash); the opcode asserts stay
                    compiled out.
  cve0614_alone     base + the mruby.cve-2022-0614 developer patch (OP_HASHADD
                    type check only).
  dev_cve0614       base + the 0630 and 0614 developer patches.
  up12d518_alone    base + upstream 12d51807a (gen_hash emits an empty OP_HASH
                    accumulator before the first double-splat).
  dev_up12d518      base + the 0630 developer patch + 12d51807a.

ours: the root cause is in gen_hash (mrbgems/mruby-compiler/core/codegen.c). A
  literal whose first element is a double-splat (NODE_KW_REST_ARGS) gets no
  OP_HASH; gen_hash reuses the splat operand's own register as the accumulator.

  H1 (narrow invariant, the reported crash): at OP_HASHCAT the accumulator
    regs[a] must be a hash. A literal with two leading splats whose first
    operand is a non-hash ([**0, **8], the PoC) makes the first OP_HASHCAT run
    on that non-hash operand; mrb_hash_merge calls hash_modify(regs[a]) first,
    which faults on the non-hash (ASAN). The developer patch inserts
    mrb_ensure_hash_type(regs[a]) before mrb_hash_merge, so these raise
    TypeError (OK after). The instrumentation fires on exactly these on the
    base build (INV at assert_before) and never after the patch (assert_after
    the patch's ensure raises first).

  H2 (ASan observability of H1, same family as mruby.cve-2022-0614/0631): an
    immediate non-hash accumulator (Integer 0, nil) gives a bad object pointer,
    so hash_modify -> mrb_check_frozen faults (ASAN at a small address). A
    heap-object accumulator (String) passes the frozen check, so the fault, if
    any, is the later table read when mrb_hash_merge writes the merge source's
    entries into mrb_hash_ptr(regs[a]); the String case is predicted ASAN and
    revised from the observation if it differs. The instrumentation
    (mrb_hash_p before the merge) is the storage-class-independent oracle for
    "reaches the faulty state".

  H3 (wide invariant, the leftover): gen_hash must give every literal a fresh
    accumulator, not the first splat operand's register. When the first splat
    operand is a hash variable, the accumulator ALIASES it, so {**h, **{b:2}}
    mutates h via OP_HASHCAT and {**h, b:2} mutates h via OP_HASHADD (a wrong
    result compared with CRuby 2.7, which leaves h unchanged; kalias,
    kaliasarr, kafroz, kpalias). A single leading splat {**nil} leaves the
    operand itself as the literal's value instead of raising (k1nil). The
    OP_HASHCAT type check (developer patch), the OP_HASHADD type check (0614)
    and the hash_modify guard (gold) are all local to the access and do NOT
    change which register gen_hash uses, so the aliasing and the single-splat
    wrong results remain on after, assert_after, gold, cve0614_alone and
    dev_cve0614. Upstream 12d51807a changes gen_hash (a fresh empty OP_HASH
    accumulator), so it repairs the crash, the aliasing and the single-splat
    value (OK on up12d518_alone and dev_up12d518).

  The OP_HASHADD non-hash crashers (hint, hfloat, hsym, hint_arr, hstr; the
  kept mruby.cve-2022-0614/0623 rows) reach a non-hash at OP_HASHADD, a
  different opcode the 0630 developer patch does not touch, so they stay ASAN
  on after, assert_before, assert_after and gold; the 0614 developer patch
  (cve0614_alone) and 12d51807a repair them. On assert_before they are ASAN not
  INV, because the HASHCAT instrumentation does not cover OP_HASHADD.

dev: the developer's model is the shipped patch's intent, a runtime type check
  of the OP_HASHCAT accumulator (commit subject of ee06bbb4, whose OP_HASHCAT
  hunk is the CVE_NVD developers_patch: "vm.c: replace type assertions with
  runtime checks"). It predicts the OP_HASHCAT non-hash crashers repaired
  (ASAN before, OK after). For a literal whose first splat operand is a hash
  (kalias, kaliasarr, kafroz) the check passes, so the dev model predicts no
  failure (OK) on both builds; the observed aliasing wrong result contradicts
  it, and these are the dev_model contradictions. The dev model makes no
  prediction (-) for the OP_HASHADD crashers and aliasing (kp) and the single
  leading splat (k1nil), which the OP_HASHCAT patch does not govern.

Cases outside both models are marked -.

This file was written on 2026-11-07 during the root-cause analysis, after the
mechanism was read from the source (vm.c OP_HASH/OP_HASHADD/OP_HASHCAT, hash.c
hash_modify/mrb_hash_merge, codegen.c gen_hash) and after the CRuby 2.7 oracle
run that set scripts/hashcat_expected.tsv, but before any before/after/assert/
gold/cve0614/up12d518 variant case log of this case set was read. The
mruby.cve-2022-0614 and 0623 records were read before this file was written
(they share the base and the gen_hash defect). The step-3 poc_before.log (base,
a SEGV in mrb_check_frozen from mrb_hash_merge at OP_HASHCAT) and the step-4
poc_after.log (TypeError "Integer cannot be converted to Hash", no sanitizer
report) were known when it was written.
"""

cols = ["dev:before", "dev:after",
        "ours:before", "ours:after",
        "ours:assert_before", "ours:assert_after",
        "ours:gold",
        "ours:cve0614_alone", "ours:dev_cve0614",
        "ours:up12d518_alone", "ours:dev_up12d518"]
rows = []


def add(name, vals):
    assert len(vals) == len(cols), (name, len(vals))
    rows.append([name] + vals)


# OP_HASHADD non-hash crashers (kept 0614/0623 rows). Cross-CVE leftover: still
# ASAN after the 0630 patch; fixed by the 0614 patch and by 12d51807a. On
# assert_before they are ASAN (the HASHCAT instrumentation does not cover
# OP_HASHADD). dev = - (the OP_HASHCAT patch does not model OP_HASHADD).
#        dev:b dev:a  o:bef o:aft a:bef a:aft gold  c614a dc614 u12a  du12
for n in ("hint", "hfloat", "hsym", "hint_arr", "hstr"):
    add(n, ["-", "-", "ASAN", "ASAN", "ASAN", "ASAN", "ASAN", "OK", "OK", "OK", "OK"])

# Boundaries: a trailing splat -> OP_HASHCAT with a real-hash accumulator
# (TypeError on the non-hash source, no crash); {**0} alone has no second op.
# No crash and no marker on any build.
for n in ("hcat", "hsplat"):
    add(n, ["OK", "OK", "OK", "OK", "OK", "OK", "OK", "OK", "OK", "OK", "OK"])

# Value controls: a real hash at OP_HASHADD / OP_HASH; the checked value is
# preserved on every build.
for n in ("cvalid", "ckw", "cmerge", "cplain"):
    add(n, ["OK", "OK", "OK", "OK", "OK", "OK", "OK", "OK", "OK", "OK", "OK"])

# OP_HASHCAT non-hash accumulator crashers with a NON-HASH second operand
# (kc2int, kc23) and the PoC: gold repairs them (hash_modify no-op then the
# merge-source type check mrb_ensure_hash_type(hash2) raises).
for n in ("kc2int", "kc23", "poc"):
    add(n, ["ASAN", "OK", "ASAN", "OK", "INV", "OK", "OK", "ASAN", "OK", "OK", "OK"])

# OP_HASHCAT non-hash accumulator crashers with a HASH second operand: gold
# does NOT repair them (hash_modify no-op, the merge source passes the type
# check, then h_set writes into mrb_hash_ptr(non-hash) -> ASAN). kc2str is the
# heap-object accumulator (H2).
for n in ("kc2hash", "kc2nil", "kc2str", "kc2call"):
    add(n, ["ASAN", "OK", "ASAN", "OK", "INV", "OK", "ASAN", "ASAN", "OK", "OK", "OK"])

# OP_HASHCAT aliasing (hash first operand): a wrong result that passes the
# developer's type check; remains on after/assert_after/gold/cve0614; fixed by
# 12d51807a. dev predicts OK and is contradicted (the dev_model finding).
for n in ("kalias", "kaliasarr", "kafroz"):
    add(n, ["OK", "OK", "WRONG", "WRONG", "WRONG", "WRONG", "WRONG", "WRONG", "WRONG", "OK", "OK"])

# Single leading non-hash splat (k1nil) and OP_HASHADD aliasing (kpalias):
# wrong results outside the OP_HASHCAT accumulator path (dev = -); fixed only by
# 12d51807a.
for n in ("k1nil", "kpalias"):
    add(n, ["-", "-", "WRONG", "WRONG", "WRONG", "WRONG", "WRONG", "WRONG", "WRONG", "OK", "OK"])

# Controls that stay correct everywhere (a pair precedes the splat, so OP_HASH
# builds a fresh accumulator; Hash#merge does not alias).
for n in ("kcpair", "kmerge"):
    add(n, ["OK", "OK", "OK", "OK", "OK", "OK", "OK", "OK", "OK", "OK", "OK"])

print("\t".join(["case"] + cols))
for r in rows:
    print("\t".join(r))
