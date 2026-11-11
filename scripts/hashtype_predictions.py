"""Predicted result class of every scripts/hashtype_cases.sh case under each
hypothesis, for scripts/check_predictions.py (mruby.cve-2022-0614 and
mruby.cve-2022-0623; one shared developer patch ff3a5ebed).

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG,
ASAN, INV (a HASHADD-INVARIANT marker from the assertion variant) or - (not
modelled).

ours: the root cause is in the OP_HASHADD handler of mrb_vm_exec (src/vm.c).
  It reads hash = regs[a] and, in the release build where mrb_assert is compiled
  out, calls mrb_hash_set(mrb, hash, ...) without checking that regs[a] is a
  hash. The compiler puts a non-hash into regs[a] for a hash or array literal
  whose first entry is a double-splat of a non-hash and which has at least one
  further pair: {**x, k:v} compiles to (load x into R) ; HASHADD R, so R holds x.
  When x is not a hash, mrb_hash_set operates on the non-hash: hash_modify ->
  mrb_check_frozen reads the object header of a bad pointer, or the hash-table
  path reads the object's fields as a table.
  Invariant: at OP_HASHADD, regs[a] must be a hash.

  H1 (entry): {**x, k:v} and [**x, k:v] with a non-hash x reach OP_HASHADD with
    regs[a] == x. A trailing splat {k:v, **x} compiles to OP_HASHCAT instead,
    whose accumulator regs[a] is a real hash, and the non-hash merge source is
    type-checked by mrb_hash_merge (TypeError, no crash); {**x} alone with no
    further pair does not reach OP_HASHADD with the non-hash.

  H2 (ASan observability, same family as mruby.cve-2022-1934/0631): the
    uninstrumented base reports a sanitizer error when the non-hash read faults
    on a bad pointer. An immediate non-hash (Integer, Float, Symbol) gives a
    bad object pointer, so mrb_check_frozen faults (SEGV at a small address) and
    the sanitizer reports. A heap-object non-hash (String) has a valid object
    header, so mrb_check_frozen passes and the fault, if any, is later in the
    table path; the base-build class of the String case is predicted ASAN here
    and revised from the observation if it differs. The invariant instrumentation
    (a mrb_hash_p check before the OP_HASHADD loop) fires on every non-hash
    regardless of storage class and is the sound oracle for "reaches the faulty
    state".

  The developer patch replaces the assert with mrb_ensure_hash_type(mrb, hash),
  which raises TypeError before mrb_hash_set, so no non-hash reaches the loop;
  all crashers become a controlled TypeError (OK after), and the assertion
  instrumentation fires on no case after the patch (its check is preceded by the
  patch's own ensure, which raises first).

dev: the developer's model, from the fix commit subject ff3a5ebed ("vm.c: should
  check type before hash access."). It names the missing type check before the
  hash access, which is the invariant above; applied as the fix it predicts the
  crashers repaired (OK after) and the base faults (ASAN before). The developer
  patch realizes it fully, so dev:before and dev:after match the observation.

Crasher and boundary cases raise exceptions on CRuby (CRuby 2.7 raises TypeError
for {**0, m:0}: no implicit conversion of Integer into Hash), so their OK class
means only "no sanitizer report, a controlled Ruby exception"; the value
controls (cvalid, ckw, cmerge, cplain) carry the wrong-result class, compared
with the CRuby 2.7 reference by hash lookups and size (format-independent).

This file was written on 2026-10-28 during the root-cause analysis, after the
mechanism was read from the source and the bytecode of {**0, m:0} but before the
before/after/assert variant case logs of this case set were read. The step-3
poc_before.log (base, a SEGV in the mrb_hash_set path from OP_HASHADD) and the
step-4 poc_after.log (TypeError "Integer cannot be converted to Hash", no
sanitizer report) were known when it was written.

Columns ours:root, ours:assert_root and ours:up12d518_alone were added on
2026-11-10, before those variants ran on either instance.
  root is patches/<instance>.root.diff: the developer patch plus the backport of
  upstream 12d51807a ("Insert an empty hash before the first
  NODE_KW_REST_ARGS"), which makes gen_hash emit an empty OP_HASH before a
  leading double-splat, so the splat operand is merged into a fresh accumulator
  with OP_HASHCAT and is never regs[a] of OP_HASHADD.
  H3 (root): with a fresh accumulator, a non-hash operand is the merge source of
    OP_HASHCAT, which mrb_hash_merge type-checks (TypeError, no sanitizer
    report), and OP_HASHADD always receives a real hash, so every case is OK and
    the OP_HASHADD instrumentation fires on none (assert_root OK).
  H4 (up12d518_alone, the upstream change without the developer patch): the
    same code generation applies, so no non-hash reaches OP_HASHADD although
    its handler keeps the compiled-out assert; every case is predicted OK.
  The aliasing cases (scripts/hashtype_alias_cases.sh, three cases, written to
  variants/<variant>.residual.log and not read by scripts/check_predictions.py)
  are predicted 3 OK, 0 WRONG on root and on up12d518_alone, because the source
  hash is no longer the accumulator.
  Known when these columns were written: the before, after, assert_before and
  assert_after logs of both instances, and the mruby.cve-2022-0630 record, in
  which the same upstream change on base ecb28f4b (the base of
  mruby.cve-2022-0614) gave 25 of 25 cases OK, including these twelve rows
  (logs/mruby.cve-2022-0630/variants/up12d518_alone.cases.log and
  root.cases.log). No build of the mruby.cve-2022-0623 tree (9037e447) with
  the upstream change had been run.
"""

cols = ["dev:before", "dev:after",
        "ours:before", "ours:after",
        "ours:assert_before", "ours:assert_after",
        "ours:root", "ours:assert_root", "ours:up12d518_alone"]
rows = []


def add(name, dev_b, dev_a, before, after, a_before, a_after):
    # H3 and H4: every case is OK on root, assert_root and up12d518_alone.
    rows.append([name, dev_b, dev_a, before, after, a_before, a_after,
                 "OK", "OK", "OK"])


# OP_HASHADD non-hash crashers: reach the faulty state (assert_before INV), all
# fixed by the developer patch. Base build ASAN for the immediate splats and the
# PoC; the String case is predicted ASAN and revised from the observation if it
# differs (H2).
for name in ("hint", "hfloat", "hsym", "hint_arr", "hstr", "poc"):
    add(name, "ASAN", "OK", "ASAN", "OK", "INV", "OK")

# Boundary: a trailing splat goes through OP_HASHCAT (accumulator is a real hash;
# the non-hash merge raises TypeError, no crash, no OP_HASHADD on a non-hash);
# {**0} alone does not reach OP_HASHADD with the non-hash. OK on every build, and
# the OP_HASHADD instrumentation never fires on them.
for name in ("hcat", "hsplat"):
    add(name, "OK", "OK", "OK", "OK", "OK", "OK")

# Value controls: regs[a] is a real hash at OP_HASHADD; must keep the value.
for name in ("cvalid", "ckw", "cmerge", "cplain"):
    add(name, "OK", "OK", "OK", "OK", "OK", "OK")

print("\t".join(["case"] + cols))
for r in rows:
    print("\t".join(r))
