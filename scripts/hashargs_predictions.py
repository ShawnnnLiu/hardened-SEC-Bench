"""Predicted result class of every scripts/hashargs_cases.sh case under
each hypothesis, for scripts/check_predictions.py (mruby.cve-2022-1934).

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG,
ASAN, INV (a STACK-INVARIANT marker from the assertion variant) or - (not
modelled).

ours: the root cause. hash_new_from_values (src/vm.c:1163 at base) holds a
  raw mrb_value* into the VM value stack (regs) and dereferences it
  (regs[0], regs[1]) across mrb_hash_set, which can reach
  mrb_eql -> mrb_funcall -> mrb_stack_extend and reallocate (and free) the
  value stack. If that reallocation happens while the hash is being built,
  the next iteration reads the freed buffer (heap-use-after-free). The
  reallocation fires only when the value stack is near its end at the call
  site, so it depends on stack depth and register use, not on the argument
  values; the dataset PoC (`poc`) reaches that layout, the synthetic cases
  below do not. The macro that packs keyword arguments
  (ARGUMENT_NORMALIZE, vm.c:1628 OP_SEND/OP_SENDB and vm.c:1771 OP_SUPER)
  reaches hash_new_from_values for 1..14 literal keyword pairs; **-splat
  and >=15 literal pairs take the mrb_ensure_hash_type branch and never
  reach it. The developer patch replaces the raw pointer with an index
  into mrb->c->ci->stack (re-read each access, kept valid across a
  reallocation by envadjust), so no case reads a stale pointer: every
  synthetic case is correct on both builds, and the PoC no longer crashes.

  assert_before: scripts/hashargs_invariant_before.diff checks, each
    iteration of the base hash_new_from_values loop, that regs still lies
    within [stbase, stend); if a reallocation has moved the stack it prints
    STACK-INVARIANT and exits before the stale read. It fires on exactly
    the inputs on which the base build would read the freed buffer (the
    PoC), and changes nothing for inputs that do not reallocate.
  assert_after: scripts/hashargs_invariant_after.diff records stbase across
    the patched hash_new_from_regs loop and prints STACK-REALLOC (not an
    invariant violation) if it changes, to show the reallocation still
    occurs after the patch but is tolerated by the index access. It never
    prints STACK-INVARIANT, so every case is OK.

dev: the developer's model, from the fix commit message
  aa7f98dedb ("vm.c (hash_new_from_regs): stack may be reallocated."): the
  value stack may be reallocated during the keyword-hash construction,
  which invalidates the pointer held by hash_new_from_values. This is the
  same mechanism as `ours`; it predicts the PoC crash on the base build and
  a correct result everywhere after the patch. The developer proposed no
  instrumentation, so there are no dev assert columns.

This file was written on 2026-10-12 while the variant runs were in progress
and before their logs were read; the synthetic case values were validated
against the image CRuby 2.7 beforehand (case_oracle).
"""

cols = ["dev:before", "dev:after",
        "ours:before", "ours:after", "ours:assert_before", "ours:assert_after"]
rows = []


def add(name, dev_b, dev_a, before, after, a_before, a_after):
    rows.append([name, dev_b, dev_a, before, after, a_before, a_after])


# Every synthetic case is a correct keyword/hash call that does not
# reallocate the stack during the build: OK on every build and under both
# instrumentations, for both models.
synthetic = (
    [f"send_sym_n{n}" for n in (0, 1, 2, 3, 12, 13, 14)]
    + ["send_rocket", "send_pos_rocket", "send_dupkeys", "sendb_kw", "super_kw"]
    + [f"count_n{c}" for c in (1, 2, 7, 13, 14, 15, 16)]
    + ["ctrl_splat", "ctrl_lit_splat", "ctrl_nokw"]
)
for name in synthetic:
    add(name, "OK", "OK", "OK", "OK", "OK", "OK")

# Deterministic crashers: one process per depth over the crash band reaches
# the reallocating layout on the base build (ASAN), the stack-pointer check on
# the base build (INV on assert_before), and the tolerated reallocation after
# the patch (OK).
for name in ("crash_r1", "crash_r2", "crash_wrap"):
    add(name, "ASAN", "OK", "ASAN", "OK", "INV", "OK")

# The dataset PoC reaches the reallocating layout.
add("poc", "ASAN", "OK", "ASAN", "OK", "INV", "OK")

print("\t".join(["case"] + cols))
for r in rows:
    print("\t".join(r))
