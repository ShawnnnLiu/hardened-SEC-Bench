"""Predicted result class of every scripts/sendempty_cases.sh case under each
hypothesis, for scripts/check_predictions.py (mruby.cve-2022-0570).

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG,
ASAN, INV (a SEND-INVARIANT marker from the assertion variant) or - (not
modelled).

ours: the root cause is in mrb_f_send (src/vm.c, base 0ed3fcf; mrb_f_send is
  identical to the mruby.cve-2022-0631 base 1e314242, both at line 672, the
  read at vm.c:695). A packed call (ci->n == CALL_MAXARGS == 15) reads the
  first element of the packed array regs[0] as the method-name symbol,
  RARRAY_PTR(regs[0])[0] (vm.c:695), without checking the array is non-empty.
  An empty packed array makes that a heap read 8 bytes past the array buffer
  (the dataset heap-buffer-overflow, this instance's report allocating through
  ary_subseq / ary_make_shared). Invariant: in the n == 15 branch the packed
  array regs[0] must have length >= 1 before RARRAY_PTR(regs[0])[0] is read.
  This is the same defect, invariant and developer patch as
  mruby.cve-2022-0631 (the developer patches are byte-identical).

  Inputs that reach the empty-array read:
    splat_empty, dunder_empty : send/__send__(*[]), n == 15 with [] directly.
    recurse1                  : send(*[:send]), one-element subseq to empty.
    crash16, chain15/17/20     : send chains of 16/15/17/20 "send" strings; the
                                re-dispatch (regs[0] = ary_subseq(regs[0], 1,
                                len-1), re-enter send with ci->n == 15) empties
                                the array after as many steps as its length.
    dunder15/16/17/20          : the same through the __send__ alias.
    shared_subseq              : send(*a[1..]) where a has 20 "send"; a[1..] is
                                a shared subsequence, emptied by re-dispatch.
    poc                        : the dataset PoC, 16 "send" strings (crash16
                                form).
  All reach the n == 15 empty-array read (the invariant violation), which the
  assertion variant observes directly: assert_before fires SEND-INVARIANT on
  all of them. All are OK (ArgumentError) after the developer patch, and
  assert_after fires on none.

  H3 observability (known from mruby.cve-2022-0631, revision of 2026-10-28):
  the UNINSTRUMENTED AddressSanitizer reports the out-of-bounds slot-0 read
  only when the empty array's buffer lies in a poisoned region. The chains
  (crash16, chain15/17/20, dunder15/16/17/20, shared_subseq, poc) build their
  empty array by ary_subseq shrinking a >= 15-element heap array (a shared
  buffer advanced to one past the end), so the slot-0 read lands on a heap
  redzone -> ASAN on the base build. The direct and one-element empties
  (splat_empty, dunder_empty, recurse1) reach the same read on an addressable
  (embedded, zero-initialized) slot, so the base build is ASan-silent (OK)
  though the invariant is violated (assert_before INV confirms it). The sound,
  layout-independent test of the invariant is the assertion variant, not the
  uninstrumented PoC; a before-column ASAN/OK that differs from this prediction
  is a heap-observability refinement, not an invariant failure. The ASAN
  predictions for the new chains follow the 0631 shrunk-heap-buffer model and
  were not observed before this file was written.

  Non-crashers:
    send_sym   send(:send)            : n == 1 (not packed); re-dispatch send
                                        with n == 0 -> ArgumentError. No INV.
    send_undef send(*[:no_such...])   : n == 15 non-empty; element read validly;
                                        NoMethodError. No INV.
    ctrl_str   "abc".send(:upcase)    : n == 1 path, value "ABC".
    ctrl_splat1 [3,1,2].send(*[:sort]): n == 15 non-empty [:sort]; value [1,2,3].
    ctrl_splat2 "hello".send(*[:ljust,7]): n == 15 non-empty; value "hello  ".
    ctrl_chain  14 "send" then "upcase": n == 15, re-dispatches without ever
                                        emptying (ends at upcase with 1 element
                                        left); value "ABC". No INV.
  These keep their value/behaviour on every build, and the assertion check
  never fires (their packed array is non-empty, or they never enter n == 15).

  assert_before: scripts/sendpack_invariant.diff (reused, it applies at 0ed3fcf)
    inserts before the n == 15 read a check that prints SEND-INVARIANT and
    raises mrb_argnum_error when RARRAY_LEN(regs[0]) == 0; it fires on exactly
    the empty-array inputs on the base build.
  assert_after: the same instrumentation on the developer-patched handler, where
    the patch's own `if (RARRAY_LEN(regs[0]) == 0) goto argnum_error;` runs
    before the inserted check, so the marker never prints and every case is OK.

dev: the developer's model, from the fix commit message 47068ae07 ("vm.c:
  packed arguments length may be zero for `send` method."). It names the packed
  (n == 15) argument array of send as possibly empty, the invariant above;
  applied as the fix it predicts the empty-array inputs repaired (OK after) and,
  where observable, crashing on the base (ASAN before). The developer patch
  realizes it fully, so dev:before and dev:after match the observation.

Crasher and boundary cases raise exceptions on CRuby, so their OK class means
only "no sanitizer report"; the value controls (ctrl_*) carry the wrong-result
class, compared with the image CRuby 2.7 reference.

This file was written on 2026-11-07 during the root-cause analysis, after the
mechanism was confirmed (mrb_f_send identical at 0ed3fcf and the 0631 base, the
developer patch byte-identical) but before the before/after/assert variant case
logs of this instance were read. The step-3 poc_before.log (base,
heap-buffer-overflow at vm.c:695) and step-4 poc_after.log were known when it
was written and fix the poc row (ASAN before, OK after).
"""

cols = ["dev:before", "dev:after",
        "ours:before", "ours:after",
        "ours:assert_before", "ours:assert_after"]
rows = []


def add(name, dev_b, dev_a, before, after, a_before, a_after):
    rows.append([name, dev_b, dev_a, before, after, a_before, a_after])


# Empty-array inputs reached by shrinking a >= 15-element heap array: ASAN on
# the base (H3 shrunk-heap-buffer), fixed by the developer patch, assert_before
# INV.
for name in ("crash16", "chain15", "chain17", "chain20",
             "dunder15", "dunder16", "dunder17", "dunder20",
             "shared_subseq", "poc"):
    add(name, "ASAN", "OK", "ASAN", "OK", "INV", "OK")

# Direct and one-element empties: ASan-silent on the base (addressable slot),
# invariant still violated (assert_before INV).
for name in ("splat_empty", "dunder_empty", "recurse1"):
    add(name, "OK", "OK", "OK", "OK", "INV", "OK")

# Boundary: n != 15 path, or a non-empty packed array read validly.
for name in ("send_sym", "send_undef"):
    add(name, "OK", "OK", "OK", "OK", "OK", "OK")

# Value controls: a non-empty packed array through the n == 15 branch (or the
# n == 1 path), then a real method; must keep their CRuby value.
for name in ("ctrl_str", "ctrl_splat1", "ctrl_splat2", "ctrl_chain"):
    add(name, "OK", "OK", "OK", "OK", "OK", "OK")

print("\t".join(["case"] + cols))
for r in rows:
    print("\t".join(r))
