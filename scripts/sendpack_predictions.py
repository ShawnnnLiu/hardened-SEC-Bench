"""Predicted result class of every scripts/sendpack_cases.sh case under each
hypothesis, for scripts/check_predictions.py (mruby.cve-2022-0631).

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG,
ASAN, INV (a SEND-INVARIANT marker from the assertion variant) or - (not
modelled).

ours: the root cause is in mrb_f_send (src/vm.c, base 1e314242). A packed call
  (ci->n == CALL_MAXARGS == 15) reads the first element of the packed array
  regs[0] as the method-name symbol, RARRAY_PTR(regs[0])[0] (base src/vm.c:695),
  without checking that the array is non-empty. An empty packed array makes that
  a heap read 8 bytes past the array buffer (the dataset heap-buffer-overflow).
  Invariant: in the n == 15 branch the packed array regs[0] must have length
  >= 1 before RARRAY_PTR(regs[0])[0] is read.

  H1 (entry): any splat call emits a packed OP_SEND (the compiler cannot know
    the runtime array length), so send(*x) reaches mrb_f_send with n == 15 and
    regs[0] == x for any x including []. And >= 15 positional arguments pack
    likewise.
  H2 (re-dispatch): in the n == 15 branch, after reading the name, mrb_f_send
    sets regs[0] = mrb_ary_subseq(regs[0], 1, len-1) and re-enters send while
    ci->n stays 15, so the array shrinks by one per re-dispatch and reaches
    length 0 after as many send re-dispatches as its initial length.

  Under H1 and H2 the inputs that reach the empty-array read are:
    splat_empty  send(*[])            : H1, n == 15 with [] directly.
    dunder_empty __send__(*[])        : same through the __send__ alias.
    recurse1     send(*[:send])       : H1 packs [:send]; name :send; subarray
                                        []; H2 re-dispatch send with [] -> OOB.
    crash16      send "send" x16       : >= 15 positional -> n == 15; H2, 16
                                        re-dispatches empty the array.
    poc          /testcase/poc_decoded: 15 "send" strings, same family.
  All five reach the n == 15 empty-array read (the invariant violation), which
  the assertion variant observes directly: assert_before fires SEND-INVARIANT
  on all five. All five are OK (ArgumentError "wrong number of arguments
  (given 0, expected 1+)") after the developer patch, and assert_after fires on
  none.

  H3 (revision 2026-10-28, after the run; original pre-registered TSV kept at
  logs/mruby.cve-2022-0631/predictions_run1.tsv, checked in predictions_run1.log):
  the UNINSTRUMENTED AddressSanitizer reports the out-of-bounds read
  RARRAY_PTR(regs[0])[0] only when slot 0 of the empty array's data buffer lies
  in a poisoned region. crash16 and the PoC build their empty array by
  mrb_ary_subseq shrinking a >= 15-element heap array, whose slot-0 read on the
  empty result lands on a heap redzone -> ASAN on the base build. splat_empty
  and dunder_empty (an empty [] literal) and recurse1 (a one-element subseq to
  empty) reach the same read on an array buffer whose slot 0 is addressable, so
  the base build gives no sanitizer report (OK) although the invariant is
  violated (assert_before INV confirms it). The pre-registered TSV predicted
  ASAN for all five on the base; the observation refined the base-build
  observability, not the invariant. This is the mruby.cve-2022-1934 lesson
  (ASan observability of an OOB access is heap-layout dependent, so the
  assertion variant, not the uninstrumented PoC, is the test of the invariant).
  So: before/dev:before ASAN for crash16 and poc, OK for splat_empty,
  dunder_empty and recurse1; assert_before INV for all five.

  Non-crashers:
    send_sym     send(:send)          : one literal arg -> n == 1 (not packed);
                                        else branch shifts, ci->n--, re-dispatch
                                        send with n == 0 -> ArgumentError. OK on
                                        every build (the n != 15 path).
    send_undef   send(*[:no_such...]) : n == 15, non-empty; first element read
                                        validly; method undefined -> funcall ->
                                        method_missing -> NoMethodError. OK.
    ctrl_str     "abc".send(:upcase)  : n == 1 path, value "ABC".
    ctrl_splat1  [3,1,2].send(*[:sort]): n == 15 non-empty [:sort]; name :sort;
                                        subarray []; re-dispatch sort (not send)
                                        with [] -> [1, 2, 3]. Exercises the
                                        n == 15 branch and the subseq-to-empty
                                        re-dispatch to a non-send method.
    ctrl_splat2  "hello".send(*[:ljust,7]): n == 15 non-empty; "hello  ".
  These keep their value/behaviour on every build.

  assert_before: scripts/sendpack_invariant.diff inserts, before the n == 15
    read, a check that prints SEND-INVARIANT and raises mrb_argnum_error when
    RARRAY_LEN(regs[0]) == 0. On the base build it fires on exactly the five
    empty-array crashers (INV) and on no boundary or control (their packed
    array is non-empty, or they never enter the n == 15 branch).
  assert_after: the same instrumentation on the developer-patched handler, where
    the patch's own `if (RARRAY_LEN(regs[0]) == 0) goto argnum_error;` runs
    before the inserted check, so the marker never prints and every case is OK.

dev: the developer's model, from the fix commit message 47068ae07 ("vm.c:
  packed arguments length may be zero for `send` method."). It names the packed
  (n == 15) argument array of send as possibly empty, which is the invariant
  above; applied as the fix it predicts the empty-array crashers repaired
  (OK after) and crashing on the base (ASAN before). The developer patch
  realizes it fully, so dev:before and dev:after match the observation on all
  cases.

Crasher and boundary cases raise exceptions on CRuby, so their OK class means
only "no sanitizer report, a controlled Ruby exception"; the value controls
(ctrl_*) carry the wrong-result class, compared with the CRuby 2.7 reference.

This file was written on 2026-10-28 during the root-cause analysis, after the
mechanism was read from the source (mrb_f_send, base src/vm.c:689-735) but
before the before/after/assert variant case logs of this instance were read.
The step-3 poc_before.log (base, heap-buffer-overflow READ at vm.c:695 in
mrb_f_send) and step-4 poc_after.log (ArgumentError, no sanitizer report) were
known when it was written and fix the poc row (ASAN before, OK after).
"""

cols = ["dev:before", "dev:after",
        "ours:before", "ours:after",
        "ours:assert_before", "ours:assert_after"]
rows = []


def add(name, dev_b, dev_a, before, after, a_before, a_after):
    rows.append([name, dev_b, dev_a, before, after, a_before, a_after])


# Empty-packed-array inputs: all reach the n == 15 read (assert_before INV),
# all fixed by the developer patch. The uninstrumented base reports a sanitizer
# error only for the two whose empty array is a shrunk >= 15-element heap buffer
# (H3): crash16 and poc are ASAN on the base, the literal/short-splat empties
# are OK on the base (ASan-silent) though the invariant is violated.
for name in ("crash16", "poc"):
    add(name, "ASAN", "OK", "ASAN", "OK", "INV", "OK")
for name in ("splat_empty", "dunder_empty", "recurse1"):
    add(name, "OK", "OK", "OK", "OK", "INV", "OK")

# Boundary: n != 15 path, or a non-empty packed array read validly.
for name in ("send_sym", "send_undef"):
    add(name, "OK", "OK", "OK", "OK", "OK", "OK")

# Value controls: a non-empty packed array through the n == 15 branch (or the
# n == 1 path), then a real method; must keep their CRuby value.
for name in ("ctrl_str", "ctrl_splat1", "ctrl_splat2"):
    add(name, "OK", "OK", "OK", "OK", "OK", "OK")

print("\t".join(["case"] + cols))
for r in rows:
    print("\t".join(r))
