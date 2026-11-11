"""Predicted result class of every case of scripts/arypush_cases.tsv under
each hypothesis, for scripts/check_predictions.py (mruby.cve-2022-0717).

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG,
ASAN, INV (ARYPUSH-INVARIANT compile error) or - (not modelled).

dev: the developer's model, from the subject of f72315575 ("codegen.c: fix
  a argument generation bug in array assignment.") and the patch: with 14
  register arguments the right-hand side is a 15th argument, which only a
  packed argument array can carry, but the n == 14 case was treated as
  already packed and the right-hand side was appended to the 14th argument
  with OP_ARYPUSH. The model predicts a failure whenever n == 14 before the
  right-hand side (ASAN for a non-array 14th value, WRONG for an Array) and
  a complete fix by the patch (pack the 15 values with OP_ARRAY). It counts
  the keyword hash as an argument, so 13 positional arguments and keywords
  (f2) fail on the base build and are fixed by the patch. It predicts the
  correct arguments for every other count (f3, b, c).

ours: H1, the reported failure. OP_ARYPUSH in the post-right-hand-side
  branch of gen_assignment() must target the packed argument array; on the
  base build it is emitted for n == 14, when the 14 arguments are separate
  registers, so it targets the 14th argument and the call reads 14
  registers. An immediate 14th value (Integer, nil, true, false, Symbol,
  Float) is read as an array pointer: SEGV in mrb_ary_push (ASAN). An Array
  receives the right-hand side and the call gets 14 arguments (WRONG). The
  plain assignment, the value-used assignment, multiple assignment, the for
  variable and the rescue target all reach the branch. The developer patch
  packs the 15 values and sets n = 15 (OK).
  H2, the keyword branch of this tree (the defect of mruby.cve-2022-1276,
  present here): gen_hash(..., VAL, 0) pushes the hash and the caller
  pushes once more, so after the keywords the compiler stack is one
  register past the values. (a) f2: 13 positional arguments and keywords
  give n == 14; on the base build OP_ARYPUSH targets the leftover register
  past the hash (the first pair's value, or the double-splat operand), ASAN;
  with the developer patch the 15-value OP_ARRAY starts one register late
  and the call reads the first positional argument (an Integer) as the
  argument array, ASAN with another first frame (mrb_vm_exec for a
  Ruby-defined []=, mrb_get_args for String#[]=), the reported failure of
  mruby.cve-2022-1276. Its developer patch c8c083cb75 packs 13 positional
  arguments before the hash, which avoids the branch (OK in cve1276_alone,
  dev_cve1276 and the two root variants, whose patch contains c8c083cb75).
  (b) f3: 0 to 12 positional arguments and keywords; n <= 13 after the
  hash, the call reads n registers and the last one is the leftover, not
  the right-hand side: WRONG on every build that lacks the pop() of the
  mruby.cve-2022-1276 root-cause patch (cve1276root_alone, dev_cve1276root:
  OK). The ARYPUSH-INVARIANT check is not reached (WRONG on assert_*).
  H3, observability of a heap 14th value (f1_str, f1_obj, and the hash
  leftovers of f2_dsplat and poc1276): mrb_ary_push reads the object's
  fields as array fields. A one-character String has a zero length and
  capacity there, so the push allocates a 32-byte buffer into the string's
  slot and the string stays readable; the buffer is never freed, reported
  by LeakSanitizer at exit (ASAN). An Object, or a Hash, gets its ivar
  table pointer overwritten by the new length, and the next access to it
  (iv_free at the latest, during mrb_close) faults (ASAN). These classes
  depend on the object layout, not on the invariant; the assertion
  variants show the reach independently of them.
  assert_before / assert_after: scripts/arypush_invariant_before.diff and
  arypush_invariant_after.diff add, in the post-right-hand-side OP_ARYPUSH
  branch, a codegen_error() with ARYPUSH-INVARIANT when n != 15. It fires
  at compile time for every f1 and f2 case on the base build (INV), on no
  case with the developer patch (that branch is then only reached with
  n == 15), and not for f3, whose n stays below 14 (WRONG as above).
  Boundaries (b) and controls (c) do not reach the branch with n == 14: OK
  on every build.

This file was written on 2026-10-28 before the before variant ran. Known
when it was written: poc_before.log (SEGV in mrb_ary_push) and poc_after.log
(ArgumentError, no report), the regression tests on both builds, the CRuby
2.7.0 values of scripts/arypush_expected.tsv, and the `mrbc -v` bytecode of
five programs (14 and 13 positional arguments, 13 and 12 positional
arguments with a keyword, and a 14-argument multiple assignment) on the
base and the developer build; no case of the table had been run with mruby.

Revision of 2026-11-04, after the first check (logs/mruby.cve-2022-0717/
predictions_run1.tsv and predictions_run1.log): H4, the exception class
of the String receiver. Run 1 predicted OK for f1_strrecv, f2_strrecv and
poc1276 wherever their call completes; there they raise TypeError, where
CRuby 2.7 raises ArgumentError. The errclass case set
(scripts/arypush_errclass_cases.py, variants/before.errclass.log,
variants/after.errclass.log) shows the same class for the same argument
list passed through send, which does not use gen_assignment(), so the
class comes from String#[]= and not from the code generator. H4: a
String-receiver call that completes reads WRONG (E:TypeError) against
CRuby 2.7, in the dev and the ours columns alike. The three rows change
accordingly; H1 to H3 and every other cell are unchanged. This revision
was made after the observations and is not a test of H4.
"""
import csv
import sys

COLS = ["dev:before", "dev:after", "ours:before", "ours:after",
        "ours:assert_before", "ours:assert_after", "ours:cve1276_alone",
        "ours:dev_cve1276", "ours:cve1276root_alone", "ours:dev_cve1276root"]

F1_CRASH = ["poc", "f1_int", "f1_zero", "f1_nil", "f1_true", "f1_false", "f1_sym",
            "f1_float", "f1_str", "f1_obj", "f1_arrrecv", "f1_strrecv", "f1_val",
            "f1_masgn", "f1_for", "f1_rescue"]
F1_ARRAY = ["f1_ary", "f1_arysrc"]
F2 = ["f2_kw", "f2_dsplat", "f2_strrecv", "poc1276"]
F3 = ["f3_kw0", "f3_kw1", "f3_kw12", "f3_dsplat1"]
STR_F1 = ["f1_strrecv"]
STR_F2 = ["f2_strrecv", "poc1276"]

#                 dev:b   dev:a  ours:b  ours:a  as_b   as_a   1276a  d1276  1276ra d1276r
ROW = {
    "f1_crash": ["ASAN", "OK", "ASAN", "OK", "INV", "OK", "ASAN", "OK", "ASAN", "OK"],
    "f1_array": ["WRONG", "OK", "WRONG", "OK", "INV", "OK", "WRONG", "OK", "WRONG", "OK"],
    "str_f1": ["ASAN", "WRONG", "ASAN", "WRONG", "INV", "WRONG", "ASAN", "WRONG", "ASAN", "WRONG"],
    "str_f2": ["ASAN", "WRONG", "ASAN", "ASAN", "INV", "ASAN", "WRONG", "WRONG", "WRONG", "WRONG"],
    "f2": ["ASAN", "OK", "ASAN", "ASAN", "INV", "ASAN", "OK", "OK", "OK", "OK"],
    "f3": ["OK", "OK", "WRONG", "WRONG", "WRONG", "WRONG", "WRONG", "WRONG", "OK", "OK"],
    "ok": ["OK"] * 10,
}


def group(name):
    if name in STR_F1:
        return "str_f1"
    if name in STR_F2:
        return "str_f2"
    if name in F1_CRASH:
        return "f1_crash"
    if name in F1_ARRAY:
        return "f1_array"
    if name in F2:
        return "f2"
    if name in F3:
        return "f3"
    return "ok"  # b_* and c_*


cases = [r[0] for r in csv.reader(open(sys.argv[1] if len(sys.argv) > 1 else
                                       "scripts/arypush_cases.tsv"), delimiter="\t")]
for n in F1_CRASH + F1_ARRAY + F2 + F3:
    assert n in cases, n
print("case\t" + "\t".join(COLS))
for n in cases:
    assert group(n) != "ok" or n.startswith(("b_", "c_")), n
    print(n + "\t" + "\t".join(ROW[group(n)]))
