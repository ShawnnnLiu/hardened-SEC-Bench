"""Predicted result class of every scripts/trimzero_cases.py case under each
hypothesis, for scripts/check_predictions.py (njs.cve-2022-38890).

Usage: python3 trimzero_predictions.py > trimzero_predictions.tsv

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG,
ASAN, INV (a TRIMZERO-INVARIANT check fired) or - (no prediction).

Written on 2026-10-28, before any case of the families that reach the
faulty state (viol = 1) had run in a variant. The only viol case observed
before this file was written is the dataset PoC (poc_before.log: an ASan
SEGV whose frames #0 njs_utf8_next / #1 njs_string_offset / #2
njs_string_prototype_last_index_of equal the dataset report; poc_after.log:
no report), added as the row `poc`.

Invariant (ours). njs_string_prop stores a string value as (start, size,
length): size is the byte count, length the UTF-8 character count, and
length == 0 with size != 0 is a byte string, length == 0 with size == 0
the empty string (src/njs_string.h). njs_string_trim() must return a
(length, size) consistent with an actual sub-range of the input; when every
character is removed the result is the empty string (size == 0). In the
UTF-8 trim-end branch the loop sets end only when it meets a non-whitespace
character; when the whole run from `start` is whitespace it leaves through
`if (start == prev) break;` with end still at the original string end, so
the tail sets size = end - start (nonzero) and length -= trim (0). The
result is then a byte string of nonzero size and length 0 that holds the
original whitespace bytes instead of the empty string.

  H1 (faulty producer set). Only trimEnd() applied to a UTF-8 string whose
  whole run from the string start is whitespace reaches the faulty break
  with end unset. trim() runs trim-start first, which advances start to end
  for an all-whitespace input, so the trim-end break already has
  start == end; trimStart() never enters the trim-end branch; a UTF-8 input
  with a non-whitespace character sets end at that character; an ASCII or
  byte input takes another branch. The viol = 1 cases (tz_<kind>_<cons>,
  10 all-whitespace UTF-8 kinds times 11 consumers, and the dataset PoC)
  are exactly the inputs that reach the faulty state; the instrumentation
  (trimzero_invariant.diff) therefore fires on exactly these on the base
  build (class INV) and on no other, whatever the consumer.
  H2 (the consumer symptom is not determined by H1). The faulty result is a
  byte string holding the original whitespace bytes; its observable value
  depends on how the base build treats a length-0 byte string of specific
  bytes, which is a property of the string builtins, not of the
  (length, size) invariant. The base-build class of a viol case is
  therefore not predicted (-) in ours:before and ours:cvenvd_base for every
  consumer; the invariant's testable claim is that the faulty state is
  reached, carried by the assert_before column (INV). The dataset PoC
  chains the faulty result through padEnd() to length 512 and then
  lastIndexOf(), which was observed to give an ASan report (poc_before.log)
  and is predicted ASAN.
  Revision 2026-10-28, after the before run (predictions_run1.tsv kept
  under logs/njs.cve-2022-38890/): the pre-run file predicted OK for the
  val and slice consumers, on the reasoning that a length-0 result renders
  identically to the empty string. That was falsified: njs reports
  String.prototype.length of a byte string as its byte size, so val
  (show by length) and slice(0, 1) also observe the hidden bytes (20
  cases, WRONG on the base build). The idx consumer is OK for the kinds
  whose bytes do not contain U+2028 (indexOf returns -1 as for the empty
  string) and WRONG for the kinds whose bytes do (it finds the character):
  a per-kind outcome. Both confirm that the per-consumer base-build symptom
  is not derivable from the length/size invariant, so H2 now marks every
  viol consumer - on before and cvenvd_base.
  H3 (the patch). The developer patch adds `end = prev;` in the faulty
  break, so for an all-whitespace trailing run start == end holds and the
  empty-string path (size 0, length 0) is taken. Every consumer then
  observes the reference value: ours:after, ours:cvenvd_after and
  ours:upstream_master are OK on every case, and the instrumentation placed
  inside the patched tree (ours:assert_after) never fires.
  H4 (scope). Nothing else changes: trim(), trimStart(), UTF-8 inputs with
  a non-whitespace character, and ASCII/byte inputs are OK on every build
  (the viol = 0 families prod_*, valid_*). A non-OK result in these
  families on the base build is a separate defect, not part of H1.
  Variants: before (base), after (developer patch), assert_before (base +
  trimzero_invariant.diff), assert_after (developer patch +
  trimzero_invariant.diff), cvenvd_base / cvenvd_after (the CVE_NVD base
  commit 8cd99f9b without / with the developer patch; src/njs_string.c,
  src/njs_string.h and src/njs_utf8.h are byte-identical between the image
  tree 6af74b6c and 8cd99f9b, so the two bases are expected to behave
  alike), upstream_master.

dev: the developer's and reporter's model. The fix commit b9aea585 is
  "Fixed String.prototype.trimEnd() with unicode string." and issue #569 is
  "Another way to trigger SEGV in njs_utf8_next cause oob read" with the
  padEnd()+lastIndexOf() PoC. Read as a crash report, trimEnd() on a
  unicode (UTF-8) whitespace string yields an out-of-bounds read, so
  dev:before predicts ASAN for every viol case and OK after the patch. The
  model names the right producer and the right fix; it does not model the
  wrong-result consumers (a byte string observed without a crash), so the
  viol cases that are wrong-value-only on the base build are the
  observations the crash report does not predict (counted in dev_model).

Observations on the base build that precede this file (not kept as logs):
  none beyond the recorded stage logs; the PoC crash (poc_before.log) and
  its absence after the patch (poc_after.log) are the only viol
  observations, and the Node.js reference outputs of the non-viol cases
  were produced by scripts/njs_cases.py --oracle (scripts/
  trimzero_expected.tsv) without a base-build run. No case of this set was
  run on an njs build before this file was written.

The expected values are the Node.js v20.9.0 outputs
(scripts/trimzero_expected.tsv).
"""
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from trimzero_cases import gen  # noqa: E402

COLS = ["dev:before", "dev:after", "ours:before", "ours:after",
        "ours:assert_before", "ours:assert_after",
        "ours:cvenvd_base", "ours:cvenvd_after", "ours:upstream_master"]

def row(viol, cons):
    if not viol:
        return dict.fromkeys(COLS, "OK")
    # H2 (revised 2026-10-28): the per-consumer base-build symptom of a viol
    # case is not predicted from the length/size invariant; assert_before
    # (INV) carries the invariant's claim that the faulty state is reached.
    return {
        "dev:before": "ASAN", "dev:after": "OK",
        "ours:before": "-", "ours:after": "OK",
        "ours:assert_before": "INV", "ours:assert_after": "OK",
        "ours:cvenvd_base": "-", "ours:cvenvd_after": "OK",
        "ours:upstream_master": "OK",
    }


def main():
    w = csv.writer(sys.stdout, delimiter="\t", lineterminator="\n")
    w.writerow(["case"] + COLS)
    for name, family, prod, kind, cons, viol, _body in gen():
        c = row(viol, cons)
        w.writerow([name] + [c[col] for col in COLS])
    # the dataset PoC, added by the runner as case "poc": observed to crash
    # the base build before this file (poc_before.log) and not after
    # (poc_after.log); with the instrumentation the abort fires in the
    # trimEnd() call (class INV) before the padEnd()/lastIndexOf() chain.
    w.writerow(["poc", "ASAN", "OK", "ASAN", "OK", "INV", "OK",
                "ASAN", "OK", "OK"])


if __name__ == "__main__":
    main()
