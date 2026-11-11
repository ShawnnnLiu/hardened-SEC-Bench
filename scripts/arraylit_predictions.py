"""Predicted result class of every scripts/arraylit_cases.py case under
each hypothesis, for scripts/check_predictions.py (njs.cve-2022-28049).

Prints a TSV with one column per <model>:<variant>. Classes are OK,
WRONG, ASAN, INV (an ARRAYLIT-INVARIANT check fired) or - (not modelled).

dev: the developer's model, from the message of f65981b0 ("allocation of
  large array literals may result in null-pointer dereference ... the
  instruction code assumes that array is always flat ... check fast_array
  flag before accessing array->start"). Read literally, a large array
  literal (slow array) dereferences a NULL array->start; the fix removes
  that for the array instruction. It predicts the crash on every slow
  literal on the base build and a correct array on every literal after
  the patch.
ours: H1, the CVE crash. NJS_VMCODE_ARRAY with ctor set (a literal with a
  trailing hole or a leading value before holes: shapes elision and
  ctorlead) fills every slot through array->start; on a slow array
  (length + 8 > 32768, i.e. length > 32760) array->start is NULL and the
  write faults (ASAN). The developer patch guards the fill loop with
  fast_array, so on a slow array it is skipped: a pure-elision literal is
  then all holes (OK), and a ctorlead literal has its leading value lost
  (WRONG, see H2). A fast literal (length <= 32760) builds a flat array
  and is OK on every build.
  H2, the residual element loss (independent, not the CVE crash). A
  literal with an actual element at a defined index initialises it through
  NJS_VMCODE_PROPERTY_INIT, which writes array->start[index]; on a slow
  array the value is lost and the index reads undefined, without a crash.
  This holds on the base build for the non-ctor shapes (element, tailval,
  mixed) that are slow (WRONG, no crash), and on the developer-patch build
  for every slow literal with an element (element, tailval, mixed, and
  ctorlead, whose crash the patch turned into this loss). Upstream fixed
  it in 3557c57d (a slow-array branch in the element initialiser; its
  verbatim hunk uses later APIs and does not compile on the base, so the
  elemfix variant is a backport that uses njs_value_property_i64_set, the
  indexed setter of the base array builtins, source backport:3557c57d); it is
  independent of the CVE crash by the separability rule (the developer
  patch alone repairs the pure-elision crashes, 3557c57d alone repairs the
  element loss, and the two repaired sets are disjoint), so it is not in a
  root patch. At upstream master the element loss is fixed.
  Variants: before (base), after (developer patch), elemfix /
  after_elemfix (3557c57d alone / with the developer patch), assert_before
  (base + arraylit_invariant_before.diff, which aborts with
  ARRAYLIT-INVARIANT before the NULL write when the ctor fill loop meets a
  slow array), assert_after (developer patch +
  arraylit_invariant_after.diff, a silent assertion that the fill loop
  runs only on a fast array; never the violation, same classes as after),
  upstream_master.

The boundary length (32760 fast, 32761 slow) and the element-loss
behaviour were observed on the base and developer builds with exploratory
scripts before this file was written (not kept as logs); the predictions
for the 30 cases were written on 2026-10-13 before the `before` variant
run. The expected values are the Node.js v22.22.2 outputs
(scripts/arraylit_expected.tsv).
"""
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from arraylit_cases import cases  # noqa: E402

COLS = ["dev:before", "dev:after", "ours:before", "ours:after", "ours:elemfix",
        "ours:after_elemfix", "ours:assert_before", "ours:assert_after",
        "ours:upstream_master"]


def classes(shape, n, slow, he):
    # control cases: small dense/elision/trailhole, Array(n) constructor, all OK
    if shape == "control":
        return dict.fromkeys(COLS, "OK")
    if not slow:
        return dict.fromkeys(COLS, "OK")
    # slow literal
    if shape == "elision":
        # ctor, no element: base crash, dev all-holes OK, elemfix still crash
        base = "ASAN"; after = "OK"; elemfix = "ASAN"; after_elemfix = "OK"
        a_before = "INV"; a_after = "OK"; master = "OK"
    elif shape == "ctorlead":
        # ctor, has element: base crash; dev crash gone but value lost (WRONG);
        # elemfix alone still crashes (fill loop); both OK
        base = "ASAN"; after = "WRONG"; elemfix = "ASAN"; after_elemfix = "OK"
        a_before = "INV"; a_after = "WRONG"; master = "OK"
    else:
        # element, tailval, mixed: not ctor, element lost, no crash
        base = "WRONG"; after = "WRONG"; elemfix = "OK"; after_elemfix = "OK"
        a_before = "WRONG"; a_after = "WRONG"; master = "OK"
    return {"dev:before": "OK", "dev:after": "OK",
            "ours:before": base, "ours:after": after, "ours:elemfix": elemfix,
            "ours:after_elemfix": after_elemfix, "ours:assert_before": a_before,
            "ours:assert_after": a_after, "ours:upstream_master": master}


def dev_before(slow):
    # the developer's model: every slow literal dereferences NULL (crash)
    return "ASAN" if slow else "OK"


def main():
    w = csv.writer(sys.stdout, delimiter="\t", lineterminator="\n")
    w.writerow(["case"] + COLS)
    for name, shape, n, slow, he, _body in cases():
        c = classes(shape, n, slow, he)
        c["dev:before"] = dev_before(slow and shape != "control")
        c["dev:after"] = "OK"
        # poc_shape prints a number after the shift; dev/master OK, base crash
        if name == "poc_shape":
            c = {"dev:before": "ASAN", "dev:after": "OK", "ours:before": "ASAN",
                 "ours:after": "OK", "ours:elemfix": "ASAN", "ours:after_elemfix": "OK",
                 "ours:assert_before": "INV", "ours:assert_after": "OK",
                 "ours:upstream_master": "OK"}
        w.writerow([name] + [c[col] for col in COLS])
    # the dataset PoC (a large elision array literal, added by the runner as
    # case "poc"): base crash, developer patch and master OK
    w.writerow(["poc", "ASAN", "OK", "ASAN", "OK", "ASAN", "OK", "INV", "OK", "OK"])


if __name__ == "__main__":
    main()
