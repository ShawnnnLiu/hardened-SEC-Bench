"""Predicted result class of every scripts/recurdesc_cases.py case under each
hypothesis, for scripts/check_predictions.py (njs.cve-2022-31306).

Usage: python3 recurdesc_predictions.py CASES_TSV > recurdesc_predictions.tsv
(CASES_TSV is the cases.tsv written by recurdesc_cases.py.)

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG,
ASAN, INV (a RECURDESC-INVARIANT check fired) or - (not modelled).

ours: the invariant of the note. njs_object_prop_define() caches the result
  of one property query of the target; for an existing fast-array element the
  cached result is an NJS_PROPERTY_REF. It then reads the supplied descriptor
  with njs_descriptor_prop(), which fetches the fields get, set, value,
  writable, enumerable and configurable with ordinary property gets. If a
  field is an accessor whose getter converts the target fast array to a slow
  array (any of Object.defineProperty on an element, Object.freeze,
  Object.seal, an index at or above NJS_ARRAY_LARGE_OBJECT_LENGTH, or a large
  length), njs_array_convert_to_slow_array() releases array->start and clears
  object.fast_array. The cached NJS_PROPERTY_REF is then stale: for an
  accessor descriptor (field get or set) the NJS_PROPERTY_REF arm calls
  njs_array_convert_to_slow_array() a second time, and the base build reads
  array->start[i] over the released storage (array->start is NULL after the
  first conversion, so the read is at the zero page). The invariant:
  njs_array_convert_to_slow_array() is called only on a fast array. The
  developer patch adds an early return when the array is not a fast array, so
  the second call is a no-op.
  The faulty set is the family rc (an accessor descriptor, field get or set,
  for the outer define; and the index variants idx0 and newidx and the nested
  case depth2). For these: ASAN on the base build and on the CVE_NVD base,
  OK after the patch, at upstream master and on the two assert_after columns;
  INV on assert_before (the instrumentation fires on the second conversion).
  The family reent (a data or generic descriptor, field value, writable,
  enumerable or configurable) does not reach the convert arm: the outer write
  takes the direct NJS_PROPERTY_REF write path, which does not call the
  conversion a second time, so the base build does not crash. njs resolves
  some of these reentrant defines to a different final array state than the
  reference, on the base build and after the patch alike; this is a
  reentrancy-ordering difference unrelated to the reported crash and is not
  determined by the invariant (-), recorded as a residual. The instrumentation
  does not fire on reent (no second conversion), so its assert columns are
  also -.
  The families ctl (controls that do not reach the faulty state) and valid
  (ordinary defineProperty results) are OK on every build.

dev: the developer's model, from the message of 81af2636 ("Fixed
  Object.defineProperty() when a recursive descriptor is provided.") and the
  unit test the patch adds (a descriptor whose set field is an accessor whose
  getter recursively calls Object.defineProperty on the same array). Read
  literally, a recursive descriptor, one whose field getter re-enters
  Object.defineProperty on the array, crashes on the base build and is fixed
  after. The dev columns are therefore ASAN on the base build for the cases
  whose getter's conversion is itself an Object.defineProperty (conv == defp),
  the nested case and the dataset PoC, and OK for every other case; OK after
  the patch for all cases. The model names only the Object.defineProperty
  re-entry route; the freeze, seal, large-index and large-length routes reach
  the identical second conversion (ours predicts ASAN, dev predicts OK), and
  a data-field recursive descriptor (field value, writable, enumerable,
  configurable with conv == defp) does not crash (ours -, dev predicts ASAN);
  the reentrancy-ordering residual is wrong after the patch where dev predicts
  OK. check_predictions.py reports these as the observations the dev model
  does not predict.

Exploratory observations before this file was written (not kept as logs):
the dataset PoC on both builds (poc_before.log, poc_after.log); probe scripts
that read the final array state of one reentrant accessor descriptor and of
the value, writable and configurable data-field descriptors on the base and
developer builds, which established that the accessor-field cases crash and
are fixed while the data-field cases do not crash and differ from the
reference the same way on both builds; the first run of the `before` and
`after` case variants, written to an outdir path one level too high and
removed, whose summaries (base 22 ASAN, 12 WRONG; developer 0 ASAN, 12 WRONG)
match this model. The predictions were written on 2026-10-17 before the
`before` and `after` variants were rerun into logs/njs.cve-2022-31306/variants.
The expected values are the Node.js v22.22.2 outputs
(scripts/recurdesc_expected.tsv).
"""
import csv
import sys

COLS = ["dev:before", "dev:after",
        "ours:before", "ours:after", "ours:assert_before", "ours:assert_after",
        "ours:cvenvd_base", "ours:cvenvd_after", "ours:upstream_master"]


def ours(c, variant):
    fam = c["family"]
    if fam == "rc":
        if variant in ("before", "cvenvd_base"):
            return "ASAN"
        if variant == "assert_before":
            return "INV"
        return "OK"  # after, assert_after, cvenvd_after, upstream_master
    if fam == "reent":
        return "-"
    # ctl, valid
    return "OK"


def dev(c, variant):
    if variant == "after":
        return "OK"
    # before: a recursive descriptor whose getter re-enters Object.defineProperty
    recursive_define = c["conv"] == "defp" or c["case"] == "poc"
    return "ASAN" if recursive_define else "OK"


def main():
    rows = list(csv.DictReader(open(sys.argv[1]), delimiter="\t"))
    rows.append({"case": "poc", "family": "rc", "field": "set", "conv": "defp", "idx": "1", "faulty": "1"})
    print("case\t" + "\t".join(COLS))
    for c in rows:
        cells = []
        for col in COLS:
            model, variant = col.split(":")
            cells.append(dev(c, variant) if model == "dev" else ours(c, variant))
        print(c["case"] + "\t" + "\t".join(cells))


if __name__ == "__main__":
    main()
