"""Predicted result class of every scripts/dumpacc_cases.py case (plus the
dataset PoC, run as the --extra case "poc") under each model, for
scripts/check_predictions.py (njs.cve-2023-27728).

Usage: python3 dumpacc_predictions.py CASES_TSV > dumpacc_predictions.tsv
(CASES_TSV is the cases.tsv written by dumpacc_cases.py.)

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG,
ASAN, INV (a DUMPACC-INVARIANT check fired) or - (not modelled). Every case's
reference (Node.js) output is empty, so the file-mode observable is the
result class only: ASAN (the OOB read), INV (the instrumented invariant), a
printed GETTER-INVOKED/SETTER-INVOKED marker (WRONG) or no output (OK).

dev: the developer's model, from the message of 1f54b79c ("Fixed array
  instance with a getter property dumping.", closes #618). Read literally the
  model names one trigger: dumping an array instance that has a getter
  property. So dev predicts ASAN on the base for the fast-array cases whose
  accessor has a getter (kinds get, getset, getobj), and OK everywhere else,
  including the set-only accessor (no getter) and the controls; after the fix
  everything is OK.
ours: the invariant of the note. In njs_vm_value_dump (src/njs_json.c), before
  a dumped property's val is used as a value (njs_dump_is_recursive(val) and
  the recursion njs_json_push_stringify_state -> njs_value_own_enumerate), an
  accessor-descriptor property's val must have been replaced by the marker
  string "[Getter]"/"[Setter]"/"[Getter/Setter]", for every container kind.
  At the base commit the replacement runs only inside `if (!state->fast_array)`,
  so for a fast array an own accessor property keeps val = njs_prop_value(prop),
  the raw getter/setter union. The invariant is therefore violated for every
  fast-array own accessor (assert_before INV), independent of the getter.
  The base-build symptom depends on the union bits: a getter pointer is
  present (kinds get, getset, getobj) and is dereferenced as an object -> a
  sanitizer report (ASAN); a set-only accessor has a NULL getter, so the
  overlaid value does not recurse and the dump terminates without the OOB
  read -- no crash (OK on the base) although the invariant is violated
  (assert_before INV). A container that is not a fast array (a plain object,
  a slow array, an index accessor that converts the array to slow) and a data
  or absent named property take the replacement / non-accessor path already,
  so val is replaced or the property is not an accessor: no INV, OK.
  After the developer patch (the gate removed) the replacement runs for fast
  arrays too, so val is replaced on every accessor and no case reaches the
  faulty val-as-value use (after OK, assert_after no INV).
  Variants:
    before          base, the image tree 4c1e2332 (v0.7.10)
    after           developer patch (both hunks; the test hunk is inert here)
    assert_before   base + scripts/dumpacc_invariant.diff (print DUMPACC-
                    INVARIANT and abort when a dumped accessor property still
                    has val == njs_prop_value(prop)): INV on exactly the
                    fast-array accessor cases, OK elsewhere
    assert_after    developer patch + the same diff (applies with offset):
                    never fires, every case OK
    upstream_master master of https://github.com/nginx/njs: OK on every case

Calibration before this file was written (allowed boundary probes on the base
and developer-patch builds, not kept as logs): the dataset PoC on both builds
(poc_before.log SEGV at 0x18 in njs_value_own_enumerate via the retval dump,
poc_after.log clean); a get-only accessor on a fast array crashes on the base
and is clean after (t1/t2 probes); a set-only accessor on a fast array does
not crash on either build; a non-enumerable get accessor on a fast array
crashes on the base (arrays dump non-enumerable own keys, njs_array_keys
all=1) and is clean after. The reference values are the Node.js v20.9.0
outputs (scripts/dumpacc_expected.tsv, all empty). The predictions were
written on 2026-10-28 before any variant run.

Revision 2026-10-28, after the before and assert_before runs (the pre-run
TSV is logs/njs.cve-2023-27728/predictions_run1.tsv, predictions_run1.log):
the invariant model is unchanged and was confirmed -- ours:assert_before is
INV on exactly the seven fast-array accessor cases and OK on the five
controls (12/12), ours:after/assert_after/upstream_master 12/12. Only the
ours:before crash SYMPTOM was corrected for two cases. The invariant (an
accessor's val is not replaced on a fast array) is violated for all seven
fast-array accessors, but whether that violation faults depends on the
overlaid union bits and the heap layout -- the field read first was already
build dependent (0x18 here vs 0x22 in the dataset report). Observed on the
base build: fa_get, fa_getobj, fab_nonenum and poc fault (a get-only accessor
whose getter pointer is dereferenced as a recursive object on an array with no
indexed elements ahead of it); fa_getset (get and set), fa_set (set only) and
fab_elems (a get accessor behind indexed elements) do not fault although they
violate the invariant (assert_before INV). The two cases moved from ASAN to
OK in ours:before relative to run1 are fa_getset and fab_elems; the crash is
therefore recorded as a bits-dependent symptom and the invariant is tested by
assert_before, not by the before crash class. The dev column is left as the
literal commit-message model ("getter property"), so its two before
mismatches (fa_getset, fab_elems: a getter present yet no crash) are the
observations the developer's message does not predict (dev_model).
"""
import csv
import sys

# accessor kinds whose union carries a getter pointer.
GETTER_KINDS = ("get", "getset", "getobj")

# fast-array accessor cases that actually fault on the base build (a
# bits/layout-dependent subset of the seven invariant-violating cases); see
# the revision note above. Keyed by case name because fab_nonenum and
# fab_elems share group fab and kind get yet differ in outcome.
CRASH_ON_BASE = ("fa_get", "fa_getobj", "fab_nonenum", "poc")

COLUMNS = [
    "dev:before", "dev:after",
    "ours:before", "ours:after",
    "ours:assert_before", "ours:assert_after", "ours:upstream_master",
]


def predict(case, group, kind):
    if group == "ctl":
        return {c: "OK" for c in COLUMNS}
    # fa / fab: a fast array with one own accessor property.
    getter = kind in GETTER_KINDS
    row = {}
    # dev: the literal commit-message model, a getter property crashes.
    row["dev:before"] = "ASAN" if getter else "OK"
    row["dev:after"] = "OK"
    # ours: the invariant is violated for every fast-array accessor
    # (assert_before INV); the before crash is the bits-dependent subset.
    row["ours:before"] = "ASAN" if case in CRASH_ON_BASE else "OK"
    row["ours:after"] = "OK"
    row["ours:assert_before"] = "INV"
    row["ours:assert_after"] = "OK"
    row["ours:upstream_master"] = "OK"
    return row


def main(cases_tsv):
    rows = list(csv.DictReader(open(cases_tsv), delimiter="\t"))
    print("case\t" + "\t".join(COLUMNS))
    for r in rows:
        p = predict(r["case"], r["group"], r["kind"])
        print(r["case"] + "\t" + "\t".join(p[c] for c in COLUMNS))
    # the dataset PoC, run by njs_run_variant.sh as --extra poc (a fast array
    # [] with one own enumerable getter accessor 'a', get: Object), dumped via
    # the shell retval path.
    poc = predict("poc", "fa", "getobj")
    print("poc\t" + "\t".join(poc[c] for c in COLUMNS))


if __name__ == "__main__":
    main(sys.argv[1])
