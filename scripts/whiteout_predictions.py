"""Predicted result class of every scripts/whiteout_cases.py case under each
hypothesis, for scripts/check_predictions.py (njs.cve-2023-27727).

Usage: python3 whiteout_predictions.py CASES_TSV > whiteout_predictions.tsv
(CASES_TSV is the cases.tsv written by whiteout_cases.py.)

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG,
ASAN, INV (a WHITEOUT-INVARIANT check fired) or - (not modelled).

dev: the developer's model, from the message of 484411868
  ("an error object dumping might result in invalid pointer dereference when
  'name' or 'message' property of accessor descriptor type was added and
  removed before. The fix is to properly handle NJS_WHITEOUT properties.").
  Read literally the model names one consequence: error-object dumping of an
  accessor 'name'/'message' that was added and removed crashes. So dev
  predicts ASAN on the base for the faulty (accessor) cases whose consumer
  dumps an error (errmsg, errname, poc), and OK everywhere else, including
  the other njs_object_property consumers (to-primitive toString/valueOf,
  JSON toJSON, Array join, defineProperty descriptor reads) and the data
  (non-accessor) tombstones; after the fix everything is OK. The mismatches
  on the base are the observations the message does not predict.
ours: the invariant of the note. njs_object_property() (src/njs_object_prop.c)
  must not return a property whose own-hash entry is an NJS_WHITEOUT
  tombstone; a deleted property must be looked up further or reported absent.
  njs_value_property_delete() (src/njs_value.c) leaves the deleted property in
  the hash as a tombstone and overwrites its accessor getter/setter union
  with the invalid-value bits (njs_set_invalid). On the base,
  njs_object_property() reaches `goto found` with the tombstone and
  - for an accessor kind (sacc, gacc, bacc) calls the overwritten getter
    pointer: a sanitizer report (ASAN);
  - for a data kind (data, dataro, assign) returns the invalidated value,
    because njs_is_data_descriptor() is true (writable != UNSET): a wrong
    result (WRONG), the invalid value masks the inherited member.
  After the developer patch (both files) the tombstone is skipped and the
  member is absent, so every case equals the reference (OK).
  Variants:
    before          base, the image tree 1f54b79c
    after           developer patch (both source hunks)
    objprop_only    only the src/njs_object_prop.c hunk (skip the WHITEOUT in
                    the own-hash find): predicted OK on every case, because
                    the tombstone is never returned regardless of its value
                    bits -- the hypothesis that this file's lines are what the
                    PoC needs
    value_only      only the src/njs_value.c hunk (stop invalidating the value
                    on delete and handle the removed out-value): the tombstone
                    is still returned as found, so the faulty and wrong cases
                    are not repaired; the exact class then depends on how the
                    retained accessor-union bits are read as a value, which is
                    implementation detail, so those cells are - (not modelled)
                    and only the valid cases are predicted OK
    assert_before   base + scripts/whiteout_invariant_before.diff, which prints
                    WHITEOUT-INVARIANT and aborts when njs_object_property() is
                    about to `goto found` on a prop of type NJS_WHITEOUT: INV
                    on exactly the faulty and wrong cases, OK on the valid ones
    assert_after    developer patch + scripts/whiteout_invariant_after.diff
                    (the same check at the found label of the patched tree):
                    never fires, every case OK
    upstream_master master of https://github.com/nginx/njs: OK on every case

Exploratory observations before this file was written (not kept as logs):
five probe programs on the base build (an accessor message deleted then
String(error) crashes for a setter-only and a getter-only descriptor; a data
message deleted gives a TypeError; a plain-object accessor deleted and read
with `in`/`.k` gives false/undefined with no crash; redefining after delete
is correct), and the dataset PoC on both builds (poc_before.log,
poc_after.log). The expected values are the Node.js v20.9.0 outputs
(scripts/whiteout_expected.tsv). The predictions were written on 2026-10-17
before any variant run of the faulty and wrong cases.
"""
import csv
import sys

ACC = ("sacc", "gacc", "bacc")
ERR_DUMP = ("errmsg", "errname", "poc")
# consumers that use the value njs_object_property returns directly, so a data
# tombstone's invalidated value becomes a wrong result (a TypeError when the
# member had to be converted, a wrong string when a non-callable member makes
# the caller fall back to a default): error name/message dumping, the error
# used as a message argument, Array toString (join), Object.defineProperty
# descriptor reads, and the string/default-hint primitive conversion (which
# tries valueOf -- here present only on the prototype, returning the object --
# then the deleted own toString).
CONSUMED_AS_VALUE = ("errmsg", "errname", "poc", "prim_ts", "arrjoin", "defprop", "ts_fn")
# consumers that only probe a function slot and fall back cleanly when the
# returned value is not callable, so a data tombstone is coincidentally OK on
# the base build although njs_object_property still returns the tombstone
# (the WHITEOUT-INVARIANT check fires on these too): the number-hint primitive
# conversion (valueOf deleted, toString inherited) and JSON toJSON (optional).
CONSUMED_AS_FUNCTION = ("prim_vo", "json")

COLUMNS = [
    "dev:before", "dev:after",
    "ours:before", "ours:after", "ours:objprop_only", "ours:value_only",
    "ours:assert_before", "ours:assert_after", "ours:upstream_master",
]


def predict(group, kind, consumer):
    if group == "valid":
        return {c: "OK" for c in COLUMNS}

    faulty = kind in ACC  # accessor tombstone -> crash on base
    row = {}
    # developer model: only accessor name/message error dumping is named
    row["dev:before"] = "ASAN" if (faulty and consumer in ERR_DUMP) else "OK"
    row["dev:after"] = "OK"
    # ours: the invariant is violated in every faulty and wrong case (the
    # tombstone is returned by njs_object_property), so assert_before is INV
    # for all of them; the base-build symptom is ASAN for an accessor, WRONG
    # for a data tombstone consumed as a value, and coincidentally OK for a
    # data tombstone consumed through a function slot that falls back.
    if faulty:
        row["ours:before"] = "ASAN"
    elif consumer in CONSUMED_AS_FUNCTION:
        row["ours:before"] = "OK"
    else:
        row["ours:before"] = "WRONG"
    row["ours:after"] = "OK"
    row["ours:objprop_only"] = "OK"
    row["ours:value_only"] = "-"
    row["ours:assert_before"] = "INV"
    row["ours:assert_after"] = "OK"
    row["ours:upstream_master"] = "OK"
    return row


def main(cases_tsv):
    rows = list(csv.DictReader(open(cases_tsv), delimiter="\t"))
    print("case\t" + "\t".join(COLUMNS))
    for r in rows:
        p = predict(r["group"], r["kind"], r["consumer"])
        print(r["case"] + "\t" + "\t".join(p[c] for c in COLUMNS))


if __name__ == "__main__":
    main(sys.argv[1])
