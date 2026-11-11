"""Predicted result class of every scripts/splice_deleted_cases.py case under
each hypothesis, for scripts/check_predictions.py (njs.cve-2022-29779).

Usage: python3 splice_deleted_predictions.py CASES_TSV > splice_deleted_predictions.tsv
(CASES_TSV is the cases.tsv written by splice_deleted_cases.py.)

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG,
ASAN, INV (a SPLICE-INVARIANT check fired) or - (not modelled).

dev: the developer's model, from the message of 2e00e954 ("when "this"
  argument was not a fast array, but the "deleted" array was a fast array,
  the "deleted" array may be left in uninitialized state if "this" argument
  had gaps ... ensure that "deleted" is properly initialized"). Read
  literally: the returned array holds unwritten memory exactly when `this`
  is not a fast array, `deleted` is fast and `this` has a gap in the deleted
  window; what a consumer then observes depends on the memory (not
  modelled); after the patch the array is correct. It says nothing about
  other builtins or about a delete count with a side effect.
ours: the invariant of the note. Every slot [0, length) of a fast array holds
  a value or the absent-element marker. njs_array_prototype_splice() breaks
  it when `this` is not a fast array, the array of deleted elements is fast
  (delete count of 32768 or less) and an element of the deleted window is
  absent (njs_value_property_i64() returns NJS_DECLINED, and the slot is not
  written). The class a consumer observes at an unwritten slot depends on the
  memory content (the AddressSanitizer fill pattern or stale pool memory), so
  the cells of the faulty cases on the base build are -; every other case
  of the groups splice, consumer, size, bt and valid is OK on every build,
  and the group nbr (other Array builtins on a `this` with gaps) is
  predicted OK on every build because slice, map, filter, concat and the
  index-based builtins write every slot or the marker (read in the source
  before the cases were run; the group tests that reading). The group reent
  (a delete count whose valueOf shortens `this`) is another defect of the same
  function, not modelled for the builds before 607de2bd (-) and predicted OK
  at upstream master, whose history (607de2bd) says it is fixed.
  Variants: before (base, the image tree f65981b0), after (developer patch),
  assert_before (base + scripts/splice_deleted_invariant.diff, which fills
  the slots of a fast array of deleted elements with a poison value after the
  allocation and prints SPLICE-INVARIANT and aborts if a poison slot is left
  after the copy loops), assert_after (developer patch + the same diff;
  never fires), upstream_master, cvenvd_base and cvenvd_after (the CVE_NVD
  base 8b39afda, without and with the developer patch), noguard (the
  developer patch without the line `if (deleted->object.fast_array) {` and
  its closing brace: the marker is then written into a slow array of deleted
  elements, whose start is NULL, so a gap with a delete count of 32769 writes
  through NULL: ASAN).

Exploratory observations before this file was written: the 38 cases of the
groups valid and the containers fast and fastholes were run on the base
build (38 OK against the reference); the dataset PoC was run on both builds
(poc_before.log, poc_after.log). The printer of plain objects in the case files was changed at 03:59 EDT, after
run 1 of the variants `before` and `after` (kept in logs/<instance>/variants_run1) had shown that njs and the
reference engine order integer-like keys differently in JSON.stringify; the predictions did not change. The
predictions for the 145 cases were
written on 2026-10-14 at 03:55 EDT before the `before` variant run. The
expected values are the Node.js v22.22.2 outputs
(scripts/splice_deleted_expected.tsv).
"""
import csv
import sys

COLS = ["dev:before", "dev:after", "ours:before", "ours:after", "ours:assert_before", "ours:assert_after",
        "ours:upstream_master", "ours:cvenvd_base", "ours:cvenvd_after", "ours:noguard"]


def faulty(c):
    return c["faulty"] == "1"


def before(c):
    g = c["group"]
    if g == "reent":
        return "-"
    if g in ("splice", "consumer", "size", "bt"):
        return "-" if faulty(c) else "OK"
    return "OK"


def after(c):
    if c["group"] == "reent":
        return "-"
    return "OK"


def assert_before(c):
    if c["group"] in ("splice", "consumer", "size", "bt") and faulty(c):
        return "INV"
    return before(c)


def upstream_master(c):
    return "OK"


def noguard(c):
    if c["group"] == "size" and c["n"] == "32769":
        return "ASAN"
    return after(c)


def dev_before(c):
    g = c["group"]
    if g in ("nbr", "reent"):
        return "-"
    if g in ("splice", "consumer", "size", "bt") and faulty(c):
        return "-"
    return "OK"


def dev_after(c):
    if c["group"] in ("nbr", "reent"):
        return "-"
    return "OK"


def main(path):
    rows = list(csv.DictReader(open(path), delimiter="\t"))
    fn = {"dev:before": dev_before, "dev:after": dev_after, "ours:before": before, "ours:after": after,
          "ours:assert_before": assert_before, "ours:assert_after": after, "ours:upstream_master": upstream_master,
          "ours:cvenvd_base": before, "ours:cvenvd_after": after, "ours:noguard": noguard}
    w = sys.stdout
    w.write("case\t" + "\t".join(COLS) + "\n")
    for c in sorted(rows, key=lambda r: r["case"]):
        w.write(c["case"] + "\t" + "\t".join(fn[col](c) for col in COLS) + "\n")
    # the dataset PoC (case poc, run as an extra file): a sanitizer report on the base build, none after
    poc = {"dev:before": "ASAN", "dev:after": "OK", "ours:before": "ASAN", "ours:after": "OK",
           "ours:assert_before": "INV", "ours:assert_after": "OK", "ours:upstream_master": "OK",
           "ours:cvenvd_base": "ASAN", "ours:cvenvd_after": "OK", "ours:noguard": "OK"}
    w.write("poc\t" + "\t".join(poc[col] for col in COLS) + "\n")


if __name__ == "__main__":
    main(sys.argv[1])
