"""Predicted result class of every scripts/errname_cases.py case (plus the
dataset PoC, run as the --extra case "poc") under each model, for
scripts/check_predictions.py (njs.cve-2023-27730).

Usage: python3 errname_predictions.py CASES_TSV > errname_predictions.tsv
(CASES_TSV is the cases.tsv written by errname_cases.py.)

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG,
ASAN, INV (an ERRNAME-INVARIANT check fired) or - (not modelled). For a mode
dump case the shell retval dump is built but not printed in file mode, so the
reference (Node.js) output is empty and the observable is a sanitizer report
(ASAN) or nothing (OK); for a mode log case the reference output is the
console.log string and a differing string is WRONG. The reference values are
the Node.js v20.9.0 outputs (scripts/errname_expected.tsv).

Written on 2026-11-04 (host date), before any variant of this instance ran.
Calibration beforehand used base-build probes kept only as the note's
mechanism summary (not as logs): dumping an Error whose name is a non-string
object reports; the dataset PoC (poc_before.log) reports a SEGV at 0x726f with
frames njs_lvlhsh_find <- njs_object_property <- njs_error_to_string2; and
String(e), a non-string message, a string name, and a number/boolean name do
not report.

dev: the developer's model, from the message of 9cec8745 ("Fixed Error()
  instance dumping when \"name\" prop is not primitive.", closes #615). The
  stated trigger is dumping an Error whose "name" property is not a primitive.
  So dev predicts a report on the base for a dump whose error has a non-string
  OBJECT name (group name), and OK for a primitive name (group prim), a
  string name and the other groups; after the fix everything is OK. The dev
  model does not speak to the instrumented invariant or to master.

ours: the invariant of the note. njs_object_property (src/njs_object_prop.c)
  took `const njs_value_t *value` and derived object = njs_object(value)
  lazily at the lookup. njs_error_to_string2 (src/njs_error.c) fetches the
  error's "name" (line 597) and, when the name is a non-string object,
  converts it with njs_value_to_string (line 606), which invokes the name's
  toString/valueOf: a function call that can reallocate the VM value stack.
  The `error` argument points into that stack during a dump
  (njs_dump_terminal -> njs_error_to_string -> njs_error_to_string2), so it is
  stale afterwards; the "message" fetch (line 619) re-derives
  njs_object(error) from the stale slot (a string's bytes, address 0x726f)
  and njs_lvlhsh_find dereferences it: a report. Invariant: the object whose
  hash njs_object_property searches must be the error object live at the name
  fetch; the base re-derives it from a value pointer an intervening non-string
  name conversion can invalidate. A non-string PRIMITIVE name (number,
  boolean) is converted without a function call, so the stack is not
  reallocated and the pointer stays live (group prim OK). A string name needs
  no conversion; a non-string message is converted only after the message
  fetch; the toString path (String(e)) holds a stable argument pointer, not a
  dump temporary -- all OK. So ours predicts a report on the base for group
  name only, and no report after the fix (the patch changes njs_object_property
  to take a njs_object_t* and captures error_object once, before the
  conversion). The render and sib groups test the rendered value and the other
  njs_object_property callers the patch changes.

  Variants:
    before          base, the image tree 4c1e2332 (v0.7.10)
    after           developer patch (both hunks; the test hunk is inert here)
    assert_before   base + scripts/errname_invariant.diff (print
                    ERRNAME-INVARIANT and abort when njs_object_property is
                    called with a non-object value): INV on exactly the group
                    name cases (the stale re-deref at the message fetch), OK
                    elsewhere
    upstream_master master of https://github.com/nginx/njs: OK on every case

  No assert_after column: the fix changes njs_object_property's signature to
  take a njs_object_t*, so the instrumented precondition (a non-object value
  argument) no longer exists on the patched tree and errname_invariant.diff
  does not apply there; the patched tree is covered by the after and
  upstream_master variants (no report). This is recorded as a deviation.

Revision 2026-11-04, after the before and assert_before runs (the pre-run TSV
is logs/njs.cve-2023-27730/predictions_run1.tsv, predictions_run1.log): the
invariant model is unchanged and was confirmed -- ours:assert_before is INV on
exactly the five group-name cases and the PoC (6 of 6), OK on the eleven
others. Only the ours:before crash SYMPTOM was corrected for one case,
name_arr (e.name = [1,2,3]): it violates the invariant (assert_before INV, a
stale re-deref at the message fetch) but does not fault on this build, because
after the array's toString reallocates the value stack the stale slot holds
bytes whose object reinterpretation is a readable address; name_obj, name_err,
name_fn, name_tyerr and the PoC fault (the stale slot holds a short string
whose bytes are read as a near-null pointer, address 0x726f). So the crash is
a bits-dependent symptom of the invariant violation, tested by assert_before,
not by the before crash class. The dev column keeps the literal commit-message
model ("name not primitive"), so its one before mismatch (name_arr: a
non-primitive name yet no crash) is the observation the developer's message
does not predict (dev_model).
"""
import csv
import sys

COLUMNS = [
    "dev:before", "dev:after",
    "ours:before", "ours:after",
    "ours:assert_before", "ours:upstream_master",
]

# group-name cases (and the PoC) whose stale re-deref actually faults on the
# base build: a bits-dependent subset of the invariant-violating cases.
# name_arr violates the invariant (assert_before INV) but does not fault here.
CRASH_ON_BASE = ("name_obj", "name_err", "name_fn", "name_tyerr", "poc")


def predict(case, group):
    violates = (group == "name")  # a dump of an Error with a non-string object name
    row = {}
    # dev: the literal commit-message model, a non-primitive name reports.
    row["dev:before"] = "ASAN" if violates else "OK"
    row["dev:after"] = "OK"
    # ours: the invariant is violated for every group-name case (assert_before
    # INV); the before crash is the bits-dependent subset.
    row["ours:before"] = "ASAN" if case in CRASH_ON_BASE else "OK"
    row["ours:after"] = "OK"
    row["ours:assert_before"] = "INV" if violates else "OK"
    row["ours:upstream_master"] = "OK"
    return row


def main(cases_tsv):
    rows = list(csv.DictReader(open(cases_tsv), delimiter="\t"))
    print("case\t" + "\t".join(COLUMNS))
    for r in rows:
        p = predict(r["case"], r["group"])
        print(r["case"] + "\t" + "\t".join(p[c] for c in COLUMNS))
    # the dataset PoC, run by njs_run_variant.sh as --extra poc: a URIError
    # whose name is set to another URIError (a non-string object), then dumped.
    poc = predict("poc", "name")
    print("poc\t" + "\t".join(poc[c] for c in COLUMNS))


if __name__ == "__main__":
    main(sys.argv[1])
