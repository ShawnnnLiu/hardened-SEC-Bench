"""Predicted result class of every scripts/apply_args_cases.py case under
each hypothesis, for scripts/check_predictions.py (njs.cve-2021-46462).

Usage: python3 apply_args_predictions.py CASES_TSV > apply_args_predictions.tsv
(CASES_TSV is the cases.tsv written by apply_args_cases.py.)

Prints a TSV with one column per <model>:<variant>. Classes are OK,
WRONG, ASAN, INV (an APPLY-INVARIANT check fired) or - (not modelled).

dev: the developer's model, from the message of 39e8fa1b ("Previously, the
  function had two issues: array->start was referenced without checking for
  fast array flag; the created arguments list was not sanity-checked for its
  length, which can be very large. The fix is to remove micro-optimization
  for arrays and introduce limit size for arguments list"). Read literally:
  on the base build every call with a slow array of nonzero length
  dereferences array->start (ASAN), a fast array is correct (holes are not
  mentioned), and an argument list that is "very large" is a problem
  (threshold not stated: not modelled below the limit); after the patch
  every array goes through the generic path and a list above 1024 is
  refused (the call throws, which differs from the reference engine).
ours: the invariant of the note. njs_function_prototype_apply() must give
  the callee `length` argument slots that hold the values the reference
  engine passes; it may take them from the array's element storage only for
  a flat array. Faulty states on the base build:
  S (slow array, nonzero stale length): start == NULL, so njs_function_frame()
    copies nothing and the callee frame holds `length` unwritten slots. A
    lambda callee reads them as undefined (the lambda frame sets every slot
    to the absent marker first), so its argument count is right and every
    value is undefined: WRONG against the reference. A native callee reads
    uninitialised frame memory: the class depends on the memory content
    (a wrong value or a fault), so the cell is - (not modelled).
  H (fast array with holes): the absent marker NJS_INVALID is passed as an
    argument. A lambda callee reads it as undefined (OK). A native callee
    that stores its arguments verbatim (Array.of, Array.prototype.push,
    Array called as a function) keeps the marker, a hole where the
    reference has undefined (WRONG). Natives that convert the argument
    (Math.max, String.prototype.concat, String.fromCharCode) are -.
  Engine limits on the base build, independent of the CVE: a call frame is
  allocated within NJS_MAX_STACK_SIZE (256 KiB), a lambda frame takes about
  48 bytes per argument (limit about 5400 arguments) and a native frame 16
  bytes (about 16000), so larger lists throw a RangeError (WRONG against the
  reference); the sizes 1024, 1025, 2000, 9000 and 40000 are far from both.
  The developer patch's limit of 1024 is a third rule: above it the call
  throws InternalError (WRONG against the reference, by design); the huge
  and poc_shape cases print only whether the call threw, so both engines
  agree there.
  Variants: before (base), after (developer patch), assert_before (base +
  scripts/apply_args_invariant.diff, which prints APPLY-INVARIANT and aborts
  when the argument vector handed to njs_function_frame() by apply has a
  NULL start with a nonzero count, or holds an absent marker),
  assert_after (developer patch + the same diff; never fires), H_limit
  (the developer patch without the limit hunk: only the removal of the array
  shortcut), H_fast (the developer patch without the shortcut removal: only
  the limit, placed in the generic path), min (the minimal patch of the note: the
  same diff as H_limit, run again for its stage logs; the column was added at
  02:37 EDT before that run), upstream_master.
  The group othr (other Array builtins on a slow array) is not modelled.

Exploratory observations before this file was written (not kept as logs):
44 probe scripts on the base and developer builds (slow arrays by freeze,
seal, defineProperty, index and length assignment, holes, array-likes,
sizes around the limits, the dataset PoC shape), and one run of the 53
valid-input cases on the base build (53 OK against the reference). The
predictions for the first 213 cases were written on 2026-10-14 at 02:10 EDT before
the `before` variant run of the other groups. The row of the dataset PoC (case
`poc`, an extra file) was added at 02:16 EDT, after the variants `before` and `after`
had run, from poc_before.log and poc_after.log. The four huge cases with
lengths 1e7 and 5e7 were added at 02:28 EDT after run 1 of the variants (kept in
logs/<instance>/variants_run1 and ablation_run1) with the same rule as the other
huge cases; their predictions were generated before run 2.
47 further cases of the group othr (containers lenbig and freeze, more methods on lenback)
were added at 02:36 EDT before any run of them; the group is not modelled. The expected values are the
Node.js v22.22.2 outputs (scripts/apply_args_expected.tsv).
"""
import csv
import sys

COLS = ["dev:before", "dev:after", "ours:before", "ours:after", "ours:assert_before", "ours:assert_after",
        "ours:H_limit", "ours:min", "ours:H_fast", "ours:upstream_master"]

STACK = {"lam": 5400, "native": 16000}
LIMIT = 1024
NATIVE_STORE = ("of", "push", "actor")


def num(n):
    try:
        return int(n)
    except ValueError:
        return None


def stack_ok(c):
    n = num(c["n"])
    return n <= (STACK["lam"] if c["callee"] == "lam" else STACK["native"])


def before(c):
    g, callee = c["group"], c["callee"]
    slow, holes = c["slow"] == "1", c["holes"] == "1"
    if g == "othr":
        return "-"
    if g in ("valid", "huge"):
        return "OK"
    if g == "poc":
        if c["case"] == "poc_shape":
            return "ASAN"  # the dataset report, observed before the predictions
        if slow:
            return "WRONG" if callee == "lam" else "-"
        return "-"
    if slow:
        return "WRONG" if callee == "lam" else "-"
    if holes:
        if callee == "lam":
            return "OK" if (g != "limit" or stack_ok(c)) else "WRONG"
        if g == "limit":
            return "-"
        return "WRONG" if callee in NATIVE_STORE else "-"
    if g == "limit":
        return "OK" if stack_ok(c) else "WRONG"
    return "OK"


def after(c):
    g = c["group"]
    if g == "othr":
        return "-"
    if g in ("valid", "huge"):
        return "OK"
    if g == "poc":
        return "OK" if c["case"] == "poc_shape" else "WRONG"
    if g == "limit":
        return "OK" if num(c["n"]) <= LIMIT else "WRONG"
    return "OK"


def assert_before(c):
    g = c["group"]
    if g in ("othr", "valid", "huge"):
        return before(c)
    if c["slow"] == "1" or c["holes"] == "1":
        return "INV"
    return before(c)


def h_limit(c):
    g = c["group"]
    if g == "othr":
        return "-"
    if g in ("valid", "huge", "slow", "hole"):
        return "OK"
    if g == "poc":
        return "OK" if c["case"] in ("poc_shape", "poc_len1500_obj") else "WRONG"
    return "OK" if stack_ok(c) else "WRONG"


def h_fast(c):
    g = c["group"]
    if g == "limit" and c["container"] == "like":
        return "OK" if num(c["n"]) <= LIMIT else "WRONG"
    return before(c)


def dev_before(c):
    g = c["group"]
    if g in ("othr", "huge"):
        return "-"
    if g == "valid":
        return "OK"
    if g == "poc":
        if c["case"] == "poc_shape":
            return "ASAN"
        return "ASAN" if c["slow"] == "1" else "-"
    if c["slow"] == "1":
        return "ASAN"
    if g == "limit":
        return "OK" if num(c["n"]) <= LIMIT else "-"
    return "OK"


def main(path):
    rows = list(csv.DictReader(open(path), delimiter="\t"))
    fn = {"dev:before": dev_before, "dev:after": after, "ours:before": before, "ours:after": after,
          "ours:assert_before": assert_before, "ours:assert_after": after, "ours:H_limit": h_limit,
          "ours:min": h_limit, "ours:H_fast": h_fast, "ours:upstream_master": after}
    w = sys.stdout
    w.write("case\t" + "\t".join(COLS) + "\n")
    for c in sorted(rows, key=lambda r: r["case"]):
        w.write(c["case"] + "\t" + "\t".join(fn[col](c) for col in COLS) + "\n")
    # the dataset PoC (case poc, run as an extra file): a sanitizer report on the base build,
    # none with the developer patch (poc_before.log, poc_after.log)
    poc = {"dev:before": "ASAN", "dev:after": "OK", "ours:before": "ASAN", "ours:after": "OK",
           "ours:assert_before": "INV", "ours:assert_after": "OK", "ours:H_limit": "OK",
           "ours:min": "OK", "ours:H_fast": "ASAN", "ours:upstream_master": "OK"}
    w.write("poc\t" + "\t".join(poc[col] for col in COLS) + "\n")


if __name__ == "__main__":
    main(sys.argv[1])
