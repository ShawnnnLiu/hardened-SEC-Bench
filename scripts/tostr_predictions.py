"""Predicted result class per case for njs.cve-2022-29369, under two models.

Usage: python3 tostr_predictions.py CASEDIR > tostr_predictions.tsv

Reads CASEDIR/cases.tsv (written by scripts/tostr_cases.py) and prints a TSV
with a header `case<TAB><model>:<variant>...` and one row per case, plus the
dataset PoC (case "poc"). A cell is OK, WRONG, ASAN, INV or - (no
prediction). scripts/check_predictions.py compares it with the case logs.

The predictions were written before any njs_run_variant.sh variant was run,
from the code of the image tree (7bd570b3) and the following observations,
listed here and not kept as logs: the PoC runs of the build stages
(poc_before.log, poc_after.log); a probe showing njs evaluates the method
key twice on the not-a-function path (once at the property access, once to
build the error message) while the reference engine evaluates it once; and a
calibration run of all 25 cases on the base and developer-patch builds in the
-base and -dev containers. The faulty-case base symptom is left unpredicted
(-): the invariant fixes which exit the conversion error takes and whether
the current frame's catch runs, not whether the stale frame later yields a
wrong result or a sanitizer report, which depends on the surrounding frame
and heap (the calibration showed both: WRONG for the single-call shapes,
ASAN for loop2 and the PoC).

Models.

ours (the invariant of the note): njs_vmcode_interpreter() must reach the
`error:` label (which offers the exception to the current frame's catch and
unwinds the active frames) on every NJS_ERROR exit of the opcode loop. The
base NJS_VMCODE_METHOD_FRAME not-a-function branch returns NJS_ERROR directly
when the key-to-string conversion fails while building the "...is not a
function" TypeError (njs_value_to_key at base line 757), so the current
frame's catch is skipped and its frame is left un-unwound. This is reached
only when the key's first conversion (the property access) succeeds and its
second (the error message) fails; a failure on the first conversion fails at
the property access, which already reaches `error:` (a control), and a key
that always converts yields a normal TypeError, also at `error:` (a control).
`ours` therefore predicts OK for every control and valid case on every build,
and does not predict the base-build symptom of a faulty case (-). The
developer patch routes the error through `error:`, so `ours` predicts OK for
every case after the patch, at the CVE_NVD base and at master. On
assert_before the STACK-INVARIANT check fires (and aborts) when a second-
conversion failure reaches the non-unwinding return, which is every faulty
case; on assert_after the guard is unreachable (the patch takes `goto error`
first), so it fires on no case.

dev (the developer's model, commit 222d6fdc): njs_vmcode_interpreter() "might
return prematurely when an error happens", which is wrong because the current
frame has to be unwound (or the exception caught) first; fixed by leaving
through only five exit points. The model names the mechanism exactly (a
premature return of an opcode error), and the reported symptom is a crash, so
the literal reading predicts a sanitizer report (ASAN) for every faulty case
on the base and OK after. It does not distinguish the shapes whose symptom is
a wrong result (a skipped same-frame catch) from those that crash.
"""
import sys
from pathlib import Path

VARIANTS = ["before", "after", "assert_before", "assert_after",
            "cvenvd_base", "cvenvd_after", "upstream_master"]


def rows(casedir):
    lines = [l.rstrip("\n").split("\t") for l in open(Path(casedir) / "cases.tsv")]
    head = lines[0]
    gi, ti, fi = head.index("group"), head.index("trigger"), head.index("faulty")
    cs = []
    for r in lines[1:]:
        cs.append((r[0], r[gi], r[ti], r[fi]))
    # the dataset PoC: a faulty METHOD_FRAME shape in a deep context
    cs.append(("poc", "poc", "unittest", "1"))
    return cs


def predict(group, trigger, faulty):
    p = {}
    # ours
    p["ours:before"] = "-" if faulty == "1" else "OK"
    p["ours:cvenvd_base"] = p["ours:before"]
    p["ours:after"] = "OK"
    p["ours:cvenvd_after"] = "OK"
    p["ours:upstream_master"] = "OK"
    p["ours:assert_before"] = "INV" if faulty == "1" else "OK"
    p["ours:assert_after"] = "OK"
    # dev: literal crash model
    p["dev:before"] = "ASAN" if faulty == "1" else "OK"
    p["dev:after"] = "OK"
    return p


def main(casedir):
    cs = rows(casedir)
    cols = []
    for m in ("ours", "dev"):
        for v in VARIANTS:
            c = f"{m}:{v}"
            if c in ("dev:assert_before", "dev:assert_after",
                     "dev:cvenvd_base", "dev:cvenvd_after", "dev:upstream_master"):
                continue
            cols.append(c)
    print("case\t" + "\t".join(cols))
    for name, group, trigger, faulty in cs:
        p = predict(group, trigger, faulty)
        print(name + "\t" + "\t".join(p.get(c, "-") for c in cols))


if __name__ == "__main__":
    main(sys.argv[1])
