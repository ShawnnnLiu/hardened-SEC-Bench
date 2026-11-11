"""Predicted result class per case for njs.cve-2022-34029, under two models.

Usage: python3 awaiterr_predictions.py CASEDIR > awaiterr_predictions.tsv

Reads CASEDIR/cases.tsv (written by scripts/awaiterr_cases.py) and prints a
TSV with a header `case<TAB><model>:<variant>...` and one row per case, plus
the dataset PoC (case "poc"). A cell is OK, WRONG, ASAN, INV or - (no
prediction). scripts/check_predictions.py compares it with the case logs.

The predictions were written before any variant of the faulty-state cases
was run, from the code of the base commit (d493f891) and the following
observations, which are listed here and are not kept as logs: the PoC runs
of the build stages; the probes p1-p4, the host-shape probes and the
top-level probe on the base and developer-patch builds (about a dozen short
programs); and the calibration run of the 14 control and valid cases on the
base build (all equal to the reference).

Models.

ours (the invariant of the note): njs_vmcode_interpreter() must reach the
`error:` label (which unwinds the active frames) on every NJS_ERROR exit of
the opcode loop. The NJS_VMCODE_AWAIT case returns njs_vmcode_await()'s
NJS_ERROR directly, so a synchronous await failure leaves the async
function's frame un-unwound. The triggers that make njs_vmcode_await() return
NJS_ERROR synchronously are `ctor` (a native promise whose `constructor`
accessor throws, read while resolving the awaited value) and `tdz` (an
uninitialised binding, njs_scope_valid_value returns NULL). The symptom in
the caller is a wrong result or a sanitizer report depending on the frame
and heap state, so `ours` does not predict the base-build class of a case
that reaches the faulty state (-); it predicts OK for the cases that do not
(controls, valid, and the top-level cases, which fail the await with no
caller frame to corrupt). The developer patch routes the AWAIT error through
`error:`, so `ours` predicts OK for every case after the patch, at the
CVE_NVD base and at master. On assert_before the STACK-INVARIANT check fires
when a synchronous await failure returns without unwinding, which is every
ctor/tdz case (the top-level ones included: the invariant is violated there
too, the symptom only being benign) and the PoC; on assert_after the check is
unreachable (the patch takes `goto error` first), so it fires on no case.

dev (the developer's model, commit d09868bc): "while interpreting a user
function, njs_vmcode_interpreter() might return prematurely when an error
happens in await instruction ... the current frame has to be unwound (or
exception caught) first", fixed by exiting "through only 5 appropriate exit
points". The model names the mechanism exactly (a premature return of the
await error), and the reported symptom is a crash, so the literal reading
predicts a sanitizer report (ASAN) for every synchronous await failure on the
base and OK after. It does not distinguish the shapes whose symptom is a
wrong result from those that crash, nor the top-level shapes whose violation
is benign; those are the observations it does not predict.
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
    # the dataset PoC: a ctor-trigger shape in a deep context, faulty
    cs.append(("poc", "poc", "ctor", "1"))
    return cs


def predict(group, trigger, faulty):
    reaches = trigger in ("ctor", "tdz")   # a synchronous await failure
    p = {}
    # ours
    p["ours:before"] = "-" if faulty == "1" else "OK"
    p["ours:cvenvd_base"] = p["ours:before"]
    p["ours:after"] = "OK"
    p["ours:cvenvd_after"] = "OK"
    p["ours:upstream_master"] = "OK"
    p["ours:assert_before"] = "INV" if reaches else "OK"
    p["ours:assert_after"] = "OK"
    # dev: literal crash model
    p["dev:before"] = "ASAN" if reaches else "OK"
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
