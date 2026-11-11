"""Predicted result class of every scripts/promise_absent_cases.py case
(and the dataset PoC) under each hypothesis, for
scripts/check_predictions.py (njs.cve-2022-32414).

Prints a TSV with one column per <model>:<variant>. Classes are OK,
WRONG, ASAN, INV (INVALID-INVARIANT check fired) or - (not modelled).

dev: the developer's model, from the message of 31ed93a5 ("while
  iterating over an array-like object the methods may be resolved with
  INVALID values. INVALID value is a special internal type which should
  never be visible by ordinary functions. The fix is to ensure that absent
  elements are represented by undefined value", Promise.all, allSettled,
  any and race) and the issue it closes (#483: await of the race result
  followed by a for-in crashes). Read literally: on the base build an
  aggregate whose input has an absent element is resolved with (race,
  any: when the first element is absent) or contains (all, allSettled:
  any absent element) an INVALID value, which every consumer sees; a
  consumer that awaits and then runs a for-in crashes (ASAN) as in the
  issue, every other consumer gets a wrong value (WRONG). The input length
  plays no role. After the patch every absent element is undefined (OK).
  The model says nothing about AggregateError or non-promise operations (-).
ours: H1, the root cause. njs_object_iterate() represents an absent
  index of an array-like (no own or inherited property; an array hole) by
  the internal NJS_INVALID marker, and a handler that forwards the entry
  to JavaScript must replace it with undefined first. The four Promise
  handlers forward it to C.resolve(), so the aggregate fulfils with
  (race, any) or stores (all, allSettled) an INVALID value. Its
  observable effects depend on the consumer:
  - lambda parameters, var and let reads, arguments[0] and
    JSON.stringify convert an INVALID value to undefined (OK);
  - a native handler that converts its argument to a primitive (String)
    fails with a TypeError (WRONG);
  - njs_await_fulfilled() writes the value into vm->retval; the next
    for-in's PROPERTY_FOREACH stores its iterator pointer into
    vm->retval.data without setting the type, the iterator slot keeps the
    INVALID type, the operand fetch of PROPERTY_NEXT resets it to
    undefined and the pointer to NaN bits, and next->index faults (ASAN):
    consumers forin, pocshape and freeze (Object.freeze returns its
    INVALID argument, so the promise it resolves is INVALID again); chain
    converts in the lambda (OK);
  - Promise.all stores the marker as a hole in the result array (WRONG
    where show() sees the array; String() and JSON.stringify print a hole
    and undefined alike, and vals reads each element by index, OK);
    Promise.allSettled stores it as the value property of the result
    object, which reads as undefined (OK), but Object.values() copies it
    into an array as a hole (vals: WRONG).
  race and any with only later absent elements settle with the present
  first element (OK).
  H2, the residual #538 (not this CVE): an array-like longer than
  NJS_ARRAY_FAST_OBJECT_LENGTH (1024) takes the njs_array_indices() path
  and absent indices are never visited, so all, allSettled and any
  resolve or reject with a pre-allocated, uninitialised result array
  (ASAN) and race never settles (WRONG), with or without the developer
  patch; e008f7ae allocates the array empty (all, allSettled, any:
  WRONG, length 0 or a rejection; race: WRONG).
  H3, the residual AggregateError: njs_iterator_to_array() stores the
  marker into the errors array as a hole (WRONG for absent inputs), with
  or without the developer patch; the synthetic handler fix (agg) repairs
  it. For agg_big, njs_iterator_to_array() has the H2 defect (1025
  pre-allocated slots, none visited): ASAN on every build but master,
  which allocates the array empty (WRONG, length 0).
  H4: no operation outside the Promise machinery leaves an INVALID value
  in vm->retval, so the src_* cases are OK on every build.
  Variants: before (base), after (developer patch), sink (upstream
  982100ba alone: PROPERTY_FOREACH tags the iterator slot, so the for-in
  no longer crashes but the WRONG cases stay), after_sink (developer
  patch + 982100ba), fix538 / after_fix538 (e008f7ae alone / with the
  developer patch), agg / after_agg (iterator_to_array_handler fix alone /
  with the developer patch), assert_before / assert_after (the
  INVALID-INVARIANT checks of scripts/promise_absent_invariant.diff on the
  base / developer-patch build: they fire when an INVALID value reaches
  Promise.resolve, a resolving function, njs_await_fulfilled() or a
  PROPERTY_FOREACH, so on the base build every case whose aggregator
  meets an absent element in the fast path is INV whatever its consumer),
  cvenvd_base / cvenvd_after (the CVE_NVD base commit 2e00e954 without /
  with the developer patch, same as before / after), upstream_master
  (master: the developer checks, e008f7ae and 982100ba present, H3 open).

Observations made before this file was written: 33 exploratory scripts
on the base build (not kept as logs) covering race and any of {length:1},
[,] and await + for-in (ASAN), Promise.all({length:2}) (holes),
allSettled({length:1}) (value reads as undefined), then(String)
(TypeError), let/var after await (undefined), Promise.all({length:1025})
(ASAN), AggregateError({length:2}) (holes), apply, bind and call spread
with holes (call spread is not supported by njs at the base commit); and
the calibration run of the 273 valid-input cases (all OK). Written on
2026-10-13 before any variant run of the absent-element and src_* cases.
The vals consumer and its predictions were added at 01:30 EDT, after a
first variant run had been stopped during the build of its first variant
(before), before any case had run; the 30 valid-input vals cases were not
calibrated separately and are checked by the before run.
"""
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from promise_absent_cases import cases  # noqa: E402

COLS = ["dev:before", "dev:after", "ours:before", "ours:after", "ours:sink", "ours:after_sink",
        "ours:fix538", "ours:after_fix538", "ours:agg", "ours:after_agg",
        "ours:assert_before", "ours:assert_after", "ours:cvenvd_base", "ours:cvenvd_after",
        "ours:upstream_master"]

AWAIT_FORIN = {"forin", "pocshape", "chain", "freeze"}


def dev(method, absent, consumer, after):
    if absent == "none" or after:
        return "OK"
    if method in ("race", "any") and absent == "later":
        return "OK"
    return "ASAN" if consumer in AWAIT_FORIN else "WRONG"


def h1_base(method, absent, consumer):
    """Base-build class of a fast-path promise case under H1."""
    if absent == "none":
        return "OK"
    if method in ("race", "any"):
        if absent == "later":
            return "OK"
        if consumer in ("forin", "pocshape", "freeze"):
            return "ASAN"
        if consumer == "str":
            return "WRONG"
        return "OK"
    if method == "all":
        return "OK" if consumer in ("str", "json", "pocshape", "vals") else "WRONG"
    return "WRONG" if consumer == "vals" else "OK"  # allSettled


def h1_sink(method, absent, consumer):
    b = h1_base(method, absent, consumer)
    return "OK" if b == "ASAN" else b


def big(method, fixed538):
    if fixed538 or method == "race":
        return "WRONG"
    return "ASAN"


def promise_row(method, absent, consumer):
    if absent == "big":
        b, f = big(method, False), big(method, True)
        return [dev(method, absent, consumer, False), "OK",
                b, b, b, b, f, f, b, b, b, b, b, b, f]
    base = h1_base(method, absent, consumer)
    sink = h1_sink(method, absent, consumer)
    inv = "INV" if absent in ("first", "later") else "OK"
    return [dev(method, absent, consumer, False), dev(method, absent, consumer, True),
            base, "OK", sink, "OK", base, "OK", base, "OK", inv, "OK", base, "OK", "OK"]


def main():
    w = csv.writer(sys.stdout, delimiter="\t", lineterminator="\n")
    w.writerow(["case"] + COLS)
    for name, method, inp, consumer, absent, _src, _body in cases():
        if method in ("race", "any", "all", "allSettled"):
            w.writerow([name] + promise_row(method, absent, consumer))
        elif method == "AggregateError" and absent == "big":
            # njs_iterator_to_array() pre-allocates 1025 slots and the slow
            # path visits none (H2 in AggregateError); master allocates empty
            w.writerow([name, "-", "-"] + ["ASAN"] * 12 + ["WRONG"])
        elif method == "AggregateError":
            c = "OK" if absent == "none" else "WRONG"
            w.writerow([name, "-", "-", c, c, c, c, c, c, "OK", "OK", c, c, c, c, c])
        else:
            w.writerow([name, "-", "-"] + ["OK"] * (len(COLS) - 2))
    # dataset PoC: Promise.race(Float64Array), await, for-in
    w.writerow(["poc", "ASAN", "OK", "ASAN", "OK", "OK", "OK", "ASAN", "OK", "ASAN", "OK",
                "INV", "OK", "ASAN", "OK", "OK"])


if __name__ == "__main__":
    main()
