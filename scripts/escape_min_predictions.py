#!/usr/bin/env python3
"""Predictions for the ablation of the candidate minimal patch (min10) of
libredwg.cve-2020-21816, for the cases of scripts/escape_cases.py.

Written 2026-10-13 at 17:40 EDT (21:40 UTC), before any variant M1 to M10
was built or run and before the groups of the ablation of the developer patch
(min10 among them) had run; the single-line variants L1 to L39 had run. The
predictions for the groups are in scripts/escape_ablation_predictions.py.

Usage: python3 escape_min_predictions.py > escape_min_predictions.tsv

min10 is the developer patch without the reformatting of the case lines, the
`end` pointer and the two redundant NUL stores. Its 10 changed lines, numbered
as in `scripts/ablate_patch.py` applied to patches/*.min.diff, are
  1  -  d = malloc (len);             2  +  d = calloc (len, 1);
  3  -  while (*s++)                  4  +  while (*s)
  5  -  *d++ = *s;                    6  +  {   7  +  *d++ = *s;   8  +  *d = 0;   9  +  }
  10 +  s++;
Variant Mi is min10 without changed line i (a dropped '-' line stays in the
file, a dropped '+' line is removed). Predictions from reading the code:
  M1  malloc and calloc both stay: the first block leaks; every call of
      htmlescape that allocates is reported by LeakSanitizer (class ASAN).
  M2  neither call stays: d is uninitialised; no prediction.
  M3  `while (*s++)` stays as an outer loop around `while (*s)`: the first
      character is consumed by the outer test, the inner loop handles the
      rest: no fault (calloc, NUL stores), the first character is lost.
  M4  no loop: the body runs once, so only the first character is escaped.
  M5  the original store stays and the braces follow: every character that
      reaches `default:` is stored twice (plain) or followed by its raw
      byte (127 or more, control); entity characters are unaffected.
  M6  syntax error (the brace opens nothing): the build fails.
  M7  the store inside the braces is missing: plain characters are lost.
  M8  no NUL after the plain store: state machine of
      escape_ablation_predictions.py (init NUL, plain leaves it undefined).
  M9  syntax error (unclosed brace): the build fails.
  M10 no `s++`: the loop never advances; every non-empty input hangs and
      the case runner reports WRONG timeout (CASE_TIMEOUT 5 s).
htmlwescape is not changed by any of these (base class). File cases: the
class follows the injected string and the other names of the file as in
escape_ablation_predictions.py; reproducers of #182 only where the class
does not depend on their strings. Cells for M2, M6 and M9 are - .
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import escape_ablation_predictions as ap  # noqa: E402
import escape_cases as ec  # noqa: E402
import escape_predictions as ep  # noqa: E402

VARIANTS = ["M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9", "M10"]


def unit_class(us, v):
    """Class of one htmlescape call on the units us under variant v."""
    spec_all = ep.spec_of(us)
    if v == "M1":
        return "ASAN"
    if v == "M3":
        return ap.machine(us, True, True, True, False)
    if v == "M4":
        return "OK" if ep.spec_of(us[:1]) == spec_all else "WRONG"
    if v == "M5":
        return "OK" if all(ep.kind(c) == "S" for c in us) else "WRONG"
    if v == "M7":
        return "OK" if all(ep.kind(c) != "P" for c in us) else "WRONG"
    if v == "M8":
        return ap.machine(us, False, True, False, False)
    if v == "M10":
        return "OK" if not us else "WRONG"
    return "-"


def pred(case, v):
    if v in ("M2", "M6", "M9"):
        return "-"
    if "func" in case:
        if case["text"] is None:
            return "OK"
        if case["func"] in "wW":
            return ep.base_class(ec.units(case["text"], True))
        return unit_class(ec.units(case["text"], False), v)
    if case["kind"] == "issue":
        base_cls, fn = ep.ISSUE[case["report"]]
        if base_cls is None or v in ("M8", "M10"):
            return "-"
        if fn == "w":
            return base_cls
        if base_cls == "OK":
            return "-" if v == "M1" else "OK"
        return "ASAN" if v == "M1" else "OK"
    value = "*P`per_Space" if case["kind"] == "poc" else case["value"]
    us = ec.units(value, False)
    if v == "M1":
        return "ASAN"
    if v == "M8":
        cls = ap.machine(us, False, True, False, False)
        return "ASAN" if cls == "ASAN" else "OK"
    if v == "M10":
        return "WRONG"
    # M3, M4, M5, M7 never fault; the other names of the file lose or gain characters
    return "WRONG"


def main():
    cases = ec.unit_cases() + ec.file_cases()
    print("case\t" + "\t".join("ours:" + v for v in VARIANTS))
    for case in cases:
        print(case["name"] + "\t" + "\t".join(pred(case, v) for v in VARIANTS))


if __name__ == "__main__":
    main()
