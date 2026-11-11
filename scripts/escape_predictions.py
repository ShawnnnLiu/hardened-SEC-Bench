#!/usr/bin/env python3
"""Predictions for the cases of scripts/escape_cases.py (libredwg.cve-2020-21816).

Written 2026-10-13 at 15:51 EDT (19:51 UTC), before any run of the case
set on the base build or on any variant. Before that, the case script was
debugged once on the developer-patch build with two subsets (CASE_ONLY):
four unit cases (a_one_n01, a_second_n01, a_null_n1: OK; w_second_n01:
ASAN, htmlwescape is not changed by the developer patch) and the file
cases poc, blk12_* and txt_* (all OK). The dataset PoC had been run on the
base and on the developer-patch build on 2026-10-13 (poc_before.log,
poc_after.log).

Usage: python3 escape_predictions.py > escape_predictions.tsv

The TSV has one row per case and one column `<model>:<variant>` per model
and variant; a cell is OK, WRONG, ASAN, INV or - (no prediction). Variants:
  before           base commit 5f998146
  after            developer patch (7e4c59b6: htmlescape only)
  wfix             upstream e8c3edb9 alone (htmlwescape only)
  after_wfix       both (the SEC-bench gold patch)
  upstream_master  upstream master, whole tree
  assert_before    base + scripts/escape_invariant.diff
  assert_after     developer patch + scripts/escape_invariant.diff
  root             developer patch + e8c3edb9 (both functions)
  assert_root      root + scripts/escape_invariant.diff

The columns root and assert_root were added 2026-10-28, after the user
decided that the developer patch is incomplete for GH #182 and before
either variant ran. The diff of root is the programs/escape.c part of
variants/after_wfix.diff, byte for byte, so its predictions are those of
after_wfix, which had been observed (variants.log); the assert_root column
had no observation. The same day the user withdrew the decision, because
the htmlwescape defect is its own CVE (libredwg.cve-2020-21814, fixed by
e8c3edb9); the columns stay as the record of those runs
(predictions_root.log).

Hypothesis "ours" (invariants of htmlescape and htmlwescape, read from
programs/escape.c at 5f998146; the two functions have the same structure).
Let d be the output position, dest the start of the output buffer.
  I1  strcat (d, x) appends x at the first NUL at or after d and the loop
      then advances d by strlen (x). The output is correct only if the
      byte at d is NUL when strcat is called.
  I2  Before every append at least 9 bytes are free (the guard
      `off >= len - 8` grows the buffer), and the longest append is 9
      bytes (&#xFFFF; and its NUL), so the capacity logic holds.
  I3  Every input character is examined exactly once from the first.
The base code violates I1 and I3:
  - the buffer comes from malloc, so *d is undefined at the start; a plain
    character is stored with `*d++ = c` and leaves *d undefined again;
    sprintf and strcat leave a NUL at d. Under AddressSanitizer a fresh
    malloc block holds the fill byte 0xBE (max_malloc_fill_size 0x1000),
    so strcat reads on to the end of the block and writes past it: ASAN.
    State T is "*d is NUL": false at the start, true after a character
    >= 127 (sprintf) or one of the eight characters with an entity
    (strcat), false after a plain character, unchanged after a control
    character (dropped). A character with an entity met with T false is
    ASAN, at the first such character.
  - `while (*s++)` followed by `switch (*s)` examines the input from its
    second character on, so the first character never reaches the output:
    WRONG unless the first character produces no output (control character)
    or the input is empty.
Predictions of the base build: ASAN if T is false at some character with an
entity, else OK when the output equals the table applied to the whole
input, else WRONG. The developer patch makes htmlescape OK for every
input (calloc, NUL after every store, loop on *s); it does not touch
htmlwescape, which keeps its base class; e8c3edb9 does the reverse.
File cases: the same function of the strings the file holds. Every block
name and TEXT value of a file passes through the function, and all names
lose their first character on the base build (`*Model_Space` is printed
as `Model_Space`), so a file without a string that faults is WRONG on
the base build and a file with one is ASAN. The instrumentation
(escape_invariant.diff) makes the check fail before the strcat: INV
instead of ASAN. Upstream master (whole tree, 2026-10-12) rewrote
the function and changed the table for control characters, DEL and
bytes >= 128 (control characters become &#x..;, bytes pass through a
codepage conversion), so it is predicted OK only for inputs of printable
ASCII and the eight characters, - otherwise.
The reproducers of #182 (class by sanitizer report only): r1 and r4 are
fixed before the base commit (b7fa220b, "Fixes Case 1 of GH #182", skip a
NULL text_value), r5 has no prediction; r2, r3 and r7 reach htmlescape,
r6 and r8 htmlwescape.

Hypothesis "dev" (the developer's own explanation): the message of
7e4c59b6 reads "htmlescape: fix off-by-one and overflow. need \\0
termination to do strcat. don't skip the very first char. Fixes GH #182".
It names the two defects of I1 and I3, so for htmlescape cases it predicts
as "ours"; it says nothing about htmlwescape (no prediction); and
"Fixes GH #182" claims that all eight reports of the issue are fixed
after the commit.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import escape_cases as ec  # noqa: E402

OURS = ["before", "after", "wfix", "after_wfix", "upstream_master",
        "assert_before", "assert_after", "root", "assert_root"]
DEV = ["before", "after"]
FIXED = {  # functions repaired by the variant: e = htmlescape, w = htmlwescape
    "before": "", "after": "e", "wfix": "w", "after_wfix": "ew",
    "assert_before": "", "assert_after": "e", "root": "ew", "assert_root": "ew",
}


def kind(c):
    if chr(c) in ec.ENTITY:
        return "S"
    if c >= 127:
        return "H"
    if c >= 20:
        return "P"
    return "C"


def spec_of(us):
    return "".join(ec.spec_unit(c) for c in us)


def base_class(us):
    """Class of one call on the base build: ASAN, OK or WRONG."""
    t = False
    for c in us[1:]:
        k = kind(c)
        if k == "S":
            if not t:
                return "ASAN"
            t = True
        elif k == "H":
            t = True
        elif k == "P":
            t = False
    return "OK" if spec_of(us[1:]) == spec_of(us) else "WRONG"


def resolve(cls, variant, fn):
    """Class of a call to function fn (e or w) with base class cls."""
    if variant == "upstream_master" or fn in FIXED.get(variant, ""):
        return "OK"
    if cls == "ASAN" and variant.startswith("assert"):
        return "INV"
    return cls


def master_ok(us):
    return all(kind(c) in "PS" for c in us)


def unit_pred(case, model, variant):
    if case["text"] is None:
        return "OK"
    fn = "e" if case["func"] in "aA" else "w"
    if model == "dev" and fn == "w":
        return "-"
    us = ec.units(case["text"], fn == "w")
    if model == "dev":
        return "OK" if variant == "after" else base_class(us)
    if variant == "upstream_master":
        return "OK" if master_ok(us) else "-"
    return resolve(base_class(us), variant, fn)


# class of the dataset-independent reproducers on the base build and the
# function that causes it (r1, r4: fixed before the base commit; r5: unknown)
ISSUE = {1: ("OK", "e"), 2: ("ASAN", "e"), 3: ("ASAN", "e"), 4: ("OK", "e"),
         5: (None, "e"), 6: ("ASAN", "w"), 7: ("ASAN", "e"), 8: ("ASAN", "w")}


def file_pred(case, model, variant):
    kind_ = case["kind"]
    if kind_ == "issue":
        base, fn = ISSUE[case["report"]]
        if base is None:
            return "-"
        if model == "dev":
            if variant == "before":
                return base if case["report"] in (2, 3, 6, 7, 8) else "-"
            return "OK"
        return resolve(base, variant, fn)
    value = "*P`per_Space" if kind_ == "poc" else case["value"]
    us = ec.units(value, False)
    fault = base_class(us) == "ASAN"
    # all other names of the file lose their first character on the base build
    cls = "ASAN" if fault else "WRONG"
    if model == "dev":
        return "OK" if variant == "after" else cls
    if variant == "upstream_master" and not master_ok(us):
        return "-"
    return resolve(cls, variant, "e")


def main():
    cases = ec.unit_cases() + ec.file_cases()
    cols = [("ours", v) for v in OURS] + [("dev", v) for v in DEV]
    print("case\t" + "\t".join("%s:%s" % c for c in cols))
    for case in cases:
        pred = unit_pred if "func" in case else file_pred
        print(case["name"] + "\t" + "\t".join(pred(case, m, v) for m, v in cols))


if __name__ == "__main__":
    main()
