#!/usr/bin/env python3
"""Predictions for the cases of scripts/escape_cases.py (libredwg.cve-2020-21814).

This file was written on 2026-10-28 before the before variant ran
(02:57 EDT, 06:57 UTC). No variant of this instance had run. The stage
build_before of this instance was running; poc_before had not run.

Known results. The case script, the base tree (5f998146) and the diffs of
four of the variants below are those of libredwg.cve-2020-21816, whose
logs (logs/libredwg.cve-2020-21816/variants.log, variants/*.cases.log,
built from the image of that instance) show the class of every case:
its variants before, wfix, after, after_wfix, assert_before, assert_after
and upstream_master (f860b0fb) correspond to before, after,
cve21816_alone, after_cve21816, assert_before, assert_after (except that
the instrumented diff is applied to e8c3edb9 here) and upstream_master
here. Those results were known when this file was written. The case
`poc` differs: here it is the dataset PoC of this instance, reproducer r8
of LibreDWG/libredwg#182 (byte-identical to issue182_r8), copied to
/testcase/poc.dwg by scripts/wescape_make_built_image.sh, and it is
checked against the dwgread reference (issue182_r8 is not); no build had
run it with that check.

Usage: python3 wescape_predictions.py > wescape_predictions.tsv

The TSV has one row per case and one column `<model>:<variant>` per model
and variant; a cell is OK, WRONG, ASAN, INV or - (no prediction). Variants:
  before           base commit 5f998146 (the image tree)
  after            developer patch e8c3edb9 (patches/libredwg.cve-2020-21814.diff,
                   htmlwescape only)
  cve21816_alone   7e4c59b6 alone (patches/libredwg.cve-2020-21816.diff,
                   htmlescape only), the developer patch of libredwg.cve-2020-21816
  after_cve21816   7e4c59b6, then e8c3edb9 (the changed lines of the
                   SEC-bench gold patch)
  assert_before    base + scripts/escape_invariant.diff
  assert_after     developer patch + scripts/escape_invariant.diff
  upstream_master  upstream master, whole tree (4fa78a09, 2026-10-27;
                   programs/escape.c, escape.h and dwg2SVG.c unchanged
                   since f860b0fb)

Hypothesis "ours" (invariants of htmlwescape, read from programs/escape.c
at 5f998146, lines 71-120; htmlescape, lines 26-69, has the same
structure and the same defects, which are the reported failure of
libredwg.cve-2020-21816). Let d be the output position, dest the start of
the output buffer, and a unit one UTF-16 code unit of the input.
  I1  strcat (d, x) appends x at the first NUL at or after d and the loop
      then advances d by strlen (x). The output is correct only if the
      byte at d is NUL when strcat is called.
  I2  Before every append at least 9 bytes are free (len starts at the
      number of units plus 16 and grows by 16 when off >= len - 8), and
      the longest append is 9 bytes (&#xFFFF; and its NUL): the capacity
      logic holds.
  I3  Every unit of the input is examined exactly once, from the first.
The base code violates I1 and I3:
  - dest comes from malloc, so *d is undefined at the start; a plain unit
    is stored with `*d++ = *wstr` and leaves *d undefined again; sprintf
    and strcat leave a NUL at d. Under AddressSanitizer a fresh block
    holds the fill byte 0xBE, so strcat reads on to the end of the block
    and appends past it: ASAN. State T is "*d is NUL": false at the start,
    true after a unit >= 127 (sprintf) or one of the eight characters
    with an entity (strcat), false after a plain unit (20 to 126), and
    unchanged after a unit below 20 (dropped). A unit with an entity met
    with T false is ASAN, at the first such unit.
  - `while (*wstr++)` followed by `switch (*wstr)` examines the input from
    its second unit on, so the first unit never reaches the output: WRONG
    unless the first unit produces no output (below 20) or the input is
    empty.
Predictions of the base build: ASAN if T is false at some unit with an
entity, else OK when the output equals the table applied to the whole
input, else WRONG. The same machine over bytes gives the class of an
htmlescape case (a_*). The developer patch e8c3edb9 (calloc, a NUL after
the plain store, after realloc and after sprintf, the loop on *wstr with
wstr++ at the end of the body) makes htmlwescape OK for every input and
does not touch htmlescape, which keeps its base class; 7e4c59b6 does the
reverse; both together make every escape case OK.
File cases: the same function of the strings the file holds. Files of
R2007 and later (AC1021 on) use htmlwescape, older files htmlescape
(programs/dwg2SVG.c lines 132-135 and 397-400). The blk12 and txt files
are R2000 (htmlescape): every name loses its first character on the base
build, so a file without a string that faults is WRONG on the base build
and a file with one is ASAN. The PoC (`poc`, reproducer r8) holds a TEXT
value that faults in htmlwescape (the dataset report: strcat <-
htmlwescape <- output_TEXT, 42-byte block, so 26 units): ASAN on the base
build and on cve21816_alone, OK with e8c3edb9, on the assumption that the
strings that dwgread -O json reads from the file are those that dwg2SVG
passes to htmlwescape (the same decoder) or cannot be read (no reference:
OK). The instrumentation (escape_invariant.diff) makes the check fail
before the strcat: INV instead of ASAN, in either function. Upstream
master (escape.c rewritten 2026-06-28, table changed for units below 20,
DEL and units of 128 or more) is predicted OK only for inputs of
printable ASCII and the eight characters, - otherwise, and - for `poc`,
whose strings are not known.
The reproducers of #182 (class by sanitizer report only): r1 and r4 are
fixed before the base commit (b7fa220b), r5 (output_TEXT, dwg2SVG.c) has
no prediction; r2, r3 and r7 reach htmlescape, r6 and r8 htmlwescape.

Hypothesis "dev" (the developer's own explanation): the message of
e8c3edb9 reads "htmslescape: fix off-by-one and overflow. ditto. Fixes GH
#182". "ditto" repeats for htmlwescape the explanation of 7e4c59b6, one
commit earlier ("need \\0 termination to do strcat. don't skip the very
first char."), that is I1 and I3 of the wide function, so for htmlwescape
cases (w_*, r6, r8, poc) it predicts as "ours" on before and OK after the
commit. "Fixes GH #182" claims that the reports of the issue are fixed
after the commit on the developer's tree, which contains 7e4c59b6; it is
applied to after_cve21816, the tree with both commits, where the
reproducers r1 to r4 and r6 to r8 are predicted OK. The message makes no
statement about htmlescape on a tree without 7e4c59b6 (a_*, blk12_*,
txt_*, and r2, r3, r7 on before and after): -. r5 has no prediction, as in
libredwg.cve-2020-21816 (its report names output_TEXT, no escape
function).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import escape_cases as ec  # noqa: E402

OURS = ["before", "after", "cve21816_alone", "after_cve21816",
        "assert_before", "assert_after", "upstream_master"]
DEV = ["before", "after", "after_cve21816"]
FIXED = {  # functions repaired by the variant: e = htmlescape, w = htmlwescape
    "before": "", "after": "w", "cve21816_alone": "e", "after_cve21816": "ew",
    "assert_before": "", "assert_after": "w",
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
    fn = "e" if case["func"] in "aA" else "w"
    if model == "dev" and fn == "e":
        return "-"
    if case["text"] is None:
        return "OK"
    us = ec.units(case["text"], fn == "w")
    if model == "dev":
        return base_class(us) if variant == "before" else "OK"
    if variant == "upstream_master":
        return "OK" if master_ok(us) else "-"
    return resolve(base_class(us), variant, fn)


# class of the reproducers on the base build and the function that causes
# it (r1, r4: fixed before the base commit; r5: unknown)
ISSUE = {1: ("OK", "e"), 2: ("ASAN", "e"), 3: ("ASAN", "e"), 4: ("OK", "e"),
         5: (None, "e"), 6: ("ASAN", "w"), 7: ("ASAN", "e"), 8: ("ASAN", "w")}


def file_pred(case, model, variant):
    kind_ = case["kind"]
    if kind_ in ("issue", "poc"):
        base, fn = ISSUE[case["report"] if kind_ == "issue" else 8]
        if base is None:
            return "-"
        if model == "dev":
            if variant == "after_cve21816":
                return "OK"
            if fn == "e":
                return "-"
            return base if variant == "before" else "OK"
        if kind_ == "poc" and variant == "upstream_master":
            return "-"
        return resolve(base, variant, fn)
    us = ec.units(case["value"], False)
    # all other names of the file lose their first character on the base build
    cls = "ASAN" if base_class(us) == "ASAN" else "WRONG"
    if model == "dev":
        return "-"
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
