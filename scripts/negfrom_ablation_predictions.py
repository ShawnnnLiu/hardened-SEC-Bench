"""Predicted result class of every scripts/negfrom_cases.py case for the
ablation variants of the source part of the developer patch of
njs.cve-2022-31307, for scripts/check_predictions.py.

Usage: python3 negfrom_ablation_predictions.py > negfrom_ablation_predictions.tsv

Written on 2026-10-14 at about 02:28 EDT, before any ablation variant ran.

The source part of the developer patch has 9 changed lines in one hunk of
njs_object_iterate_reverse() (UTF-8 branch), numbered as by
scripts/ablate_patch.py:
  1  - p = njs_string_offset(string_prop.start, end, from);
  2  - p = njs_utf8_next(p, end);
  3  - (blank)
  4  + p = NULL;
  5  + if (i > to) {
  6  +     p = njs_string_offset(string_prop.start, end, from);
  7  +     p = njs_utf8_next(p, end);
  8  + }
  9  + (blank)
Dropping a '-' line keeps the original line; dropping a '+' line removes it.
The hunk is applied to the base tree; the test hunk is not part of the
reduction (worklist tier 3_drop_test_hunks).

ours, by variant (the cases that take the UTF-8 branch with i > to are the
60 lio cases that do not reach the faulty state and the 12 rr cases on UTF-8
strings; the 77 violating cases take it with i <= to):
  L1  keeps the old unguarded call: the faulty state is reached again, so
      the violating cases behave as on the base build (not predicted, see
      negfrom_predictions.py) and every other case is OK.
  L2  keeps the old `p = njs_utf8_next(p, end)` before `p = NULL`, so that
      njs_utf8_next() reads through an uninitialised pointer for every UTF-8
      string input; nothing is predicted for the UTF-8 cases (lio, rr UTF-8,
      the PoC), everything else is OK.
  L4  drops `p = NULL;`: p is read only in the loop, which runs exactly when
      the guard holds, so every case is OK as with the developer patch (the
      secb build passes -w; the project's default flags are a separate
      check).
  L5, L8  drop the opening or the closing line of the new block and do not
      compile; no cases log.
  L6  drops the guarded njs_string_offset(): the guard then calls
      njs_utf8_next(NULL, end) for every UTF-8 string input with i > to; those
      cases are predicted ASAN (a NULL read), the violating cases are OK.
  L7  drops the guarded njs_utf8_next(): p stays at the start of character
      `from`, the loop then yields the previous character; the cases that
      take the guard are not predicted, the violating cases are OK.
  core drops lines 3, 4 and 9 (the blank-line changes and `p = NULL;`): the
      same code as L4 up to blank lines; every case is OK.
L3 and L9 change only blank lines and are not run.
"""
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from negfrom_cases import lio_cases, rr_cases, ctl_cases, d_cases, is_viol  # noqa: E402

COLS = ["ours:L1", "ours:L2", "ours:L4", "ours:L6", "ours:L7", "ours:core"]


def row(name, family, sname, from_):
    if family == "x":
        return dict.fromkeys(COLS, "-")
    utf8_valid = (family == "lio" and not is_viol(from_)) or (family == "rr" and sname in ("u1", "u3", "u33"))
    viol = family == "lio" and is_viol(from_)
    c = dict.fromkeys(COLS, "OK")
    if viol:
        c["ours:L1"] = "-"
        c["ours:L2"] = "-"
    if utf8_valid:
        c["ours:L2"] = "-"
        c["ours:L6"] = "ASAN"
        c["ours:L7"] = "-"
    return c


def main():
    w = csv.writer(sys.stdout, delimiter="\t", lineterminator="\n")
    w.writerow(["case"] + COLS)
    for gen in (lio_cases, rr_cases, ctl_cases, d_cases):
        for name, family, recv, sname, n, from_, _body in gen():
            c = row(name, family, sname, from_)
            w.writerow([name] + [c[col] for col in COLS])
    # the dataset PoC: a violating case, UTF-8 branch with i <= to
    w.writerow(["poc", "ASAN", "-", "OK", "OK", "OK", "OK"])


if __name__ == "__main__":
    main()
