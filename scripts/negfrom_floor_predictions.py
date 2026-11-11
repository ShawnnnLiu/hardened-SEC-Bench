"""Predicted result class of every scripts/negfrom_cases.py case for the
variant floor0 of njs.cve-2022-31307, for scripts/check_predictions.py.

Usage: python3 negfrom_floor_predictions.py > negfrom_floor_predictions.tsv

Written on 2026-10-14 at about 03:13 EDT, before the variant ran.

floor0 (scripts/negfrom_floor0_synthetic.diff, source synthetic) is the fix
form that the blind second reading proposed in its phase 1: after
`from += length` in njs_array_prototype_reverse_iterator() the start index
is floored at 0, as the forward iteration does for indexOf/includes. It
leaves njs_object_iterate_reverse() unchanged and keeps every start index
non-negative, so no case reaches njs_string_offset() with an invalid index
(no ASAN). For lastIndexOf, however, a start index below 0 means that no
element is searched (the reference returns -1); with the floor the element
at index 0 is searched. Every case that reaches the faulty state searches
for the first character of the string, which is at index 0, so each returns
0 where the reference returns -1: WRONG. The dataset PoC (case poc) prints
nothing and stays OK. All other cases are unchanged (OK); the x_* cases are
not predicted.
"""
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from negfrom_cases import lio_cases, rr_cases, ctl_cases, d_cases, is_viol  # noqa: E402


def main():
    w = csv.writer(sys.stdout, delimiter="\t", lineterminator="\n")
    w.writerow(["case", "ours:floor0"])
    for gen in (lio_cases, rr_cases, ctl_cases, d_cases):
        for name, family, recv, sname, n, from_, _body in gen():
            if family == "x":
                c = "-"
            elif family == "lio" and is_viol(from_):
                c = "WRONG"
            else:
                c = "OK"
            w.writerow([name, c])
    w.writerow(["poc", "OK"])


if __name__ == "__main__":
    main()
