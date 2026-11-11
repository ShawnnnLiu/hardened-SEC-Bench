#!/usr/bin/env python3
"""Compare the mruby.cve-2022-1427 catalog runs with the mruby.cve-2022-1201
catalog runs of the equivalent builds, per program.

The two instances share the OP_SUPER fix: the 1201 root patch (base d1f1b4ea
+ a4d97934d, both branches guarded) produces the same OP_SUPER block as the
1427 developer patch (base bdc244e9 + a4d97934d), and the 1427 base (bdc244e9,
which already carries 00acae117, the 1201 developer patch, so the module
branch alone is guarded) produces the same OP_SUPER block as the 1201
developer build (d1f1b4ea + 00acae117). So:
  1427 base  should match 1201 developer  (module guarded, prepended not);
  1427 after should match 1201 root        (both guarded).
The two bases differ by 74 commits (bigint rewrite, method cache, int sizes),
so an exception message or a non-super value may differ for an unrelated
reason; the memory-safety class (ASAN vs not) is the invariant under test.

Usage (from the repository root):
  python3 scripts/superprep_catalog_compare.py > logs/mruby.cve-2022-1427/variants/catalog_compare.log

Inputs:
  logs/mruby.cve-2022-1427/variants/catalog_base.tsv, catalog_after.tsv
  logs/mruby.cve-2022-1201/second_reading/catalog_dev.tsv, catalog_root.tsv
Each TSV: one line `<dir>/<name>\t<class>\t<detail>` per program (header '#').
"""
import sys

A = "logs/mruby.cve-2022-1427/variants/"
B = "logs/mruby.cve-2022-1201/second_reading/"


def norm(detail):
    d = detail.strip()
    if d.startswith("exc="):
        return d[4:]
    if d.startswith("mrb_") and " 0x" in d:   # ASAN "<frame> <addr>" -> frame only
        return d.split(" ", 1)[0]
    return d


def load(path):
    rows = {}
    with open(path) as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            prog, cls, detail = (line.rstrip("\n").split("\t") + ["", ""])[:3]
            key = prog.split("/", 1)[1]
            rows[key] = (cls, norm(detail))
    return rows


def counts(rows):
    asan = sum(1 for c, _ in rows.values() if c == "ASAN")
    return f"{len(rows)} programs, {asan} ASAN, {len(rows) - asan} non-ASAN"


def compare(name, ours, theirs):
    common = sorted(set(ours) & set(theirs))
    only_ours = sorted(set(ours) - set(theirs))
    only_theirs = sorted(set(theirs) - set(ours))
    cls_diff = [k for k in common if ours[k][0] != theirs[k][0]]
    detail_diff = [k for k in common if ours[k][0] == theirs[k][0] and ours[k][1] != theirs[k][1]]
    print(f"\n== {name}")
    print(f"common programs: {len(common)}; only in 1427: {len(only_ours)}; only in 1201: {len(only_theirs)}")
    print(f"class differences (ASAN vs not, or OK vs INV): {len(cls_diff)}")
    for k in cls_diff:
        print(f"    {k}  1427={ours[k]}  1201={theirs[k]}")
    print(f"same class, different detail (exception class or value): {len(detail_diff)}")
    for k in detail_diff:
        print(f"    {k}  1427={ours[k][1]}  1201={theirs[k][1]}")


def main():
    base = load(A + "catalog_base.tsv")
    after = load(A + "catalog_after.tsv")
    dev = load(B + "catalog_dev.tsv")
    root = load(B + "catalog_root.tsv")
    print("# superprep_catalog_compare mruby.cve-2022-1427")
    print(f"1427 base : {counts(base)}")
    print(f"1427 after: {counts(after)}")
    print(f"1201 dev  : {counts(dev)}")
    print(f"1201 root : {counts(root)}")
    compare("1427 base vs 1201 developer build", base, dev)
    compare("1427 after vs 1201 root build", after, root)


if __name__ == "__main__":
    main()
