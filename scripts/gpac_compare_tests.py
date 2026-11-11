"""Compare two GPAC test-suite logs per test.

Usage: python3 gpac_compare_tests.py BASE.log OTHER.log [RERUN.log...]

The logs are written by scripts/gpac_run_tests_parallel.sh (or
scripts/gpac_run_tests.sh). Each test has one line "RESULT <name> <result>"
in the merged section; the per-script sections repeat the same lines.
Prints the merged SUMMARY line of each log, every test whose result line
differs between BASE and OTHER with both results, the tests present in only
one log, and a count line:
  compare: N tests in both, I identical, D differing, B only in BASE, O only in OTHER
With RERUN logs (e.g. tests_reruns/<build>.<pass>.log), each differing
test is followed by its result in each rerun log that contains it.
"""
import sys
from pathlib import Path


def load(path):
    results, summary = {}, None
    merged = False
    for line in Path(path).read_text(errors="replace").splitlines():
        if line.startswith("### merged results"):
            merged = True
        elif line.startswith("SUMMARY ") and (merged or summary is None):
            summary = line
        elif line.startswith("RESULT "):
            parts = line.split(None, 2)
            results[parts[1]] = parts[2].strip() if len(parts) > 2 else ""
    return results, summary


def main():
    base, other, reruns = sys.argv[1], sys.argv[2], sys.argv[3:]
    a, sa = load(base)
    b, sb = load(other)
    rr = [(r, load(r)[0]) for r in reruns]
    print(f"base  {base}: {sa}")
    print(f"other {other}: {sb}")
    both = sorted(set(a) & set(b))
    diff = [t for t in both if a[t] != b[t]]
    for t in diff:
        print(f"DIFF {t}\n  base:  {a[t]}\n  other: {b[t]}")
        for r, res in rr:
            if t in res:
                print(f"  {r}: {res[t]}")
    for t in sorted(set(a) - set(b)):
        print(f"ONLY-BASE {t} {a[t]}")
    for t in sorted(set(b) - set(a)):
        print(f"ONLY-OTHER {t} {b[t]}")
    print(f"compare: {len(both)} tests in both, {len(both) - len(diff)} identical, {len(diff)} differing, "
          f"{len(set(a) - set(b))} only in BASE, {len(set(b) - set(a))} only in OTHER")


if __name__ == "__main__":
    main()
