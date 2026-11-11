"""Classify GPAC tests whose result differs between two full suite runs,
using rerun passes of both builds made at the same time.

Usage: python3 gpac_rerun_verdict.py LOGDIR BASE OTHER BASE_FULL OTHER_FULL PASS...

LOGDIR is logs/<instance>; BASE_FULL and OTHER_FULL are the full-run logs
relative to it (e.g. tests_before.log, tests_root.log); BASE and OTHER are
the build names of the rerun logs tests_reruns/<build>.<pass>.log, and
each PASS names a pass run for both builds at the same time (e.g. net1).
For every test whose result line differs between the two full runs the
script prints one Markdown table row:
  test | paired passes with equal result | results seen on BASE | results seen on OTHER | verdict
A difference is "persistent" if the result differs in every paired pass
and no result line occurs on both builds over all their runs; otherwise it
is "not reproduced". The last line counts both verdicts.
"""
import sys
from pathlib import Path


def load(path):
    r = {}
    for line in Path(path).read_text(errors="replace").splitlines():
        if line.startswith("RESULT "):
            p = line.split(None, 2)
            r[p[1]] = p[2].strip() if len(p) > 2 else ""
    return r


def main():
    logdir, base, other, base_full, other_full, *passes = sys.argv[1:]
    d = Path(logdir)
    fb, fo = load(d / base_full), load(d / other_full)
    rb = [load(d / "tests_reruns" / f"{base}.{p}.log") for p in passes]
    ro = [load(d / "tests_reruns" / f"{other}.{p}.log") for p in passes]
    counts = {"persistent": 0, "not reproduced": 0}
    print(f"| Test | paired passes equal | distinct results {base} | distinct results {other} | verdict |")
    print("|---|---|---|---|---|")
    for t in sorted(x for x in fo if fo[x] != fb.get(x)):
        eq = sum(b.get(t) == o.get(t) for b, o in zip(rb, ro))
        sb = {fb.get(t)} | {b.get(t) for b in rb}
        so = {fo[t]} | {o.get(t) for o in ro}
        verdict = "persistent" if eq == 0 and not (sb & so) else "not reproduced"
        counts[verdict] += 1
        print(f"| `{t}` | {eq} of {len(passes)} | {len(sb)} | {len(so)} | {verdict} |")
    print(f"verdicts: {counts['persistent']} persistent, {counts['not reproduced']} not reproduced")


if __name__ == "__main__":
    main()
