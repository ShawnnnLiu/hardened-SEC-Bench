#!/usr/bin/env python3
"""Summarize the ablation variants of a patch against a reference variant.

Usage: libredwg_ablation_summary.py LOGDIR REFERENCE [--manifest FILE]
                                     [--only PREFIX] [--names A,B,...] [--compact] [--no-drops]

LOGDIR/ablation.log holds one summary line per variant (build, PoC, case
summary) and LOGDIR/ablation/<variant>.cases.log the case results.
REFERENCE is a variant of LOGDIR/variants (e.g. after): its case results
are the oracle, because the ablation runs only a subset of the cases.
For each variant the script prints one Markdown row: the build result, the
PoC result, the number of cases whose class differs from the reference and
the verdict. --manifest (the MANIFEST of scripts/ablate_patch.py) adds the
changed lines the variant drops. --only keeps the variants whose name starts
with PREFIX, --names the listed variants (in that order); --compact prints one line per verdict
that lists the variants (with the number of differing cases) instead of one row
per variant, --no-drops leaves out the column of dropped lines. Numbers in notes
come from this script.

Verdicts:
  build fails            no BUILD COMPLETED line
  PoC crashes            the dataset PoC gives a sanitizer report
  PoC hangs              `secb repro` did not end within the timeout of the runner
  differs on N cases     at least one case has another class than REFERENCE
  equal to REFERENCE     build, PoC and all cases as REFERENCE
"""
import re
import sys
from pathlib import Path

LINE = re.compile(r"^(\S+)\s+(OK|WRONG|ASAN|.*\b[A-Z]+-INVARIANT\b.*)")


def classes(path):
    out = {}
    for line in Path(path).read_text(errors="replace").splitlines():
        m = LINE.match(line)
        if not m or m.group(1) == "summary:" or line.startswith("---"):
            continue
        out[m.group(1)] = "INV" if "INVARIANT" in m.group(2) else m.group(2).split()[0]
    return out


def main():
    args = sys.argv[1:]
    logdir, ref = Path(args.pop(0)), args.pop(0)
    manifest = None
    only = ""
    names = None
    compact = False
    no_drops = False
    while args:
        a = args.pop(0)
        if a == "--manifest":
            manifest = Path(args.pop(0))
        elif a == "--only":
            only = args.pop(0)
        elif a == "--names":
            names = args.pop(0).split(",")
        elif a == "--compact":
            compact = True
        elif a == "--no-drops":
            no_drops = True
    drops = {}
    if manifest:
        for line in manifest.read_text().splitlines():
            m = re.match(r"^(\w+): drops (.*)$", line)
            if m:
                drops[m.group(1)] = m.group(2)
    refc = classes(logdir / "variants" / f"{ref}.cases.log")
    rows = []
    for line in (logdir / "ablation.log").read_text().splitlines():
        parts = [p.strip() for p in line.split(" | ")]
        name = parts[0]
        if not name.startswith(only) or (names is not None and name not in names):
            continue
        f = {}
        for p in parts[2:]:
            for key in ("build=", "poc="):
                if p.startswith(key):
                    f[key.rstrip("=")] = p[len(key):]
        build = f.get("build", "?")
        poc = f.get("poc", "-")
        cl = logdir / "ablation" / f"{name}.cases.log"
        if not build.startswith("OK"):
            verdict, diff = "build fails", "-"
        elif poc == "crash":
            verdict, diff = "PoC crashes", "-"
        elif poc == "timeout":
            verdict, diff = "PoC hangs", "-"
        elif not cl.exists():
            verdict, diff = "no case log", "-"
        else:
            got = classes(cl)
            common = [c for c in got if c in refc]
            bad = [c for c in common if got[c] != refc[c]]
            diff = f"{len(bad)} of {len(common)}"
            verdict = f"differs on {len(bad)} cases" if bad else f"equal to {ref}"
        rows.append((name, drops.get(name, ""), build, poc, diff, verdict))
    if names is not None:
        rows.sort(key=lambda r: names.index(r[0]))
    order = {"build fails": 0, "PoC crashes": 1, "PoC hangs": 1}
    if compact:
        by = {}
        for name, d, b, p, diff, v in rows:
            key = "differs on cases" if v.startswith("differs") else v
            by.setdefault(key, []).append(name + (" (%s)" % diff.split(" of")[0] if key == "differs on cases" else ""))
        for key in sorted(by, key=lambda k: order.get(k, 2)):
            print("- %s (%d): %s" % (key, len(by[key]), ", ".join(by[key])))
        return
    if no_drops:
        print("| Variant | Build | PoC | Cases differing from " + ref + " | Verdict |")
        print("|---|---|---|---|---|")
        for name, d, b, p, diff, v in rows:
            print(f"| {name} | {b} | {p} | {diff} | {v} |")
    else:
        print("| Variant | Drops changed lines | Build | PoC | Cases differing from " + ref + " | Verdict |")
        print("|---|---|---|---|---|---|")
        for name, d, b, p, diff, v in rows:
            print(f"| {name} | {d} | {b} | {p} | {diff} | {v} |")
    counts = {}
    for r in rows:
        key = "differs" if r[5].startswith("differs") else r[5]
        counts[key] = counts.get(key, 0) + 1
    print()
    print("Totals: " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items(), key=lambda x: order.get(x[0], 2))))


if __name__ == "__main__":
    main()
