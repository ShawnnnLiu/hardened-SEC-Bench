"""Render Markdown tables for a note from variants.log and the case logs.

Usage: python3 render_cases_table.py LOGDIR VARIANT... [--merge NAME=prefix,prefix,...]... [--set SET]

The first table has one row per VARIANT from LOGDIR/variants.log or
LOGDIR/ablation.log (build, PoC, case summary, digest, tests). The second
counts case results per case group and variant from
LOGDIR/variants/<v>.cases.log or LOGDIR/ablation/<v>.cases.log. With
--set SET (a second case set, e.g. big), the second table reads
LOGDIR/variants/<v>.<SET>.log where it exists and <v>.cases.log otherwise
(a variant that a variant runner ran on the second set alone), and the
first table is not printed, because variants.log summarises the main set.
A case
group is the case name without its trailing _n<digits>; --merge joins
groups under one name, in the order given, and the remaining groups follow
in order of first appearance. A --merge entry ending in * matches every
group that starts with the text before it. Cells read "a OK, b wrong, c ASan, d inv",
leaving out zero counts. Numbers in notes come from this script, not from
memory.
"""
import re
import sys
from collections import Counter, OrderedDict
from pathlib import Path

LINE = re.compile(r"^(\S+)\s+(OK|WRONG|ASAN|.*\b[A-Z]+-INVARIANT\b.*)")


def rows_of(logdir, variant, caseset=None):
    if caseset:
        p = logdir / "variants" / f"{variant}.{caseset}.log"
        if p.exists():
            return p
    for name in ("variants", "ablation"):
        p = logdir / name / f"{variant}.cases.log"
        if p.exists():
            return p
    sys.exit(f"no cases log for {variant}")


def summary_line(logdir, variant):
    for name in ("variants.log", "ablation.log"):
        p = logdir / name
        if p.exists():
            for line in p.read_text().splitlines():
                if line.startswith(f"{variant} | "):
                    return line
    return None


def main():
    args = sys.argv[1:]
    logdir = Path(args.pop(0))
    merges, variants, caseset = OrderedDict(), [], None
    while args:
        a = args.pop(0)
        if a == "--merge":
            name, prefixes = args.pop(0).split("=", 1)
            merges[name] = prefixes.split(",")
        elif a == "--set":
            caseset = args.pop(0)
        else:
            variants.append(a)

    if not caseset:
        print_summary(logdir, variants)
        print()

    counts = {v: {} for v in variants}
    order = []
    for v in variants:
        for line in rows_of(logdir, v, caseset).read_text().splitlines():
            m = LINE.match(line)
            if not m or m.group(1) == "summary:":
                continue
            name, res = m.groups()
            group = re.sub(r"_n\d+$", "", name)
            for mname, prefixes in merges.items():
                if any(group == p or (p.endswith("*") and group.startswith(p[:-1])) for p in prefixes):
                    group = mname
                    break
            if group not in order:
                order.append(group)
            cls = "inv" if re.search(r"\b[A-Z]+-INVARIANT\b", res) else {"OK": "OK", "WRONG": "wrong", "ASAN": "ASan"}[res]
            counts[v].setdefault(group, Counter())[cls] += 1
    ordered = [g for g in merges if g in order] + [g for g in order if g not in merges]

    def cell(c):
        return ", ".join(f"{c[k]} {k}" for k in ("OK", "wrong", "ASan", "inv") if c.get(k))

    print("| Case group (count) | " + " | ".join(variants) + " |")
    print("|---|" + "---|" * len(variants))
    for g in ordered:
        total = max(sum(counts[v].get(g, Counter()).values()) for v in variants)
        print(f"| {g} ({total}) | " + " | ".join(cell(counts[v].get(g, Counter())) for v in variants) + " |")
    totals = [sum((counts[v].get(g, Counter()) for g in ordered), Counter()) for v in variants]
    print(f"| Total ({max(sum(t.values()) for t in totals)}) | " + " | ".join(cell(t) for t in totals) + " |")


def print_summary(logdir, variants):
    print("| Variant | Build | PoC | Cases | Digest | Tests |")
    print("|---|---|---|---|---|---|")
    for v in variants:
        line = summary_line(logdir, v)
        if line is None:
            print(f"| {v} | no summary line | | | | |")
            continue
        parts = [p.strip() for p in line.split(" | ")]
        f = {}
        for part in parts[2:]:
            for key in ("build=", "poc=", "digest=", "cases: ", "tests: "):
                if part.startswith(key):
                    f[key.rstrip("=: ")] = part[len(key):].strip()
        print(f"| {v} | {f.get('build','')} | {f.get('poc','')} | {f.get('cases','')} | {f.get('digest','')} | {f.get('tests','')} |")


if __name__ == "__main__":
    main()
