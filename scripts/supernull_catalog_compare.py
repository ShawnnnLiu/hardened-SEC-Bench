"""Compare the catalog runs of mruby.cve-2022-1201 (scripts/supernull_catalog_cases.sh) on the
first reading's base, developer-patch and root-patch builds with the tables of the blind second
reading (phase 3).

Run from the repository root:
    python3 scripts/supernull_catalog_compare.py > logs/mruby.cve-2022-1201/second_reading/catalog_compare.log

Inputs (all under logs/mruby.cve-2022-1201/second_reading/):
    catalog_base.tsv, catalog_dev.tsv, catalog_root.tsv, catalog_cruby.tsv - this repository's runs
    phase3/cases_all.tsv, cases5_all.tsv, cases6_all.tsv, variants_cases.tsv, matrix_all.tsv,
    variants_matrix.tsv, cruby_all.tsv - the reader's tables (builds: base; dev = developer patch;
    fix = developer patch + one NULL test after the two branches; f5 = developer patch + the
    NULL + ICLASS test in the prepended branch)

Result classes: ASAN (sanitizer report), OK (no sanitizer report), WRONG (no sanitizer report and a
printed value that differs from CRuby, for a program for which CRuby returns a value).
"""
import collections
import os
import sys

BASE = "logs/mruby.cve-2022-1201/second_reading/"
P3 = BASE + "phase3/"


def norm_detail(d):
    """exc=<Class> -> <Class>; an ASAN detail "<frame> <address>" -> "<frame>" (the reader's matrix
    table keeps only the frame function; every fault address in this repository's runs is 0x10)."""
    d = d.strip()
    if d.startswith("exc="):
        return d[4:]
    if d.startswith("mrb_") and " 0x" in d:
        return d.split(" ", 1)[0]
    return d


def load_ours(name):
    rows = {}
    with open(BASE + name) as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            prog, cls, detail = (line.rstrip("\n").split("\t") + ["", ""])[:3]
            key = prog.split("/", 1)[1]
            assert key not in rows, "duplicate program name " + key
            rows[key] = (cls, norm_detail(detail), prog.split("/", 1)[0])
    return rows


def load_reader_cases(name):
    out = collections.defaultdict(dict)
    with open(P3 + name) as f:
        next(f)
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) < 5:
                continue
            out[p[2]][p[1]] = (p[3], norm_detail(p[4]))
    return out


def load_reader_matrix(name):
    out = collections.defaultdict(dict)
    with open(P3 + name) as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) < 4 or p[0] == "program":
                continue
            out[p[1]][p[0]] = (p[2], norm_detail(p[3]))
    return out


def merge(*dicts):
    out = collections.defaultdict(dict)
    for d in dicts:
        for b, rows in d.items():
            out[b].update(rows)
    return out


ours = {b: load_ours("catalog_%s.tsv" % b) for b in ("base", "dev", "root", "cruby")}
case_rd = merge(load_reader_cases("cases_all.tsv"), load_reader_cases("cases5_all.tsv"),
                load_reader_cases("cases6_all.tsv"), load_reader_cases("variants_cases.tsv"))
mat_rd = merge(load_reader_matrix("matrix_all.tsv"), load_reader_matrix("variants_matrix.tsv"))

# program sets: matrix programs start with "mx_"; probes are listed separately
groups = {"case-set": [], "matrix": [], "probes": []}
for name, (cls, det, d) in ours["base"].items():
    g = "matrix" if d == "matrix" else "probes" if d == "probes" else "case-set"
    groups[g].append(name)
for g in groups:
    groups[g].sort()
print("programs: case-set %d, matrix %d, probes %d" % tuple(len(groups[g]) for g in ("case-set", "matrix", "probes")))
for b in ("base", "dev", "root", "cruby"):
    assert set(ours[b]) == set(ours["base"]), "program sets differ for " + b


def cls_of(rows, name):
    return rows[name][0] if name in rows else "-"


print("\n== class counts per build (this repository's runs)")
print("%-10s %-8s %6s %6s %8s" % ("set", "build", "ASAN", "OK", "other"))
for g in ("case-set", "matrix", "probes"):
    for b in ("base", "dev", "root"):
        c = collections.Counter(ours[b][n][0] for n in groups[g])
        other = sum(v for k, v in c.items() if k not in ("ASAN", "OK"))
        print("%-10s %-8s %6d %6d %8d" % (g, b, c["ASAN"], c["OK"], other))

addrs = set()
for b in ("base", "dev", "root"):
    for n, (cls, det, d) in ours[b].items():
        pass
for line in open(BASE + "catalog_base.tsv"):
    if not line.startswith("#") and "\tASAN\t" in line:
        addrs.add(line.rstrip("\n").split("\t")[2].split(" ")[-1])
for line in open(BASE + "catalog_dev.tsv"):
    if not line.startswith("#") and "\tASAN\t" in line:
        addrs.add(line.rstrip("\n").split("\t")[2].split(" ")[-1])
print("\nfault addresses in this repository's ASAN lines (base and developer builds): %s" % sorted(addrs))
print("\n== replication of the reader's builds (class and detail equal per program)")
for g, rd in (("case-set", case_rd), ("matrix", mat_rd)):
    for ob, rb in (("base", "base"), ("dev", "dev")):
        n_eq = n_diff = n_missing = 0
        diffs = []
        for n in groups[g]:
            if n not in rd.get(rb, {}):
                n_missing += 1
                continue
            if rd[rb][n] == ours[ob][n][:2]:
                n_eq += 1
            else:
                n_diff += 1
                diffs.append((n, ours[ob][n][:2], rd[rb][n]))
        print("%-9s ours:%s vs reader:%s  equal %d, different %d, not in reader's table %d" % (g, ob, rb, n_eq, n_diff, n_missing))
        for n, a, b in diffs[:20]:
            print("    %s ours=%s reader=%s" % (n, a, b))

print("\n== root build against the reader's f5 build and fix build (class and detail per program)")
for g, rd in (("case-set", case_rd), ("matrix", mat_rd)):
    for rb in ("f5", "fix"):
        n_eq = n_diff = n_missing = 0
        diffs = []
        for n in groups[g]:
            if n not in rd.get(rb, {}):
                n_missing += 1
                continue
            if rd[rb][n] == ours["root"][n][:2]:
                n_eq += 1
            else:
                n_diff += 1
                diffs.append((n, ours["root"][n][:2], rd[rb][n]))
        print("%-9s ours:root vs reader:%s  equal %d, different %d, not in reader's table %d" % (g, rb, n_eq, n_diff, n_missing))
        for n, a, b in diffs[:40]:
            print("    %s root=%s reader:%s=%s" % (n, a, rb, b))
        if len(diffs) > 40:
            print("    ... %d more" % (len(diffs) - 40))

print("\n== programs for which CRuby returns a value (this repository's CRuby run), per build")
cr = {n: v for n, v in ours["cruby"].items() if v[0] == "OK" and v[1].startswith("value=")}
cr_names = sorted(n for n in cr if n in groups["case-set"] or n in groups["probes"] or n in groups["matrix"])
print("CRuby returns a value for %d programs (%s)" % (len(cr_names), "reader's cruby_all.tsv: 38"))
reader_cr = {}
with open(P3 + "cruby_all.tsv") as f:
    next(f)
    for line in f:
        p = line.rstrip("\n").split("\t")
        if len(p) >= 3 and p[1] == "value":
            reader_cr[p[0]] = p[2]
print("cross-check with the reader's CRuby table: same program set %s, same values %s" % (
    sorted(reader_cr) == cr_names,
    all(cr[n][1] == "value=" + reader_cr[n] for n in cr_names if n in reader_cr)))
table = collections.defaultdict(collections.Counter)
wrong = collections.defaultdict(list)
for b in ("base", "dev", "root"):
    for n in cr_names:
        cls, det, _ = ours[b][n]
        if cls == "ASAN":
            k = "ASAN"
        elif cls == "OK" and det == cr[n][1]:
            k = "OK"
        else:
            k = "WRONG"
            wrong[b].append(n)
        table[b][k] += 1
    print("%-5s OK %d, WRONG %d, ASAN %d" % (b, table[b]["OK"], table[b]["WRONG"], table[b]["ASAN"]))
print("WRONG on root (%d): %s" % (len(wrong["root"]), " ".join(wrong["root"])))
print("ASAN on base and WRONG on root (%d): %s" % (
    len([n for n in wrong["root"] if ours["base"][n][0] == "ASAN"]),
    " ".join(n for n in wrong["root"] if ours["base"][n][0] == "ASAN")))
print("WRONG on every build (%d): %s" % (
    len([n for n in cr_names if all(n in wrong[b] for b in ("base", "dev", "root"))]),
    " ".join(n for n in cr_names if all(n in wrong[b] for b in ("base", "dev", "root")))))

print("\n== exception and value classes of the programs that are not ASAN on the base build: base vs developer vs root")
for g in ("case-set", "matrix"):
    ne_dev = [n for n in groups[g] if ours["base"][n][0] != "ASAN" and ours["dev"][n][:2] != ours["base"][n][:2]]
    ne_root = [n for n in groups[g] if ours["base"][n][0] != "ASAN" and ours["root"][n][:2] != ours["base"][n][:2]]
    n_non = len([n for n in groups[g] if ours["base"][n][0] != "ASAN"])
    print("%-9s non-ASAN on base: %d; differ on developer build: %d; differ on root build: %d" % (g, n_non, len(ne_dev), len(ne_root)))
    for n in ne_root[:40]:
        print("    %s base=%s root=%s" % (n, ours["base"][n][:2], ours["root"][n][:2]))
    if len(ne_root) > 40:
        print("    ... %d more" % (len(ne_root) - 40))

print("\n== probes (reader's x01-x04: prepended-class branch with a non-NULL frame class that is not an iclass)")
for n in groups["probes"]:
    print("%-34s base=%s dev=%s root=%s cruby=%s" % (n, ours["base"][n][:2], ours["dev"][n][:2], ours["root"][n][:2], ours["cruby"][n][:2]))
