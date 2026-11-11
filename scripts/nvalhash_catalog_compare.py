"""Compare the catalog runs of mruby.cve-2022-0240 (scripts/nvalhash_catalog_cases.sh) on the
first reading's base, developer-patch and root-patch builds and on the image's CRuby with the
tables of the blind second reading (phase 2).

Run from the repository root:
    python3 scripts/nvalhash_catalog_compare.py > logs/mruby.cve-2022-0240/second_reading/adjudication_compare.log

Inputs (under logs/mruby.cve-2022-0240/second_reading/):
    adjudication_{base,dev,root,cruby}.log - this repository's runs
    phase2/logs/classes_main.tsv, classes_e.tsv, classes_f.tsv - the reader's classes:
        main: input, base (before the rebuild), base (after), developer patch, fixonly
        e, f: input, base, developer patch, fixonly
    (fixonly = the reader's experimental change to gen_hash() and its caller, no change in class.c)

Classes, as in the reader's report: ASAN (sanitizer report); OK (same standard output and same
uncaught error class and message as CRuby); OKc (same output, same error class, other message);
WRONG (anything else).
"""
import collections
import re
import sys

BASE = "logs/mruby.cve-2022-0240/second_reading/"
READER = BASE + "phase2/logs/"

ERR_RES = [
    re.compile(r"^\S+:\d+:in [^:]*?: (?P<msg>.*) \((?P<cls>[A-Z]\w*)\)$"),
    re.compile(r"^\S+:\d+: (?P<msg>.*) \((?P<cls>[A-Z]\w*)\)$"),
    re.compile(r"^\S+:\d+:in `[^']*': (?P<msg>.*) \((?P<cls>[A-Z]\w*)\)$"),
]


def parse_log(name):
    runs = {}
    cur = None
    mode = None
    with open(BASE + name) as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("@@@ BEGIN "):
                key, rc = line[len("@@@ BEGIN "):].rsplit(" rc=", 1)
                cur = {"rc": int(rc), "out": [], "err": []}
                runs[key] = cur
                mode = None
            elif line == "@@@ STDOUT":
                mode = "out"
            elif line == "@@@ STDERR":
                mode = "err"
            elif line == "@@@ END":
                mode = None
            elif cur is not None and mode:
                cur[mode].append(line)
    for r in runs.values():
        # the runner writes one extra newline before each marker
        for k in ("out", "err"):
            if r[k] and r[k][-1] == "":
                r[k] = r[k][:-1]
            r[k] = "\n".join(r[k])
    return runs


def error_of(err):
    for line in err.splitlines():
        for r in ERR_RES:
            m = r.match(line)
            if m:
                return (m.group("cls"), m.group("msg"))
    for line in err.splitlines():
        if "stack pointer" in line or "syntax error" in line or "codegen" in line:
            return ("COMPILE", line.strip())
    return None


def classify(run, ref):
    out, err = run["out"], run["err"]
    if "ERROR: AddressSanitizer" in err or "ERROR: AddressSanitizer" in out:
        m = re.search(r"ERROR: AddressSanitizer: (\S+) on (?:unknown address|address) (0x[0-9a-f]+)", err)
        f = re.search(r"^\s+#0 0x[0-9a-f]+ in (\S+)", err, re.M)
        return "ASAN", "%s %s %s" % (m.group(1) if m else "?", m.group(2) if m else "?", f.group(1) if f else "?")
    e, re_ = error_of(err), error_of(ref["err"])
    if out == ref["out"] and e == re_:
        return "OK", ""
    if out == ref["out"] and e and re_ and e[0] == re_[0]:
        return "OKc", ""
    return "WRONG", ""


logs = {b: parse_log("adjudication_%s.log" % b) for b in ("base", "dev", "root", "cruby")}
assert set(logs["base"]) == set(logs["dev"]) == set(logs["root"]) == set(logs["cruby"])
names = sorted(logs["base"])
groups = {
    "inputs": [n for n in names if n.startswith("inputs/")],
    "inputs_e": [n for n in names if n.startswith("inputs_e/")],
    "inputs_f": [n for n in names if n.startswith("inputs_f/")],
    "probes": [n for n in names if n.startswith("probes/")],
}
print("programs:", ", ".join("%s %d" % (g, len(v)) for g, v in groups.items()))
cls = {b: {n: classify(logs[b][n], logs["cruby"][n]) for n in names} for b in ("base", "dev", "root")}

print("\n== class counts per group and build (this repository's runs)")
print("%-10s %-6s %5s %5s %5s %6s" % ("group", "build", "ASAN", "OK", "OKc", "WRONG"))
for g, ns in groups.items():
    for b in ("base", "dev", "root"):
        c = collections.Counter(cls[b][n][0] for n in ns)
        print("%-10s %-6s %5d %5d %5d %6d" % (g, b, c["ASAN"], c["OK"], c["OKc"], c["WRONG"]))


def reader(path, ncols):
    rows = {}
    for line in open(READER + path):
        p = line.rstrip("\n").split("\t")
        if len(p) == ncols + 1:
            rows[p[0]] = p[1:]
    return rows


main = reader("classes_main.tsv", 4)   # base_pre, base_post, patched, fixonly
ee = reader("classes_e.tsv", 3)        # base, patched, fixonly
ff = reader("classes_f.tsv", 3)
print("\n== replication of the reader's classes (inputs a to d, batch E, batch F)")


def rd(n):
    short = n.split("/", 1)[1]
    if n.startswith("inputs/"):
        r = main[short]
        return {"base": r[1], "dev": r[2], "fixonly": r[3]}
    if n.startswith("inputs_e/"):
        r = ee[short]
        return {"base": r[0], "dev": r[1], "fixonly": r[2]}
    if n.startswith("inputs_f/"):
        r = ff[short]
        return {"base": r[0], "dev": r[1], "fixonly": r[2]}
    return None


for ob, rb in (("base", "base"), ("dev", "dev")):
    diffs = []
    n_cmp = 0
    for n in names:
        r = rd(n)
        if r is None:
            continue
        n_cmp += 1
        if cls[ob][n][0] != r[rb]:
            diffs.append((n, cls[ob][n][0], r[rb]))
    print("ours:%s vs reader:%s  compared %d, different %d" % (ob, rb, n_cmp, len(diffs)))
    for d in diffs:
        print("    %s ours=%s reader=%s" % d)

print("\n== root build against the reader's fixonly build (classes)")
diffs = []
n_cmp = 0
for n in names:
    r = rd(n)
    if r is None:
        continue
    n_cmp += 1
    if cls["root"][n][0] != r["fixonly"]:
        diffs.append((n, cls["root"][n][0], r["fixonly"], cls["base"][n][0]))
print("compared %d, different %d" % (n_cmp, len(diffs)))
for d in diffs:
    print("    %s root=%s fixonly=%s base=%s" % d)

print("\n== per input (a to d, E, F): class on base / developer / root, and the reader's fixonly")
for n in names:
    r = rd(n)
    if r is None:
        continue
    print("%-34s base=%-5s dev=%-5s root=%-5s fixonly=%-5s" % (n, cls["base"][n][0], cls["dev"][n][0], cls["root"][n][0], r["fixonly"]))

print("\n== ASAN programs (first frame and address)")
for b in ("base", "dev", "root"):
    rows = [(n, cls[b][n][1]) for n in names if cls[b][n][0] == "ASAN"]
    print("%s: %d" % (b, len(rows)))
    for n, d in rows:
        print("    %s %s" % (n, d))

print("\n== probes: output of dev and root against base (identical standard output, standard error and status)")
for b in ("dev", "root"):
    same = [n for n in groups["probes"] if (logs[b][n]["rc"], logs[b][n]["out"], logs[b][n]["err"]) == (logs["base"][n]["rc"], logs["base"][n]["out"], logs["base"][n]["err"])]
    print("%s: %d of %d probes identical to base" % (b, len(same), len(groups["probes"])))
    for n in groups["probes"]:
        if n not in same:
            print("    differs: %s base=%s %s | %s=%s %s" % (n, cls["base"][n][0], cls["base"][n][1], b, cls[b][n][0], cls[b][n][1]))
