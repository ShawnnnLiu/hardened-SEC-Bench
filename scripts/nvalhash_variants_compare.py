"""Check the independence verdict of the blind second reading of mruby.cve-2022-0240 (phase 3) on this
repository's builds.

The reader built three compiler-only variants of gen_hash() from the base commit (no change in class.c):
  A  = three `val &&` guards on the stack-emitting branches (the same text as the codegen part of the
       root-cause patch of this repository),
  B  = a fresh base hash for a leading `**` in value context,
  AB = both.
This script compares, for the reader's 67 inputs (34 + 5 + 1 + 27), the classes on this repository's
base build, developer-patch build, root-cause build (= developer patch + A), B build and AB build
(each B and AB build made from the reader's diff, applied to a clean base tree) with the reader's
class table (phase3/logs/classes_all.tsv: input, base, dev, A, B, AB), and applies the reader's rule:
two defects are independent only if the fix of each, applied alone, repairs a set of inputs disjoint
from the set repaired by the other, and neither fix repairs inputs of the other.

Expected before the B and AB builds were run (written in advance; they are the reader's classes):
  B repairs the value-context inputs with a leading `**` (b6, c6 to c9, g6 to g8, g11, g12, g14, g17,
  h7 to h10: 16 inputs) and none of the discarded-literal inputs; AB repairs the union of the sets of
  A and B and, in addition, g1 (a program with one literal of each kind); b7, b8 (`**0` in value
  context) and f1 (a private method in the reference) stay not OK on every build; the root build equals
  the reader's A column on every input.

Run from the repository root:
    python3 scripts/nvalhash_variants_compare.py > logs/mruby.cve-2022-0240/second_reading/variants_compare.log

Inputs (logs/mruby.cve-2022-0240/second_reading/): variants_{base,dev,root,b,ab,cruby}.log written by
scripts/nvalhash_catalog_cases.sh over the directories inputs, inputs_e, inputs_f, inputs_g.
Classes: ASAN (sanitizer report); OK (same standard output and same uncaught error class and message as
CRuby); OKc (same output, same error class, other message); WRONG (anything else). "Fails" means not OK.
"""
import collections
import re

BASE = "logs/mruby.cve-2022-0240/second_reading/"
READER = BASE + "phase3/logs/classes_all.tsv"

ERR_RES = [
    re.compile(r"^\S+:\d+:in [^:]*?: (?P<msg>.*) \((?P<cls>[A-Z]\w*)\)$"),
    re.compile(r"^\S+:\d+: (?P<msg>.*) \((?P<cls>[A-Z]\w*)\)$"),
    re.compile(r"^\S+:\d+:in `[^']*': (?P<msg>.*) \((?P<cls>[A-Z]\w*)\)$"),
]


def parse_log(name):
    runs, cur, mode = {}, None, None
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
        return "ASAN"
    e, re_ = error_of(err), error_of(ref["err"])
    if out == ref["out"] and e == re_:
        return "OK"
    if out == ref["out"] and e and re_ and e[0] == re_[0]:
        return "OKc"
    return "WRONG"


builds = ("base", "dev", "root", "b", "ab")
logs = {b: parse_log("variants_%s.log" % b) for b in builds + ("cruby",)}
names = sorted(logs["base"])
for b in logs:
    assert sorted(logs[b]) == names, b
cls = {b: {n: classify(logs[b][n], logs["cruby"][n]) for n in names} for b in builds}
short = {n: n.split("/", 1)[1] for n in names}

reader = {}
for line in open(READER):
    p = line.rstrip("\n").split("\t")
    if len(p) == 6:
        reader[p[0]] = dict(zip(("base", "dev", "A", "B", "AB"), p[1:]))
assert len(reader) == 67 and set(short.values()) == set(reader), (len(reader), len(names))

print("programs: %d (inputs 34, inputs_e 5, inputs_f 1, inputs_g 27)" % len(names))
print("\n== class counts per build (this repository's runs)")
print("%-6s %5s %5s %5s %6s" % ("build", "ASAN", "OK", "OKc", "WRONG"))
for b in builds:
    c = collections.Counter(cls[b].values())
    print("%-6s %5d %5d %5d %6d" % (b, c["ASAN"], c["OK"], c["OKc"], c["WRONG"]))

print("\n== equality with the reader's class table")
pairs = (("base", "base"), ("dev", "dev"), ("root", "A"), ("b", "B"), ("ab", "AB"))
for ob, rb in pairs:
    diffs = [(short[n], cls[ob][n], reader[short[n]][rb]) for n in names if cls[ob][n] != reader[short[n]][rb]]
    print("ours:%-4s vs reader:%-4s  equal %d, different %d" % (ob, rb, len(names) - len(diffs), len(diffs)))
    for d in diffs:
        print("    %s ours=%s reader=%s" % d)

fails = {n for n in names if cls["base"][n] != "OK"}
rep = {b: {n for n in fails if cls[b][n] == "OK"} for b in builds}
reg = {b: sorted(short[n] for n in names if cls["base"][n] == "OK" and cls[b][n] != "OK") for b in builds}
print("\n== failing on base: %d; repaired by each build" % len(fails))
for b in builds:
    print("%-5s repaired %2d   regressions (OK on base, not OK) %s" % (b, len(rep[b]), reg[b] if reg[b] else "none"))

print("\n== the rule (root build = A with the developer patch; b = B alone; ab = both)")
RA, RB, RAB = rep["root"], rep["b"], rep["ab"]
print("R_A (root build): %d   R_B: %d   R_AB: %d" % (len(RA), len(RB), len(RAB)))
print("intersection of R_A and R_B: %d %s" % (len(RA & RB), sorted(short[n] for n in RA & RB)))
print("R_AB - (R_A | R_B): %s" % sorted(short[n] for n in RAB - (RA | RB)))
print("(R_A | R_B) - R_AB: %s" % sorted(short[n] for n in (RA | RB) - RAB))
print("not repaired by AB: %s" % sorted(short[n] for n in fails - RAB))
print("R_A: %s" % " ".join(sorted(short[n] for n in RA)))
print("R_B: %s" % " ".join(sorted(short[n] for n in RB)))
disjoint = not (RA & RB)
print("verdict by the rule: R_A and R_B disjoint = %s" % disjoint)
