#!/usr/bin/env python3
"""Cases for the SVG escape routines of LibreDWG, programs/escape.c:
htmlescape() (libredwg.cve-2020-21816) and htmlwescape(), its UTF-16 twin.

Runs inside a container of the instance image after `secb build`.

Usage:
  escape_cases.py run [--inputs DIR]   run the unit and file cases
  escape_cases.py corpus               run dwg2SVG over every tracked DWG file
  escape_cases.py list                 print the case names
  escape_cases.py gen OUTDIR           write the blk12 and txt input files of
                                       this tree to OUTDIR (use as --inputs)

Every result line starts in column 1 with `<case> <result>`; evidence lines
are indented and header lines start with `---`. The last line of `run` is
  summary: N cases; a OK, b WRONG, c ASAN, d INV; timeouts t; valid outputs D
and that of `corpus`
  corpus: N files; a OK, b WRONG, c ASAN, d INV, e NOREF; digest D

Unit cases call htmlescape (`a_*`, byte strings) or htmlwescape (`w_*`,
UTF-16 strings) through scripts/escape_driver.c, built with the compiler
and flags of the tree's programs/Makefile and linked with the tree's
programs/escape.c. A case is a character string; the families below cross
the character classes of the escape table (plain, the eight characters
with an entity, a byte or unit of 127 or more, a control character) with
position, run length and total length, and a seeded random set covers
combinations. File cases run /src/libredwg/programs/dwg2SVG on a DWG file:
the dataset PoC (`poc`), the eight reproducers of LibreDWG/libredwg#182
(`issue182_*`, from --inputs), copies of test/test-data/example_2000.dwg
with the block name "*Paper_Space" replaced in place by another string of
12 bytes (`blk12_*`, a byte edit like the reporter's mutation) and R2000
files written by programs/dwgwrite from test/test-data/example_2000.dxf
with the TEXT value replaced (`txt_*`). Block names reach htmlescape in
output_BLOCK_HEADER and TEXT values in output_TEXT (programs/dwg2SVG.c);
files of version R2007 and later use htmlwescape.

Oracle. Unit cases: spec() below, the character table of htmlescape and
htmlwescape at 5f998146 applied to every character of the input once:
'"', "'", '`', '&', '<', '>', '{', '}' become &quot; &#39; &#96; &amp;
&lt; &gt; &#123; &#125;, a character of 127 or more becomes &#x<HEX>;, a
character of 20 or more is copied and a character below 20 is dropped.
File cases: the block names and TEXT values of the input read by
`dwgread -O json` (a path that does not use escape.c), escaped with
spec(); the expected output holds an `<!-- name -->` or `<text>` line for
each. When the strings of an input cannot be read from the JSON output the
file has no reference and only sanitizer reports (and the marker) are
observable (NOREF in the corpus; plain OK here). The JSON writer of this
revision does not always produce a document that parses, so the strings
are cut out with patterns (json_strings()).

Result of a run, in this order of precedence:
  <MARKER>-INVARIANT ...  an instrumented invariant check fired
  ASAN <type>             an AddressSanitizer report
  WRONG timeout           no exit within CASE_TIMEOUT seconds
  WRONG ...               output differs from the oracle (or driver error)
  OK                      output equals the oracle

Environment: LIBREDWG_TREE (default /src/libredwg), CASE_WORK (/tmp/cases),
CASE_TIMEOUT (seconds, 120), CASE_JOBS (cases run at the same time, the
number of CPUs), CASE_ONLY (a regular expression; run only the matching
cases, for debugging the script).
"""
import collections
import hashlib
import json
import os
import random
import re
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

TREE = Path(os.environ.get("LIBREDWG_TREE", "/src/libredwg"))
WORK = Path(os.environ.get("CASE_WORK", "/tmp/cases"))
T = int(os.environ.get("CASE_TIMEOUT", "120"))
JOBS = int(os.environ.get("CASE_JOBS", str(len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else os.cpu_count() or 1)))
HERE = Path(__file__).resolve().parent
MEM = re.compile(r"ERROR: (Address|Memory|Thread|Leak)Sanitizer|runtime error:")
MARK = re.compile(r"\b[A-Z]+-INVARIANT\b.*")

# ---------------------------------------------------------------- oracle

ENTITY = {'"': "&quot;", "'": "&#39;", "`": "&#96;", "&": "&amp;",
          "<": "&lt;", ">": "&gt;", "{": "&#123;", "}": "&#125;"}
SPECIALS = list(ENTITY)


def spec_unit(c):
    ch = chr(c)
    if ch in ENTITY:
        return ENTITY[ch]
    if c >= 127:
        return "&#x%X;" % c
    if c >= 20:
        return ch
    return ""


def units(text, wide):
    """Code units of a string: its bytes (wide False) or UTF-16 units."""
    if wide:
        b = text.encode("utf-16-le", "surrogatepass")
        return list(struct.unpack("<%dH" % (len(b) // 2), b))
    return [ord(c) for c in text]


def spec(text, wide=False):
    return "".join(spec_unit(c) for c in units(text, wide))


# ------------------------------------------------------------ unit cases

HI = chr(0xE9)
CTL = "\x01"


def families(func):
    """(family, [strings]) for one function. Strings of 'a' cases hold only
    characters up to U+00FF (one byte each); 'w' cases may hold any BMP
    character (one UTF-16 unit each)."""
    hi, top = HI, chr(0xFF)
    F = [
        ("empty", [""]),
        ("plain", ["a", "ab", "abc", "Paper_Space", "x" * 12, "x" * 50,
                   "abcdefghij" * 20, "a" * 3000]),
        ("ctlfirst", [CTL + "a", CTL + "abc", CTL + CTL + "ab", "\x13ab"]),
        ("one", list(SPECIALS)),
        ("second", ["x" + c for c in SPECIALS]),
        ("third", ["xy" + c for c in SPECIALS]),
        ("pair", ["x" + c + c for c in '&<"']),
        ("afterctl", ["x" + CTL + c for c in SPECIALS]),
        ("afterhigh", ["x" + hi + c for c in SPECIALS]),
        ("highrun", ["x" + hi + c * k for c in "&<" for k in (3, 12, 40, 100)]),
        ("run", ["x" + c * k for c in '&"' for k in (1, 10, 50)]),
        ("mixed", ["ab&cd", "ab<cd>ef", 'one "two" three', "k='v'", "{a}{b}", "a`b`c"]),
        ("highonly", [hi, "x" + hi, hi * 3, "x" + top + chr(0x7F)]),
        ("boundary", [CTL + chr(c) + "y" for c in (0x13, 0x14, 0x7E, 0x7F, 0x80, 0xFF)]),
        ("validspec", [CTL + hi + "".join(SPECIALS),
                       CTL + hi + "&<>\"'`{}" * 2]),
        ("cap", [CTL + hi + '"' * k for k in range(1, 17)]),
        ("longmixed", ["x" + "ab&" * 400]),
    ]
    if func == "w":
        F += [
            ("wideboundary", [CTL + chr(c) + "y" for c in (0x100, 0x20AC, 0x4E2D, 0xFFFF)]),
            ("widecap", [CTL + chr(0xFFFF) * k for k in range(1, 13)]),
            ("widemixed", ["x" + chr(0x20AC) + "&", "x" + chr(0xFFFF) + "<a>",
                           CTL + chr(0x4E2D) + '"' * 5, "ab" + chr(0x20AC) + "{" + chr(0xFFFF) + "}"]),
        ]
    return F


# families whose strings must give the same output on every build (a
# control character first, the character after it escaped without a
# preceding plain character); their outputs enter the valid-output digest
VALID = {"empty", "ctlfirst", "boundary", "validspec", "cap",
         "wideboundary", "widecap"}


def random_texts(func, n, seed):
    rnd = random.Random(seed)
    wide = func == "w"
    classes = [
        (6, lambda: rnd.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")),
        (1, lambda: rnd.choice("0123456789 _-*.,:/")),
        (3, lambda: rnd.choice(SPECIALS)),
        (1.5, lambda: chr(rnd.choice([0x7F, 0x80, 0xE9, 0xFF] + ([0x100, 0x20AC, 0x4E2D, 0xFFFF] if wide else [])))),
        (0.5, lambda: chr(rnd.choice([1, 9, 10, 0x13]))),
    ]
    weights = [w for w, _ in classes]
    out = []
    for _ in range(n):
        k = rnd.randint(1, 40)
        out.append("".join(rnd.choices(classes, weights)[0][1]() for _ in range(k)))
    return out


RANDOM = {"a": (200, 182), "w": (200, 21816)}


def unit_cases():
    """List of dicts: name, func, text, family, valid."""
    cases = []
    for func in ("a", "w"):
        fams = families(func) + [("rand", random_texts(func, *RANDOM[func]))]
        for fam, texts in fams:
            for i, t in enumerate(texts, 1):
                cases.append({"name": "%s_%s_n%02d" % (func, fam, i) if fam != "rand" else "%s_%s_n%03d" % (func, fam, i),
                              "func": func, "text": t, "family": fam, "valid": fam in VALID})
    cases.append({"name": "a_null_n1", "func": "A", "text": None, "family": "null", "valid": True})
    cases.append({"name": "w_null_n1", "func": "W", "text": None, "family": "null", "valid": True})
    return cases


# ------------------------------------------------------------ file cases

# The eight reproducers of LibreDWG/libredwg#182 (comments of linhlhq,
# 2020-01-10) and the function each report names. Files are fetched by
# scripts/libredwg_fetch_issue182.py into the --inputs directory.
ISSUE182 = [
    # case, file name, sha256, report number, function named in the report
    ("issue182_r1", "id:000013,sig:06,src:000000,op:flip1,pos:46417",
     "64f5a46703b61be2c077d44c4b92dc50518044d8bef52ff2a3fb8cb85acee841", 1, "htmlescape NULL source"),
    ("issue182_r2", "id:000016,sig:06,src:000000,op:flip1,pos:125355",
     "4edd7ea0c98e8bf66c8edeea2baa8534dc3eda3b0e712244a312ba44efa7ee94", 2, "htmlescape"),
    ("issue182_r3", "id:000015,sig:06,src:000000,op:flip1,pos:46436",
     "ec2bc55519cc5f6afa364514472dda2629a0e1dd2d507ac4c180e0ac11bfa66c", 3, "htmlescape"),
    ("issue182_r4", "id:000020,sig:06,src:000000,op:flip1,pos:138350",
     "62661f5bc4061646c3375f911be3b6f1a8505c0057c2eb305948752793ed5821", 4, "output_TEXT NULL"),
    ("issue182_r5", "id:000109,sig:06,src:001432+002572,op:splice,rep:2",
     "ed53d33032d4734bfd53bc977c6c6597e545b105be0665ce9862b422573f1d52", 5, "output_TEXT"),
    ("issue182_r6", "id:000025,sig:06,src:000804,op:havoc,rep:2",
     "55fcc9e6170799c9359d258bc263af9276b92e1c78b2b6d85b3975e651a3765b", 6, "htmlwescape"),
    ("issue182_r7", "id:000144,sig:06,src:005649,op:havoc,rep:2",
     "a885fc52683ff3e2eccd9c8311d94b6475092aecbc687305133aaf3a639a1724", 7, "htmlescape"),
    ("issue182_r8", "id:000099,sig:06,src:005125+003017,op:splice,rep:8",
     "13ce44421ec4a55f01d4587d711875a016d779dc34277874c84e528d25ac9584", 8, "htmlwescape"),
]

# Twelve-byte strings written over the block name "*Paper_Space" of
# test/test-data/example_2000.dwg (12 bytes at offset 125353, the byte
# position of the reporter's mutation in #182 item 2; "poc" gives the
# dataset PoC again and "orig" the unchanged file).
BLK_FILE = "test/test-data/example_2000.dwg"
BLK_OFFSET = 125353
BLK_ORIG = b"*Paper_Space"
BLK12 = [
    ("orig", "*Paper_Space"),
    ("plain", "abcdefghijkl"),
    ("mid", "abcde&fghijk"),
    ("first", "&bcdefghijkl"),
    ("last", "abcdefghijk&"),
    ("angle", "abcd<ef>ghij"),
    ("quotes", "ab\"cd'efghij"),
    ("tick", "abcdef`ghijk"),
    ("braces", "abc{def}ghij"),
    ("run", "&" * 12),
    ("all", "a<b>c&d\"e'f`"),
    ("poc", "*P`per_Space"),
]

# Strings written over the TEXT value "teksto simpla" of
# test/test-data/example_2000.dxf, which programs/dwgwrite turns into an
# R2000 DWG file.
TXT = [
    ("plain", "name"),
    ("mid", "a&b"),
    ("first", "&ab"),
    ("last", "ab&"),
    ("angle", "<a>"),
    ("quotes", "a\"b'c"),
    ("tick", "a`b"),
    ("braces", "{a}"),
    ("run", "&" * 12),
    ("long", "abcdefghijklmnopqrstuvwxyz0123456789"),
    ("all", "a<b>c&d\"e'f`g{h}i"),
    ("poc", "*P`per_Space"),
]
TXT_BASE_DXF = "test/test-data/example_2000.dxf"
TXT_ORIG = "teksto simpla"


def file_cases():
    cases = [{"name": "poc", "kind": "poc", "path": "/testcase/poc.dwg"}]
    for case, fname, sha, rep, fn in ISSUE182:
        cases.append({"name": case, "kind": "issue", "file": fname, "sha256": sha, "report": rep, "claim": fn})
    for i, (tag, value) in enumerate(BLK12, 1):
        cases.append({"name": "blk12_%s_n%02d" % (tag, i), "kind": "blk", "value": value})
    for i, (tag, value) in enumerate(TXT, 1):
        cases.append({"name": "txt_%s_n%02d" % (tag, i), "kind": "txt", "value": value})
    return cases


# --------------------------------------------------------------- running

def sha_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def hexify(text, wide):
    return "".join(("%04x" if wide else "%02x") % u for u in units(text, wide))


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, errors="replace", **kw)


def classify(rc, so, se, hang):
    m = MARK.search(se) or MARK.search(so)
    if m:
        return m.group(0).strip()
    m = MEM.search(se)
    if m:
        line = se[m.start():].splitlines()[0]
        line = re.sub(r" on (unknown )?address .*| \(pc .*| in \d+ object.*|^ERROR: ", "", line)
        return "ASAN " + line
    if hang:
        return "WRONG timeout"
    return None


def run_cmd(args, timeout=None, cwd=None):
    t0 = time.time()
    try:
        p = subprocess.run(args, capture_output=True, text=True, errors="replace",
                           timeout=timeout or T, cwd=cwd)
        return p.returncode, p.stdout, p.stderr, False, time.time() - t0
    except subprocess.TimeoutExpired as e:
        so = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        se = e.stderr.decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
        return None, so, se, True, time.time() - t0


def make_flags():
    mk = "print-flags:\n\t@echo $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)\n"
    p = subprocess.run(["make", "-s", "-C", str(TREE / "programs"), "-f", "Makefile", "-f", "-", "print-flags"],
                       input=mk, capture_output=True, text=True)
    return p.stdout.split()


def build_driver():
    WORK.mkdir(parents=True, exist_ok=True)
    out = WORK / "escape_driver"
    lib = TREE / "src" / ".libs" / "libredwg.a"
    cmd = ["clang"] + make_flags() + ["-o", str(out), str(HERE / "escape_driver.c"), "escape.c"]
    if lib.exists():
        cmd += [str(lib), "-lm"]
    p = subprocess.run(cmd, cwd=TREE / "programs", capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit("driver build failed:\n" + p.stderr[-2000:])
    return out, cmd


def esc(s):
    return s.replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t")


def run_unit(driver, case):
    wide = case["func"] in ("w", "W")
    arg = "" if case["text"] is None else hexify(case["text"], wide)
    args = [str(driver), case["func"]] + ([arg] if arg else [])
    rc, so, se, hang, el = run_cmd(args)
    want = "NULL" if case["text"] is None else "".join("%02x" % b for b in spec(case["text"], wide).encode("latin-1"))
    res = classify(rc, so, se, hang)
    got = so.strip()
    if res is None:
        if rc != 0:
            res = "WRONG exit=%s" % rc
        elif got == want:
            res = "OK"
        else:
            res = "WRONG got=%s want=%s" % (got[:120], want[:120])
    return res, got, el, args, se


def dwg_magic(path):
    return Path(path).read_bytes()[:6]


JSON_CHUNK = re.compile(r'(?="(?:object|entity)":\s*")')
JSON_NAME = re.compile(r'"name":\s*"((?:[^"\\]|\\.)*)"')
JSON_TEXT = re.compile(r'"text_value":\s*"((?:[^"\\]|\\.)*)"')


def json_strings(path, tmp):
    """(names, texts) of a DWG file from `dwgread -O json`, or None.
    The JSON writer of this revision does not always produce a document
    that parses (stray commas and braces, nan values), so the output is cut
    at its "object"/"entity" members and the name of each BLOCK_HEADER
    object and the text_value of each TEXT entity are read with patterns;
    the result is used only when every BLOCK_HEADER object has a name."""
    out = tmp / "ref.json"
    if out.exists():
        out.unlink()
    rc, so, se, hang, _ = run_cmd([str(TREE / "programs" / "dwgread"), "-O", "json", "-o", str(out), str(path)], timeout=60)
    if hang or not out.exists():
        return None
    names, texts, blocks = [], [], 0
    try:
        for chunk in JSON_CHUNK.split(out.read_text(errors="replace")):
            if chunk.startswith('"object": "BLOCK_HEADER"'):
                blocks += 1
                m = JSON_NAME.search(chunk)
                if m:
                    names.append(json.loads('"%s"' % m.group(1)))
            elif chunk.startswith('"entity": "TEXT"'):
                m = JSON_TEXT.search(chunk)
                if m:
                    texts.append(json.loads('"%s"' % m.group(1)))
    except ValueError:
        return None
    if not names or len(names) != blocks:
        return None
    return names, texts


SVG_NAME = re.compile(r"^\t\t<!-- (.*) -->$", re.M)
SVG_TEXT = re.compile(r'fill="blue">(.*)</text>$', re.M)


def svg_check(path, so, ref):
    """OK or a WRONG description: every name and text of the SVG must be the
    escaped form of a name or text of the file."""
    wide = dwg_magic(path) >= b"AC1021"
    names, texts = ref
    for s in names + texts:
        if not wide and any(ord(c) > 127 for c in s):
            return None
    en = collections.Counter(spec(s, wide) for s in names)
    et = collections.Counter(spec(s, wide) for s in texts)
    bad = [g for g in SVG_NAME.findall(so) if g not in en] + [g for g in SVG_TEXT.findall(so) if g not in et]
    return "OK" if not bad else "WRONG svg has %d unexpected string(s), first %r" % (len(bad), bad[0][:60])


def run_dwg(path, tmp, use_ref=True):
    rc, so, se, hang, el = run_cmd([str(TREE / "programs" / "dwg2SVG"), str(path)])
    res = classify(rc, so, se, hang)
    ref = None
    if res is None:
        ref = json_strings(path, tmp) if use_ref else None
        res = svg_check(path, so, ref) if ref else None
        if res is None:
            res = "OK"
    return res, so, se, el, ref is not None


def gen_dwg(case, tmp, inputs=None):
    """Write the input of a blk12 or txt case; returns (path, note). A file
    <inputs>/<case>.dwg (written earlier by `escape_cases.py gen`) is used
    as it is, so that variants built from other trees get the same bytes."""
    d = tmp / case["name"]
    d.mkdir(parents=True, exist_ok=True)
    if inputs and (Path(inputs) / (case["name"] + ".dwg")).exists():
        return Path(inputs) / (case["name"] + ".dwg"), "pre-generated file of the inputs directory"
    if case["kind"] == "blk":
        data = bytearray((TREE / BLK_FILE).read_bytes())
        if bytes(data[BLK_OFFSET:BLK_OFFSET + 12]) != BLK_ORIG:
            return None, "bytes at offset %d are not the original name" % BLK_OFFSET
        data[BLK_OFFSET:BLK_OFFSET + 12] = case["value"].encode("latin-1")
        (d / "gen.dwg").write_bytes(bytes(data))
        return d / "gen.dwg", "12 bytes at offset %d of %s" % (BLK_OFFSET, BLK_FILE)
    dxf = (TREE / TXT_BASE_DXF).read_text(encoding="latin-1")
    dxf, n = re.subn(r"(?m)^(  1\n)%s$" % TXT_ORIG, lambda m: m.group(1) + case["value"], dxf)
    (d / "in.dxf").write_text(dxf, encoding="latin-1")
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
    subprocess.run([str(TREE / "programs" / "dwgwrite"), "-y", "-o", str(d / "gen.dwg"), str(d / "in.dxf")],
                   capture_output=True, text=True, errors="replace", env=env, timeout=120)
    if not (d / "gen.dwg").exists():
        return None, "dwgwrite failed"
    return d / "gen.dwg", "%d replacement(s) in %s, written by dwgwrite" % (n, TXT_BASE_DXF)


def cmd_run(inputs):
    driver, cmd = build_driver()
    tmp = WORK / "files"
    tmp.mkdir(parents=True, exist_ok=True)
    print("--- runner escape_cases.py sha256 %s" % sha_file(__file__))
    print("--- driver %s" % " ".join(cmd))
    print("--- driver source escape_driver.c sha256 %s" % sha_file(HERE / "escape_driver.c"))
    print("--- env: ASAN_OPTIONS=%s timeout=%ss jobs=%s python %s" % (
        os.environ.get("ASAN_OPTIONS", "<unset>"), T, JOBS, sys.version.split()[0]))
    only = os.environ.get("CASE_ONLY")
    units_ = [c for c in unit_cases() if not only or re.search(only, c["name"])]
    files = [c for c in file_cases() if not only or re.search(only, c["name"])]
    counts = {"OK": 0, "WRONG": 0, "ASAN": 0, "INV": 0}
    timeouts = 0
    digest = hashlib.sha256()

    def tally(res):
        counts["INV" if MARK.match(res) else res.split()[0]] += 1

    with ThreadPoolExecutor(max_workers=JOBS) as pool:
        uruns = list(pool.map(lambda c: run_unit(driver, c), units_))
    for case, (res, got, el, args, se) in zip(units_, uruns):
        tally(res)
        timeouts += res == "WRONG timeout"
        if case["valid"]:
            digest.update(("%s\t%s\n" % (case["name"], got)).encode())
        print("%-32s %s" % (case["name"], res))
        print("    $ %s %s %s" % (os.path.basename(args[0]), args[1], (args[2][:60] + "...") if len(args) > 2 and len(args[2]) > 60 else (args[2] if len(args) > 2 else "")))
        print("    elapsed=%.1fs stdout=%s" % (el, esc(got)[:100]))
        for l in se.splitlines()[:3]:
            print("    | %s" % l[:160])

    paths = {}
    for c in files:
        if c["kind"] == "poc":
            paths[c["name"]] = Path(c["path"])
            print("--- input %s %s sha256 %s" % (c["name"], c["path"], sha_file(c["path"]) if Path(c["path"]).exists() else "missing"))
        elif c["kind"] == "issue":
            p = Path(inputs or ".") / c["file"]
            paths[c["name"]] = p
            print("--- input %s %s sha256 %s expect %s" % (
                c["name"], c["file"], sha_file(p) if p.exists() else "missing", c["sha256"][:12]))
        else:
            p, note = gen_dwg(c, tmp, inputs)
            paths[c["name"]] = p
            print("--- input %s %s, sha256 %s" % (c["name"], note, sha_file(p) if p else "none"))

    def one(c):
        p = paths[c["name"]]
        if p is None or not Path(p).exists():
            return "WRONG input missing", "", "", 0.0, False
        d = tmp / ("ref_" + c["name"])
        d.mkdir(parents=True, exist_ok=True)
        return run_dwg(p, d, use_ref=c["kind"] != "issue")

    with ThreadPoolExecutor(max_workers=JOBS) as pool:
        fruns = list(pool.map(one, files))
    for c, (res, so, se, el, ref) in zip(files, fruns):
        tally(res)
        timeouts += res == "WRONG timeout"
        print("%-32s %s" % (c["name"], res))
        print("    $ dwg2SVG %s" % (paths[c["name"]].name if paths[c["name"]] else "-"))
        print("    elapsed=%.1fs svg_lines=%d reference=%s" % (el, so.count("\n"), "json" if ref else "none"))
        for l in se.splitlines()[:3]:
            print("    | %s" % l[:160])
    total = len(units_) + len(files)
    print("summary: %d cases; %d OK, %d WRONG, %d ASAN, %d INV; timeouts %d; valid outputs %s" % (
        total, counts["OK"], counts["WRONG"], counts["ASAN"], counts["INV"], timeouts, digest.hexdigest()[:12]))


def cmd_corpus():
    tmp = WORK / "corpus"
    tmp.mkdir(parents=True, exist_ok=True)
    files = sh(["git", "ls-files", "*.dwg"], cwd=TREE).stdout.split()
    print("--- runner escape_cases.py sha256 %s" % sha_file(__file__))
    print("--- corpus %d tracked DWG files; env: ASAN_OPTIONS=%s timeout=%ss jobs=%s" % (
        len(files), os.environ.get("ASAN_OPTIONS", "<unset>"), T, JOBS))

    def one(f):
        d = tmp / re.sub(r"\W", "_", f)
        d.mkdir(exist_ok=True)
        res, so, se, el, ref = run_dwg(TREE / f, d)
        return res, so, ref

    with ThreadPoolExecutor(max_workers=JOBS) as pool:
        runs = list(pool.map(one, files))
    counts = collections.Counter()
    digest = hashlib.sha256()
    for f, (res, so, ref) in zip(files, runs):
        cls = "INV" if MARK.match(res) else res.split()[0]
        if cls == "OK" and not ref:
            cls = "NOREF"
        counts[cls] += 1
        h = hashlib.sha256(so.encode(errors="replace")).hexdigest()[:12]
        digest.update(("%s\t%s\t%s\n" % (f, cls, h)).encode())
        print("%-44s %s stdout=%s magic=%s" % (f, res if cls != "NOREF" else "NOREF", h,
                                              (TREE / f).read_bytes()[:6].decode("latin-1")))
    print("corpus: %d files; %d OK, %d WRONG, %d ASAN, %d INV, %d NOREF; digest %s" % (
        len(files), counts["OK"], counts["WRONG"], counts["ASAN"], counts["INV"], counts["NOREF"],
        digest.hexdigest()[:12]))


def cmd_gen(outdir):
    """Write the blk12 and txt input files of the current tree to OUTDIR."""
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    tmp = WORK / "gen"
    for c in file_cases():
        if c["kind"] in ("blk", "txt"):
            p, note = gen_dwg(c, tmp)
            if p is None:
                sys.exit("%s: %s" % (c["name"], note))
            (out / (c["name"] + ".dwg")).write_bytes(Path(p).read_bytes())
            print("%s %s sha256 %s" % (c["name"], note, sha_file(p)))


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    mode = sys.argv[1]
    if mode == "gen":
        cmd_gen(sys.argv[2])
    elif mode == "run":
        inputs = sys.argv[sys.argv.index("--inputs") + 1] if "--inputs" in sys.argv else None
        cmd_run(inputs)
    elif mode == "corpus":
        cmd_corpus()
    elif mode == "list":
        for c in unit_cases() + file_cases():
            print(c["name"])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
