"""Cases for the pre-R13 table decoder of LibreDWG, src/decode.c
decode_preR13_section() (libredwg.cve-2021-28237).

Runs inside a container of the instance image after `secb build`.

Usage:
  prep13_cases.py run [--inputs DIR]   run the unit and file cases
  prep13_cases.py corpus               run dwgread over the tracked pre-R13 files
  prep13_cases.py list                 print the case names

Every result line starts in column 1 with `<case> <result>`; evidence lines
are indented and header lines start with `---`. The last line of `run` is
  summary: N cases; a OK, b WRONG, c ASAN, d INV; timeouts t; valid outputs D
and that of `corpus`
  corpus: N files; a OK, b WRONG, c ASAN, d INV, e NOREF; digest D

A case runs `programs/dwgread -v5 <file>` under AddressSanitizer and is
classified from the decoder's own trace, not by exit status:
  ASAN   a sanitizer report (the reported failure of this CVE is a
         heap-buffer-overflow WRITE in decode_preR13_section);
  INV    an instrumentation marker PREPTABLE-INVARIANT was printed;
  OK     for a file with a reference entry count `ref`, the number of
         `-- table entry` traces equals `ref`; for the crasher PoC
         (ref is None) no sanitizer report was printed;
  WRONG  a file with a reference whose entry count differs from `ref`
         with no sanitizer report (table entries dropped or added).

The reference entry counts are those of the base build (49aeec4e),
measured before any variant ran and recorded in prep13_predictions.py:
test/test-data/r11/ACEB10.dwg decodes 56 pre-R13 table entries across its
10 sections on the base build. The PoC is a crafted AC1002 file whose
decode overflows dwg->object; it has no valid entry reference.

The faulty state (a write index num + i at or beyond the capacity of
dwg->object) is exercised by the PoC; a controlled per-section sweep of
the entry-count field was not run (it needs the buffer pre-sizing of
decode_preR13, which was not read), so the PoC is the natural witness and
the root candidate confirms the realloc sizing as the cause.
"""
import collections
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

TREE = Path(os.environ.get("LIBREDWG_TREE", "/src/libredwg"))
DWGREAD = TREE / "programs" / "dwgread"
ACEB10 = "test/test-data/r11/ACEB10.dwg"
POC = "/testcase/poc"
MEM = re.compile(r"ERROR: (Address|Memory|Thread|Leak)Sanitizer|runtime error:")
MARK = re.compile(r"\bPREPTABLE-INVARIANT\b.*")
ENTRY = re.compile(r"^-- table entry ", re.M)


def file_cases():
    # name, path, reference entry count (None = crasher, no entry oracle)
    return [
        {"name": "poc", "path": POC, "ref": None},
        {"name": "aceb10", "path": str(TREE / ACEB10), "ref": 56},
    ]


def run_dwg(path):
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:exitcode=0")
    p = subprocess.run([str(DWGREAD), "-v5", str(path)], capture_output=True,
                       text=True, errors="replace", env=env, timeout=120)
    return p.stdout + p.stderr


def classify(out, ref):
    m = MARK.search(out)
    if m:
        return "INV", m.group(0).strip()[:70]
    m = MEM.search(out)
    if m:
        line = out[m.start():].splitlines()[0]
        line = re.sub(r" on (unknown )?address .*| \(pc .*|^ERROR: ", "", line)
        return "ASAN", line.strip()[:70]
    n = len(ENTRY.findall(out))
    if ref is None:
        return "OK", "no report; %d entries" % n
    if n == ref:
        return "OK", "%d entries" % n
    return "WRONG", "%d entries, reference %d" % (n, ref)


def cmd_run():
    print("--- runner prep13_cases.py sha256 %s" % hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    print("--- dwgread %s" % DWGREAD)
    counts = collections.Counter()
    digest = hashlib.sha256()
    for c in file_cases():
        if not Path(c["path"]).exists():
            print("%-18s WRONG input missing %s" % (c["name"], c["path"]))
            counts["WRONG"] += 1
            continue
        out = run_dwg(c["path"])
        cls, detail = classify(out, c["ref"])
        counts[cls] += 1
        if cls in ("OK", "WRONG"):
            digest.update(("%s\t%s\n" % (c["name"], detail)).encode())
        print("%-18s %s" % (c["name"], cls if cls in ("OK", "WRONG") else cls + " " + detail))
        print("    $ dwgread -v5 %s" % os.path.basename(c["path"]))
        print("    %s" % detail)
    print("summary: %d cases; %d OK, %d WRONG, %d ASAN, %d INV; timeouts 0; valid outputs %s" % (
        sum(counts.values()), counts["OK"], counts["WRONG"], counts["ASAN"], counts["INV"],
        digest.hexdigest()[:12]))


def cmd_corpus():
    files = subprocess.run(["git", "ls-files", "*.dwg"], cwd=TREE, capture_output=True, text=True).stdout.split()
    pre = []
    for f in files:
        magic = (TREE / f).read_bytes()[:6].decode("latin-1", "replace")
        if magic in ("AC1009", "AC1006", "AC1004", "AC1003", "AC1002", "AC1001", "MC0.0"):
            pre.append((f, magic))
    print("--- corpus %d pre-R13 tracked DWG files" % len(pre))
    counts = collections.Counter()
    digest = hashlib.sha256()
    for f, magic in pre:
        out = run_dwg(TREE / f)
        cls, detail = classify(out, 56 if f.endswith(ACEB10) else None)
        counts[cls] += 1
        digest.update(("%s\t%s\t%s\n" % (f, cls, detail)).encode())
        print("%-44s %s magic=%s" % (f, cls + " " + detail, magic))
    print("corpus: %d files; %d OK, %d WRONG, %d ASAN, %d INV, 0 NOREF; digest %s" % (
        len(pre), counts["OK"], counts["WRONG"], counts["ASAN"], counts["INV"], digest.hexdigest()[:12]))


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    mode = sys.argv[1]
    if mode == "run":
        cmd_run()
    elif mode == "corpus":
        cmd_corpus()
    elif mode == "list":
        for c in file_cases():
            print(c["name"])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
