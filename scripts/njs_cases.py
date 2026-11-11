"""Run JavaScript case files through an engine and classify each run
against the outputs of a reference engine (njs instances).

Usage:
  python3 njs_cases.py --oracle ENGINE CASEDIR > EXPECTED.tsv
      run every CASEDIR/*.js with the reference engine ENGINE (e.g. node)
      and print the TSV case<TAB>output, output with \\n, \\t and \\\\
      escaped; the header line names the engine version.
  python3 njs_cases.py ENGINE CASEDIR EXPECTED.tsv [--extra NAME=PATH]...
      run every case of EXPECTED.tsv (CASEDIR/<case>.js) and every extra
      file with ENGINE (e.g. /src/njs/build/njs) and print one result
      line per case. An extra file has the expected output "" (a run
      that ends without a sanitizer report and prints nothing; the
      dataset PoC).

Result of a run, in this order of precedence:
  <MARKER>-INVARIANT ...  an instrumented invariant check fired (the line
                          it printed)
  ASAN <type>             an AddressSanitizer or UBSan error report
  WRONG timeout           the run did not end within CASE_TIMEOUT seconds
  WRONG got=<..> want=<..> standard output differs from the expected
                          output (first stderr line appended)
  OK                      standard output equals the expected output
Evidence (command, exit status, elapsed time and at most 60 lines of
stderr) follows each result line, indented, so that only result lines
start in column 1. When CASEDIR/cases.tsv has an "absent" column, the
summary digest covers the outputs of the cases whose absent value is
"none" (valid inputs). The header names the sha256 of this script and of
EXPECTED.tsv. The last line is
  summary: N cases; a OK, b WRONG, c ASAN, d INV; timeouts t; valid outputs D
with D the first 12 hex digits of the sha256 over "<case>\\t<output>" of
the valid-input cases.
Environment: CASE_TIMEOUT (seconds, default 60), CASE_JOBS (cases run
at the same time, default the number of CPUs; results are printed in case
order).
"""
import hashlib
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

T = int(os.environ.get("CASE_TIMEOUT", "60"))
JOBS = int(os.environ.get("CASE_JOBS", str(len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else os.cpu_count() or 1)))
MEM = re.compile(r"ERROR: (Address|Memory|Thread|Leak)Sanitizer|runtime error:")
MARK = re.compile(r"\b[A-Z]+-INVARIANT\b.*")


def esc(s):
    return s.replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t")


def unesc(s):
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t"}.get(m.group(1), m.group(1)), s)


def run(engine, path):
    t0 = time.time()
    try:
        p = subprocess.run([engine, str(path)], capture_output=True, text=True,
                           errors="replace", timeout=T)
        rc, so, se, hang = p.returncode, p.stdout, p.stderr, False
    except subprocess.TimeoutExpired as e:
        so = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        se = e.stderr.decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
        rc, hang = None, True
    return rc, so.rstrip("\n"), se, hang, time.time() - t0


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def oracle(engine, casedir):
    ver = subprocess.run([engine, "--version"], capture_output=True, text=True).stdout.strip()
    print(f"# oracle {engine} {ver}; runner njs_cases.py sha256 {sha(__file__)}")
    print("case\toutput")
    for path in sorted(Path(casedir).glob("*.js")):
        rc, so, se, hang, _ = run(engine, path)
        if hang or rc != 0 or se.strip():
            sys.exit(f"oracle run of {path.name} failed: rc={rc} hang={hang} stderr={se[:200]!r}")
        print(f"{path.stem}\t{esc(so)}")


def classify(rc, so, se, hang, want):
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
    if so == want:
        return "OK"
    first = next((l for l in se.splitlines() if l.strip()), "")
    return f"WRONG got={esc(so)[:200]} want={esc(want)[:200]}" + (f" stderr={first[:120]}" if first else "")


def main():
    args = sys.argv[1:]
    if args[0] == "--oracle":
        oracle(args[1], args[2])
        return
    engine, casedir, expected = args[0], Path(args[1]), args[2]
    extras = []
    rest = args[3:]
    while rest:
        flag, val = rest.pop(0), rest.pop(0)
        assert flag == "--extra"
        name, _, path = val.partition("=")
        extras.append((name, Path(path)))
    want = {}
    for line in open(expected):
        if line.startswith("#") or line.startswith("case\t"):
            continue
        name, _, o = line.rstrip("\n").partition("\t")
        want[name] = unesc(o)
    absent = {}
    meta = casedir / "cases.tsv"
    if meta.exists():
        rows = [l.rstrip("\n").split("\t") for l in open(meta)]
        if "absent" in rows[0]:
            i = rows[0].index("absent")
            absent = {r[0]: r[i] for r in rows[1:]}
    print(f"--- runner njs_cases.py sha256 {sha(__file__)}")
    print(f"--- expected {expected} sha256 {sha(expected)}")
    print(f"--- engine {engine} timeout={T}s jobs={JOBS} ASAN_OPTIONS={os.environ.get('ASAN_OPTIONS', '<unset>')}")
    for name, path in extras:
        print(f"--- extra {name} {path} sha256 {sha(path)} expect=no output")
    counts = {"OK": 0, "WRONG": 0, "ASAN": 0, "INV": 0}
    timeouts = 0
    digest = hashlib.sha256()
    todo = [(n, casedir / f"{n}.js", want[n]) for n in sorted(want)] + [(n, p, "") for n, p in extras]
    with ThreadPoolExecutor(max_workers=JOBS) as pool:
        runs = list(pool.map(lambda t: run(engine, t[1]), todo))
    for (name, path, w), (rc, so, se, hang, el) in zip(todo, runs):
        res = classify(rc, so, se, hang, w)
        cls = "INV" if MARK.match(res) else res.split()[0]
        counts[cls] += 1
        timeouts += hang
        if absent.get(name) == "none":
            digest.update(f"{name}\t{so}\n".encode())
        print(f"{name:<32} {res}")
        print(f"    $ {engine} {path}")
        print(f"    exit={'timeout' if hang else rc} elapsed={el:.1f}s stdout={esc(so)[:300]}")
        for l in se.splitlines()[:60]:
            print(f"    | {l}")
    print(f"summary: {len(todo)} cases; {counts['OK']} OK, {counts['WRONG']} WRONG, {counts['ASAN']} ASAN, "
          f"{counts['INV']} INV; timeouts {timeouts}; valid outputs {digest.hexdigest()[:12]}")


if __name__ == "__main__":
    main()
