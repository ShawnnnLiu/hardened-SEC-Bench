r"""Write the JavaScript case files for njs.cve-2019-13617 (heap-buffer-overflow
read while parsing an unterminated regexp literal in njs_regexp_literal).

Usage:
  python3 relit_cases.py OUTDIR
      write OUTDIR/<case>.js and OUTDIR/cases.tsv
  python3 relit_cases.py --oracle ENGINE OUTDIR > EXPECTED.tsv
      write the case files, then print the TSV case<TAB>output for
      scripts/njs_cases.py: for a kind=valid case the output is ENGINE's
      stdout on the file (e.g. node), and for a kind=crash case the output
      is the empty string, because an unterminated regexp literal is a
      parse error in every engine (ENGINE cannot run it; the only
      observable is whether njs ends with or without a sanitizer report).

cases.tsv columns: case, kind (valid or crash), site (which scan path of
njs_regexp_literal the case exercises), viol (1 when the case reaches the
faulty state on the base build: the failed: span reaches past the input
buffer), absent (the key scripts/njs_cases.py uses for its valid-output
digest: "none" for a valid case that prints a value, "scan" for a crash
case that prints nothing).

Mechanism under test (src/njs_regexp.c:njs_regexp_literal at the base
commit 15fc1a04, version 0.3.6):

njs_regexp_literal scans a regexp literal from lexer->start to the closing
'/'.  The invariant that the reported failure requires: when the scan
fails and reaches the failed: label, the scan pointer p must satisfy
p <= lexer->end, so that the reported span passed to njs_parser_scope_error
as the "%*s" width (p - (lexer->start - 1)) does not exceed the input
buffer.  njs_vsprintf copies that width from the source with njs_cpymem
(a memcpy) clamped only by the output buffer size (NJS_MAX_ERROR_STR =
2048), not by the input length, so a width larger than the input buffer
reads past the end of the heap region that holds the script source: the
reported heap-buffer-overflow read, top frames __asan_memcpy /
njs_vsprintf (src/njs_sprintf.c) / njs_parser_scope_error (src/njs_parser.c).

Three scan paths in njs_regexp_literal advance p without stopping at
lexer->end on the base build, so an unterminated literal that ends inside
one of them leaves p past lexer->end at failed::
  - the character-class loop `while (++p < lexer->end && *p != ']')`
    (site cls): on exit because ++p reached the end it keeps the outer
    for-loop's p++ which steps one more;
  - the character-class backslash `if (++p < lexer->end && (*p=='\n'||'\r'))`
    (site clsbs): ++p past the end short-circuits the test, the switch
    breaks, the while adds one more;
  - the outer backslash `if (++p < lexer->end && (*p=='\n'||'\r'))`
    (site outbs): same, then the outer for-loop p++ steps one more.
The developer patch rewrites all three so that ++p reaching lexer->end
goes to failed with p == lexer->end (no step past the end).

Families:
  crash (kind=crash): an unterminated regexp literal whose scan ends
    inside one of the three paths; the whole source is a parse error.
      cls_bare   `/[`            site cls    (class, immediate end)
      cls_tail   `/[abc`         site cls    (class with content)
      clsbs_tail `/[\`           site clsbs  (class, trailing backslash)
      outbs_tail `/\`            site outbs  (outer trailing backslash)
      plain      `/abc`          site plain  (unterminated, no class, no
                                 backslash; the outer for-loop exits at
                                 p == lexer->end; control for whether a
                                 plain unterminated literal over-reads)
  valid (kind=valid): a terminated regexp literal that parses and whose
    match or source is printed; the patch must not change it.  Each
    exercises one patched scan path.
      val_cls      /[abc]/.test('b')      site cls    -> true
      val_clsbs    /[\]]/.test(']')       site clsbs  -> true
      val_outbs    /a\/b/.test('a/b')     site outbs  -> true
      val_plain    /abc/.test('abc')      site plain  -> true

The observable of a valid case is printed with console.log, which njs
0.3.6 supports in file mode and which Node prints identically for these
inputs.  A crash case prints nothing (it fails to parse), so its expected
output is the empty string and it is classified by the presence of a
sanitizer report.

The dataset PoC (/testcase/poc.js, run as the extra case "poc" by
scripts/njs_cases.py) is a 233-byte source whose first regexp literal is
an unterminated character class with many '[' bytes (site cls); it prints
nothing and is expected to end without a sanitizer report.
"""
import subprocess
import sys
from pathlib import Path

# case -> (kind, site, viol, body)
# body is the full source of the case file.
CASES = {}


def add(name, kind, site, viol, body):
    absent = "none" if kind == "valid" else "scan"
    CASES[name] = (kind, site, viol, absent, body)


# crash: an unterminated regexp literal; the source is a parse error.  No
# trailing newline: a '\n' or '\r' is caught by the case '\n'/'\r' arms and
# stops the scan before lexer->end, so the buffer must end mid-scan.
add("cls_bare", "crash", "cls", 1, "/[")
add("cls_tail", "crash", "cls", 1, "/[abc")
add("clsbs_tail", "crash", "clsbs", 1, "/[\\")
add("outbs_tail", "crash", "outbs", 1, "/\\")
add("plain", "crash", "plain", 0, "/abc")

# valid: a terminated regexp literal that parses; the patch must not change
# its result.  console.log prints the observable.
add("val_cls", "valid", "cls", 0, "console.log(/[abc]/.test('b'))\n")
add("val_clsbs", "valid", "clsbs", 0, "console.log(/[\\]]/.test(']'))\n")
add("val_outbs", "valid", "outbs", 0, "console.log(/a\\/b/.test('a/b'))\n")
add("val_plain", "valid", "plain", 0, "console.log(/abc/.test('abc'))\n")


def write_files(outdir):
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    rows = ["\t".join(["case", "kind", "site", "viol", "absent"])]
    for name in sorted(CASES):
        kind, site, viol, absent, body = CASES[name]
        (out / (name + ".js")).write_text(body)
        rows.append("\t".join([name, kind, site, str(viol), absent]))
    (out / "cases.tsv").write_text("\n".join(rows) + "\n")
    return out


def oracle(engine, outdir):
    out = write_files(outdir)
    ver = subprocess.run([engine, "--version"], capture_output=True, text=True).stdout.strip()
    print(f"# oracle {engine} {ver} for valid cases; crash cases expected empty stdout (parse error)")
    print("case\toutput")
    for name in sorted(CASES):
        kind = CASES[name][0]
        if kind == "valid":
            p = subprocess.run([engine, str(out / (name + ".js"))],
                               capture_output=True, text=True, errors="replace")
            if p.returncode != 0 or p.stderr.strip():
                sys.exit(f"oracle run of {name} failed: rc={p.returncode} stderr={p.stderr[:200]!r}")
            o = p.stdout.rstrip("\n").replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t")
            print(f"{name}\t{o}")
        else:
            print(f"{name}\t")


def main():
    args = sys.argv[1:]
    if args and args[0] == "--oracle":
        oracle(args[1], args[2])
        return
    if len(args) != 1:
        sys.exit("usage: python3 relit_cases.py OUTDIR | --oracle ENGINE OUTDIR")
    write_files(args[0])
    print(f"{len(CASES)} cases written to {args[0]}")


if __name__ == "__main__":
    main()
