"""Compare two scripts/njs_run_tests.sh logs per test (njs instances).

Usage: python3 njs_compare_tests.py BEFORE.log AFTER.log

unit: build/njs_unit_test -v prints each test script, quoted, before
  running it and an njs("...") expected/got block after a failing one;
  each suite ends with "<suite> tests: PASSED|FAILED [p/t]". A record
  starts at a line that begins with a double quote when the previous
  record is complete (its text ends with a double quote) and runs to the
  next record or report line, so a test is identified by its suite and
  script text (with the occurrence number for repeated scripts). The
  suites vm_json, vm_value and vm_internal_api print no script lines and
  are compared by their report line only; a suite whose record count
  differs from its reported total is noted. A record is
  failed when it contains an njs(" block. Tests present in one log only
  are listed separately (tests added by a patch).
test262: one "<test> <log> PASSED|FAILED" line per test file.
lib: the exit status of each *_unit_test binary.
shell: the exit status and the number of interactive sessions. The
  transcript is reported as identical or not but not counted as a
  difference: test/shell_test.exp sends Ctrl-C as soon as its pattern
  matches, so how much completion output the transcript holds depends on
  timing, and an expect timeout is not reported as a failure.
Prints per suite the tests whose result differs, the tests present in one
log only, and a summary line; exits 1 if a test common to both logs
differs.
"""
import re
import sys
from collections import Counter

REPORT = re.compile(r"^(.+) tests: (PASSED|FAILED) \[(\d+)/(\d+)\]$")


def sections(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    out = {}
    for m in re.finditer(r"^=== SUITE (\w+)\n(.*?)^SUITE \1 exit=(\d+)", text, re.S | re.M):
        out[m.group(1)] = (m.group(2), int(m.group(3)))
    return out


def unit(body):
    tests, suite_recs, cur = {}, [], None
    for line in body.split("\n"):
        r = REPORT.match(line)
        if r:
            if cur is not None:
                suite_recs.append(cur)
                cur = None
            if len(suite_recs) != int(r.group(4)):
                print(f"  note: suite {r.group(1)!r}: {len(suite_recs)} records for {r.group(4)} reported tests")
            seen = Counter()
            for script, failed in suite_recs:
                seen[script] += 1
                tests[(r.group(1), script, seen[script])] = "FAILED" if failed else "PASSED"
            suite_recs = []
            continue
        complete = cur is None or cur[1] or (len(cur[0]) > 1 and cur[0].endswith('"'))
        if line.startswith('"') and complete:
            if cur is not None:
                suite_recs.append(cur)
            cur = [line, False]
        elif cur is not None:
            if line.startswith('njs("'):
                cur[1] = True
            elif not cur[1]:
                cur[0] += "\n" + line
    return {k: v for k, v in tests.items()}


def t262(body):
    res = {}
    for line in body.split("\n"):
        m = re.match(r"^(test/\S+\.t\.js|test/\S+\.js) \S+ (PASSED|FAILED)$", line)
        if m:
            res[m.group(1)] = m.group(2)
    return res


def lib(body):
    return {m.group(1): m.group(2) for m in re.finditer(r"^lib (\w+) exit=(\d+)$", body, re.M)}


def shell(body, rc):
    n = len(re.findall(r"spawn -nottycopy njs", body))
    return {"exit": str(rc), "sessions": str(n), "transcript": body}


def main():
    a, b = sections(sys.argv[1]), sections(sys.argv[2])
    bad = False
    for s in ("unit", "lib", "test262", "shell"):
        if s not in a or s not in b:
            print(f"== {s}: missing in {'before' if s not in a else 'after'}")
            continue
        (ba, ra), (bb, rb) = a[s], b[s]
        if s == "unit":
            x, y = unit(ba), unit(bb)
        elif s == "test262":
            x, y = t262(ba), t262(bb)
        elif s == "lib":
            x, y = lib(ba), lib(bb)
        else:
            x, y = shell(ba, ra), shell(bb, rb)
        common = sorted(set(x) & set(y), key=str)
        diff = [k for k in common if x[k] != y[k] and not (s == "shell" and k == "transcript")]
        only_a = sorted(set(x) - set(y), key=str)
        only_b = sorted(set(y) - set(x), key=str)
        print(f"== {s}: suite exit before={ra} after={rb}")
        for k in diff:
            print(f"  differs: {k!r}: before {x[k]} after {y[k]}")
        for k in only_a:
            print(f"  before only: {k!r}: {x[k]}")
        for k in only_b:
            print(f"  after only: {k!r}: {y[k]}")
        if s == "shell":
            print(f"summary {s}: exit {x['exit']}/{y['exit']}, sessions {x['sessions']}/{y['sessions']}, "
                  f"transcript {'identical' if x['transcript'] == y['transcript'] else 'differs (not counted)'}")
        else:
            fa = sorted(k for k in common if x[k] not in ("PASSED", "0"))
            print(f"summary {s}: {len(common)} common tests, {len(diff)} differ, "
                  f"{len(only_a)} before only, {len(only_b)} after only; "
                  f"not passed in both: {len([k for k in fa if y[k] == x[k]])}"
                  + (f" ({', '.join(str(k) for k in fa if y[k] == x[k])})" if fa else ""))
        bad |= bool(diff)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
