"""Run WAVE inputs through four gpac consumers and classify every run
against expected values computed without gpac (gpac.cve-2023-5586).

Usage, inside a SEC-bench gpac container after "secb build":
  python3 rfpcm_wav_cases.py EXPECTED.tsv FILE...

EXPECTED.tsv is written by scripts/make_wav_cases.py. A FILE not listed
in it (the dataset PoC) is expected to be rejected.

Consumers:
  poc      the SEC-bench repro command line (MP4Box -dash 1000 -out /dev/null)
  add      MP4Box -add FILE -new out.mp4
  inspect  gpac -i FILE inspect:deep (properties and per-packet CRC32)
  pcm      gpac -i FILE -o out.pcm:afmt=<expected format> (raw samples)
All but poc run with -for-test, so outputs carry no version or time
strings, and with -noprog, so stderr carries no progress bars.

One result line per run, "<input>.<consumer> <result>", where result is,
in this order of precedence,
  <MARKER>-INVARIANT ...  the instrumented invariant check fired (the line
                          printed by the check)
  ASAN <type>             an AddressSanitizer or UBSan error report, type
                          only
  WRONG timeout           the run did not end within CASE_TIMEOUT: timeout
                          exited 124 or 137, or was itself killed (negative
                          status: with -k, timeout sends SIGKILL to its
                          whole process group when the command has not
                          exited 5 s after SIGTERM)
  WRONG watchdog          the gpac filter watchdog stopped the session ("not
                          responding properly")
  ASAN LeakSanitizer ...  a LeakSanitizer report of a run that ended by
                          itself (a leak report at the forced exit of a
                          timed-out or watchdog-stopped run is not counted)
  WRONG <reason>          a valid file rejected, a bad file
                          accepted, or a value that differs from
                          EXPECTED.tsv: for inspect the sample rate,
                          channel count, audio format, duration (the
                          frames/rate fraction, without the time later
                          gpac versions print after it) and the
                          size and CRC32 of every packet; for pcm the
                          sha256 of the output against the payload
  OK                      none of the above
poc and add are checked for exit status, timeout, watchdog and sanitizer
reports only. Evidence (command line and stderr, at most 400 lines per
run) follows each result line, indented, so that only result lines start
in column 1; it is printed as produced, while the classification reads
stderr with ANSI color codes removed (MP4Box without -for-test colors its
log lines). The header names the sha256 of this script. The last line is
  summary: N runs; a OK, b WRONG, c ASAN, d INV; timeouts t, watchdog w, leaks l; valid outputs D
where D is the first 12 hex digits of the sha256 over the observed
values of the runs on valid inputs (exit status; inspect properties and
packets; pcm output hash).
Environment: CASE_TIMEOUT (seconds, default 120).
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BIN = "/src/gpac/bin/gcc"
T = int(os.environ.get("CASE_TIMEOUT", "120"))
MEM = re.compile(r"ERROR: (Address|Memory|Thread)Sanitizer|runtime error:")
LEAK = re.compile(r"ERROR: LeakSanitizer")
MARK = re.compile(r"\b[A-Z]+-INVARIANT\b.*")
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def sh(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, errors="replace").stdout


def load_expected(path):
    rows = [l.rstrip("\n").split("\t") for l in open(path)]
    head = rows[0]
    return {r[0]: dict(zip(head, r)) for r in rows[1:]}


def inspect_values(path):
    if not path.exists():
        return None
    text = path.read_text(errors="replace")
    blocks = text.count("Configure - properties:")
    props = {}
    m = re.search(r"Configure - properties:\n((?:\t[^\n]*\n)*)", text)
    if m:
        for line in m.group(1).splitlines():
            k, _, v = line.strip().partition(": ")
            props[k] = v
    pk = [f"{s}:{c.upper()}" for s, c in re.findall(r"^PID \d+ PCK \d+ .* size (\d+) .*CRC32 0x([0-9A-Fa-f]+)", text, re.M)]
    # later gpac versions append the time to the fraction: "1600/8000 (00:00:00.200)"
    dur = re.match(r"\d+/\d+", props.get("Duration") or "")
    return {"afmt": props.get("AudioFormat"), "sr": props.get("SampleRate"), "ch": props.get("NumChannels"),
            "dur": dur.group(0) if dur else props.get("Duration"), "packets": ",".join(pk), "configure_blocks": blocks}


def classify(exp, consumer, rc, hang, err, w):
    """Returns (result, observed values for the valid-output digest)."""
    err = ANSI.sub("", err)
    m = MARK.search(err)
    if m:
        return m.group(0).strip(), None

    def san(rx):
        m = rx.search(err)
        if not m:
            return None
        line = err[m.start():].splitlines()[0]
        line = re.sub(r" on (unknown )?address .*| \(pc .*| in \d+ object.*", "", line)
        return "ASAN " + line.replace("ERROR: ", "")
    mem = san(MEM)
    if mem:
        return mem, None
    if hang:
        return "WRONG timeout", None
    if "not responding properly" in err:
        f = re.search(r"\[Filter\] (\S+) \(idx \d+\) not responding properly", err)
        return f"WRONG watchdog ({f.group(1) if f else '?'} not responding)", None
    leak = san(LEAK)
    if leak:
        return leak, None
    if exp is None or exp["expect"] == "reject":
        return ("OK", None) if rc != 0 else ("WRONG accepted (exit 0)", None)
    if rc != 0:
        return f"WRONG rejected (exit {rc})", f"exit={rc}"
    if consumer == "inspect":
        got = inspect_values(w / "out" / "o.txt")
        if got is None:
            return "WRONG no inspect output", "none"
        want = {"afmt": exp["afmt"], "sr": exp["sr"], "ch": exp["ch"],
                "dur": f"{exp['frames']}/{exp['sr']}", "packets": exp["packets"], "configure_blocks": 1}
        bad = [k for k in want if str(got[k]) != str(want[k])]
        obs = " ".join(f"{k}={got[k]}" for k in ("afmt", "sr", "ch", "dur", "configure_blocks")) + \
            " packets=" + hashlib.sha256(got["packets"].encode()).hexdigest()[:12]
        if bad:
            gp, wp = got["packets"].split(","), want["packets"].split(",")
            same = sum(a == b for a, b in zip(gp, wp))
            detail = ", ".join(f"{k}={got[k]} (expected {want[k]})" for k in bad if k != "packets")
            if "packets" in bad:
                detail = (detail + ", " if detail else "") + f"packets {same} of {len(wp)} match, {len(gp)} received"
            return "WRONG inspect " + detail, obs
        return "OK", obs
    if consumer == "pcm":
        p = w / "out" / "o.pcm"
        if not p.exists():
            return "WRONG no pcm output", "none"
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        if h != exp["payload_sha256"]:
            return f"WRONG pcm output sha256 {h[:12]} size {p.stat().st_size} (expected {exp['payload_sha256'][:12]})", h
        return "OK", h
    return "OK", f"exit={rc}"


def main():
    expected = load_expected(sys.argv[1])
    files = [os.path.abspath(f) for f in sys.argv[2:]]  # the consumers run in a temp directory
    print(f"--- runner rfpcm_wav_cases.py sha256 {hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}")
    print(f"--- HEAD {sh(['git', '-C', '/src/gpac', 'rev-parse', 'HEAD']).strip()}")
    print("--- git diff --stat")
    for line in sh(["git", "-C", "/src/gpac", "diff", "--stat"]).splitlines():
        print("    " + line)
    print(f"--- environment ASAN_OPTIONS={os.environ.get('ASAN_OPTIONS', '<unset>')} "
          f"UBSAN_OPTIONS={os.environ.get('UBSAN_OPTIONS', '<unset>')} timeout={T}s")
    print(f"--- expected {sys.argv[1]} sha256 {hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest()}")
    counts = {"OK": 0, "WRONG": 0, "ASAN": 0, "INV": 0}
    extra = {"timeout": 0, "watchdog": 0, "leak": 0}
    valid_obs = []
    n = 0
    for f in files:
        name = Path(f).name
        stem = name[:-4] if name.endswith(".wav") else name
        exp = expected.get(stem)
        print(f"--- {name} sha256={hashlib.sha256(Path(f).read_bytes()).hexdigest()} expect={exp['expect'] if exp else 'reject (not in expected)'}")
        for consumer in ("poc", "add", "inspect", "pcm"):
            w = Path(tempfile.mkdtemp())
            (w / "out").mkdir()
            afmt = exp["afmt"] if exp and exp["expect"] == "decode" else "s16"
            cmd = {"poc": [f"{BIN}/MP4Box", "-dash", "1000", "-out", "/dev/null", f],
                   "add": [f"{BIN}/MP4Box", "-for-test", "-noprog", "-add", f, "-new", f"{w}/out/o.mp4"],
                   "inspect": [f"{BIN}/gpac", "-for-test", "-noprog", "-i", f, f"inspect:deep:log={w}/out/o.txt"],
                   "pcm": [f"{BIN}/gpac", "-for-test", "-noprog", "-i", f, "-o", f"{w}/out/o.pcm:afmt={afmt}"]}[consumer]
            t0 = time.monotonic()
            p = subprocess.run(["timeout", "-k", "5", str(T)] + cmd, cwd=w, capture_output=True, errors="replace")
            elapsed = time.monotonic() - t0
            rc, err = p.returncode, p.stderr
            hang = rc in (124, 137) or rc < 0
            res, obs = classify(exp, consumer, rc, hang, err, w)
            n += 1
            cls = "INV" if MARK.match(res) else res.split()[0]  # res is built from color-free text
            counts[cls] += 1
            extra["timeout"] += res == "WRONG timeout"
            extra["watchdog"] += res.startswith("WRONG watchdog")
            extra["leak"] += res.startswith("ASAN LeakSanitizer")
            if exp and exp["expect"] == "decode":
                valid_obs.append(f"{stem}.{consumer} {cls} {obs}")
            print(f"{stem + '.' + consumer:<40} {res}")
            print(f"    $ {' '.join(cmd)}".replace(str(w), "$W"))
            print(f"    exit={rc} elapsed={elapsed:.1f}s")
            lines = err.replace(str(w), "$W").splitlines()
            for line in lines[:400]:
                print("    | " + line)
            if len(lines) > 400:
                print(f"    | ... {len(lines) - 400} more stderr lines not printed")
            shutil.rmtree(w, ignore_errors=True)
    digest = hashlib.sha256("\n".join(valid_obs).encode()).hexdigest()[:12]
    print(f"summary: {n} runs; {counts['OK']} OK, {counts['WRONG']} WRONG, {counts['ASAN']} ASAN, {counts['INV']} INV; "
          f"timeouts {extra['timeout']}, watchdog {extra['watchdog']}, leaks {extra['leak']}; valid outputs {digest}")


if __name__ == "__main__":
    main()
