"""Compare hypothesis-derived predictions with observed case results.

Usage: python3 check_predictions.py PREDICTIONS.tsv LOGDIR

PREDICTIONS.tsv has a header line `case<TAB><model>:<variant>...` and one
row per case. A cell is a predicted result class: OK, WRONG, ASAN, INV (an
instrumented invariant check fired) or - (no prediction for that case). The
observed class of each case is read from LOGDIR/variants/<variant>.cases.log
or LOGDIR/ablation/<variant>.cases.log: ASAN if the result starts with
ASAN, INV if it contains a marker of the form <NAME>-INVARIANT (e.g.
STACK-INVARIANT, RFPCM-INVARIANT), OK if it is exactly OK, else WRONG. For every column the script lists the cases whose observed class
differs from the prediction, then prints one summary line per column:
predicted, matched, mismatched, no-prediction, and the cases of the log
that the predictions file does not cover. It exits 1 if any column has a
mismatch, so a hypothesis that fails to predict an observation is visible
in the exit status as well as in the log.
"""
import hashlib
import re
import sys
from pathlib import Path

LINE = re.compile(r"^(\S+)\s+(.*)$")
MARK = re.compile(r"\b[A-Z]+-INVARIANT\b")


def observed(path):
    out = {}
    for line in path.read_text().splitlines():
        m = LINE.match(line)
        if not m or m.group(1) in ("summary:", "variant") or line.startswith(("---", "HEAD")):
            continue
        name, res = m.groups()
        if res.startswith("ASAN"):
            cls = "ASAN"
        elif MARK.search(res):
            cls = "INV"
        elif res == "OK":
            cls = "OK"
        elif res.startswith("WRONG") or res:
            cls = "WRONG"
        else:
            continue
        out[name] = (cls, res)
    return out


def main():
    pred_path, logdir = Path(sys.argv[1]), Path(sys.argv[2])
    text = pred_path.read_text()
    print(f"predictions: {pred_path} sha256 {hashlib.sha256(text.encode()).hexdigest()}")
    rows = [l.split("\t") for l in text.splitlines() if l and not l.startswith("#")]
    header, rows = rows[0], rows[1:]
    cols = header[1:]
    failed = False
    for ci, col in enumerate(cols, 1):
        model, variant = col.split(":", 1)
        log = logdir / "variants" / f"{variant}.cases.log"
        if not log.exists():
            log = logdir / "ablation" / f"{variant}.cases.log"
        if not log.exists():
            print(f"\n== {col}: no cases log for variant {variant}, skipped")
            continue
        obs = observed(log)
        n_pred = n_match = n_none = 0
        mism = []
        for row in rows:
            name, pred = row[0], row[ci]
            if name not in obs:
                continue
            if pred == "-":
                n_none += 1
                continue
            n_pred += 1
            cls, res = obs[name]
            if cls == pred:
                n_match += 1
            else:
                mism.append(f"  {name:<22} predicted {pred:<5} observed {cls:<5} {res[:60]}")
        uncovered = sorted(set(obs) - {r[0] for r in rows})
        print(f"\n== {col} (model {model}, {log})")
        for m in mism:
            print(m)
        print(f"summary {col}: predicted {n_pred}, matched {n_match}, mismatched {len(mism)}, "
              f"no-prediction {n_none}, uncovered {len(uncovered)}"
              + (f" ({', '.join(uncovered)})" if uncovered else ""))
        if mism:
            failed = True
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
