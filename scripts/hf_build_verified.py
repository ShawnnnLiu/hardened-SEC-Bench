#!/usr/bin/env python3
"""Stage the `verified` configuration of the Hugging Face dataset
shawnnnliu/Hardened_SEC-Bench for a list of instances.

Usage: python3 -I scripts/hf_build_verified.py --forbid-file <file>
         <stage dir> <instance>...

Run from the repository root with an interpreter that has pandas and
pyarrow. The stage directory must not exist. It receives, mirroring the
repository layout so that the paths cited in notes and records resolve:

  data/verified-00000-of-00001.parquet   one row per instance
  results.jsonl                          the records of the instances
  patches/<instance>.diff, .min.diff     developer and minimal patch
  patches/<instance>.root.diff           root-cause patch, where one is kept
  notes/<instance>.md                    the note
  logs/<instance>/                       all logs, as produced
  scripts/<file>                         every script the above cite,
                                         and the scripts those cite

Each row holds the CVE_NVD fields of the instance (data/cve_nvd.parquet),
with `minimized_patch` replaced by the minimal patch of this repository
(empty when none is kept) and the CVE_NVD value kept in
`cve_nvd_minimized_patch`, followed by the verification fields of the
record; `root_patch` holds the root-cause patch where the developer patch
does not fix the root cause (with its source and status, e.g. adopted as
the reference patch for downstream tasks).
`post_dev_failing_inputs` lists the named failures retained after the
developer patch, with program text or a report reference and evidence.
The script checks that the developer patch is byte-identical to
CVE_NVD `developers_patch` and to the record's `patch_sha256`, screens the
staged text for the strings of the forbid file (one per line, # comments),
for local paths and for non-ASCII text in notes, scripts and records, and
prints the Markdown table of the instances for the dataset card. It exits
1 when the screen finds anything.
"""
import argparse
import hashlib
import json
import re
import runpy
import shutil
import sys
from pathlib import Path

import pandas as pd

post_dev_helpers = runpy.run_path(str(Path(__file__).with_name("post_dev_failing_inputs.py")))
collect_post_dev_inputs = post_dev_helpers["collect"]
post_dev_summary = post_dev_helpers["summary"]

SCRIPT_REF = re.compile(r"(?:\bscripts/|/tmp/scripts/)([\w.-]+\.(?:py|sh|tsv|diff|json|c))")
NAME_REF = re.compile(r"(?<![\w.-])([\w-]+\.(?:py|sh|tsv|diff|json|c))(?![\w-])")
# Home-directory paths of this host; tool paths are in the forbid file, and
# /home/... in upstream issue titles is public text.
# The character class avoids matching this definition when screening scripts.
LOCAL_PATH = re.compile(r"/[U]sers/")


def changed(text):
    return [l for l in text.splitlines()
            if l[:1] in ("+", "-") and not l.startswith(("+++", "---"))]


def read_text(p):
    try:
        return p.read_text(errors="replace")
    except (IsADirectoryError, PermissionError):
        return ""


def cited_scripts(texts):
    names = set()
    for t in texts:  # logs also name a script or config without its directory
        names.update(SCRIPT_REF.findall(t))
        names.update(NAME_REF.findall(t))
    names = {n for n in names if Path("scripts", n).is_file()}
    # The runners and the upstream search of a topic are not always cited by
    # name in its logs; a topic's scripts share the prefix before the first _.
    prefixes = {re.split(r"[_.]", n)[0] for n in names}
    names |= {p.name for p in Path("scripts").iterdir()
              if p.is_file() and re.split(r"[_.]", p.name)[0] in prefixes}
    todo = list(names)
    while todo:  # scripts the staged scripts use (comment lines only cite)
        code = "\n".join(l for l in read_text(Path("scripts", todo.pop())).splitlines()
                         if not l.lstrip().startswith("#"))
        for n in NAME_REF.findall(code):
            if n not in names and Path("scripts", n).is_file():
                names.add(n)
                todo.append(n)
    return sorted(names)


def no_min_reason(note):
    for pattern in (r"no minimal patch is kept", r"already minimal|minimal patch \(step 7\)"):
        for line in note.splitlines():
            if re.search(pattern, line, re.I):
                return line.strip().lstrip("- ")
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--forbid-file", required=True)
    ap.add_argument("stage")
    ap.add_argument("ids", nargs="+")
    a = ap.parse_args()
    stage, ids = Path(a.stage), a.ids
    if stage.exists():
        sys.exit(f"{stage} exists")
    recs = {}
    for line in open("results.jsonl"):
        d = json.loads(line)
        if d["instance_id"] in ids:
            recs[d["instance_id"]] = (d, line)
    missing = [i for i in ids if i not in recs]
    if missing:
        sys.exit(f"no record: {missing}")
    nvd = {r["instance_id"]: r for _, r in pd.read_parquet("data/cve_nvd.parquet").iterrows()}

    for sub in ("data", "patches", "notes", "logs", "scripts"):
        (stage / sub).mkdir(parents=True)
    rows, table, texts = [], [], []
    with open(stage / "results.jsonl", "w") as out:
        for i in ids:
            d, line = recs[i]
            out.write(line)
            texts.append(line)
            dev_p, min_p, note_p = Path(f"patches/{i}.diff"), Path(f"patches/{i}.min.diff"), Path(f"notes/{i}.md")
            # The record names the root-cause patch; it is outside patches/ for an
            # instance whose leftover is counted under another instance.
            root_p = Path(d.get("root_patch") or f"patches/{i}.root.diff")
            dev = dev_p.read_text()
            assert dev == nvd[i]["developers_patch"], f"{i}: developer patch differs from CVE_NVD"
            assert hashlib.sha256(dev.encode()).hexdigest() == d["patch_sha256"], f"{i}: patch_sha256"
            shutil.copy2(dev_p, stage / "patches")
            note = note_p.read_text()
            shutil.copy2(note_p, stage / "notes")
            texts.append(note)
            shutil.copytree(Path("logs", i), stage / "logs" / i)
            texts.extend(read_text(p) for p in Path("logs", i).rglob("*") if p.is_file())
            minimal = next((p for p in d.get("patches", []) if p.get("role") == "minimal"), None)
            mn = None
            if min_p.exists():
                mn = min_p.read_text()
                shutil.copy2(min_p, stage / "patches")
                assert minimal and hashlib.sha256(mn.encode()).hexdigest() == minimal["sha256"], f"{i}: min sha256"
            root = None
            if root_p.exists():
                root = root_p.read_text()
                if root_p.parent == Path("patches"):
                    shutil.copy2(root_p, stage / "patches")
                assert hashlib.sha256(root.encode()).hexdigest() == d["root_patch_sha256"], f"{i}: root sha256"
            row = nvd[i].to_dict()
            row["cve_nvd_minimized_patch"] = row["minimized_patch"]
            row["minimized_patch"] = mn
            sr = d.get("second_reading") or ""
            row.update({
                "verification_status": d["status"],
                "verified_at": d["timestamp"],
                "image_digest": d["image_digest"],
                "container_commit": d["container_commit"],
                "host_arch": d["host_arch"],
                "poc_crashed_before": bool(d["poc_crashed_before"]),
                "poc_crashed_after": bool(d["poc_crashed_after"]),
                "poc_resolved": bool(d["poc_resolved"]),
                "semantic_flag": bool(d["semantic_flag"]),
                "semantic_status": d["semantic_status"],
                "semantic_reasoning": d["semantic_reasoning"],
                "dev_patch_fixes_root_cause": bool(d["dev_patch_fixes_root_cause"]),
                "post_dev_failing_inputs": collect_post_dev_inputs(i) if d["dev_patch_fixes_root_cause"] is False else [],
                "root_cause": d["root_cause"],
                "regression_tests": d["tests"],
                "developers_patch_sha256": d["patch_sha256"],
                "minimized_patch_sha256": minimal["sha256"] if mn else None,
                "minimized_patch_derivation": minimal["status"] if mn else no_min_reason(note),
                "minimized_patch_tests": minimal["tests"] if mn else None,
                "second_reading": sr,
                "root_patch": root,
                "root_patch_sha256": d.get("root_patch_sha256") if root else None,
                "root_patch_source": d.get("root_patch_source") if root else None,
                "root_patch_status": d.get("root_patch_status") if root else None,
                "residual": d["residual"],
                "confidence": d["confidence"],
                "note": d["note"],
                "evidence": f"notes/{i}.md; logs/{i}/; results.jsonl",
            })
            rows.append(row)
            nd = len(changed(dev))
            table.append("| {} | {} / {} | {} | {} | {} | {} | {} |".format(
                i,
                "report" if d["poc_crashed_before"] else "none",
                "report" if d["poc_crashed_after"] else "none",
                "identical to baseline" if re.match(r"(passed, )?same as unpatched baseline", d["tests"]) else "see `regression_tests`",
                ("true (" + d["semantic_status"].split(":")[0] + ")" if d["semantic_flag"] else "false")
                + (" (noted for review)" if "Noted for review" in d["semantic_reasoning"] else ""),
                f"{len(changed(mn))} of {nd} changed lines" if mn else f"none kept ({nd} changed lines)",
                "not run" if sr.startswith("not run") else ("done, dissent recorded" if "dissent" in sr else "done"),
                post_dev_summary(row["post_dev_failing_inputs"]),
            ))
    for n in sorted(set(cited_scripts(texts)) | {"hf_build_verified.py", "post_dev_failing_inputs.py"}):
        shutil.copy2(Path("scripts", n), stage / "scripts")
    pd.DataFrame(rows).to_parquet(stage / "data/verified-00000-of-00001.parquet", index=False)

    forbidden = [l.strip().lower() for l in open(a.forbid_file)
                 if l.strip() and not l.startswith("#")]
    problems = []
    for p in sorted(stage.rglob("*")):
        if not p.is_file() or p.suffix == ".parquet":
            continue
        t = read_text(p)
        rel = p.relative_to(stage)
        low = t.lower()
        problems += [f"{rel}: forbidden string {s!r}" for s in forbidden if s in low]
        if LOCAL_PATH.search(t):
            problems.append(f"{rel}: local path")
        # Checksum manifests name files as they are, which may be non-ASCII.
        if (rel.parts[0] in ("notes", "scripts") or rel.name == "results.jsonl") and rel.suffix != ".sha256":
            if re.search(r"[^\x09\x0a\x0d\x20-\x7e]", t):
                problems.append(f"{rel}: non-ASCII text")
    files = [p for p in stage.rglob("*") if p.is_file()]
    print(f"staged {len(ids)} instances, {len(files)} files, "
          f"{sum(p.stat().st_size for p in files) / 1e6:.1f} MB, "
          f"{len(list((stage / 'scripts').iterdir()))} scripts")
    print("\n".join(problems) if problems else "screen: clean")
    print()
    print("| Instance | PoC before / after | Regression tests | `semantic_flag` | Minimal patch | Second reading | Inputs failing after developer patch |")
    print("|---|---|---|---|---|---|---|")
    print("\n".join(table))
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
