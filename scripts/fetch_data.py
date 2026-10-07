"""Download the CVE_NVD and SEC-bench CVE datasets into data/ and check they line up.

Usage: python scripts/fetch_data.py [--cve-nvd-rev SHA] [--secbench-rev SHA]

Files are pinned to a dataset revision and written read-only. The revisions
used are recorded in data/REVISIONS so a later run can fetch the same bytes.
"""
import argparse
import csv
import json
import os
import shutil
import stat
from pathlib import Path

import pandas as pd
from huggingface_hub import HfApi, hf_hub_download

DATA = Path(__file__).resolve().parent.parent / "data"

SOURCES = {
    "cve_nvd.parquet": ("SongTonyLi/CVE_NVD", "data/train-00000-of-00001.parquet"),
    "secbench_cve.jsonl": ("SEC-bench/SEC-bench", "data/eval-cve.jsonl"),
}


def fetch(repo, filename, rev, out):
    path = hf_hub_download(repo, filename, repo_type="dataset", revision=rev)
    if out.exists():
        out.chmod(stat.S_IWUSR | stat.S_IRUSR)
    shutil.copyfile(path, out)
    out.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--cve-nvd-rev", help="dataset commit; default is current main")
    p.add_argument("--secbench-rev", help="dataset commit; default is current main")
    args = p.parse_args()

    api = HfApi()
    revs = {
        "SongTonyLi/CVE_NVD": args.cve_nvd_rev or api.dataset_info("SongTonyLi/CVE_NVD").sha,
        "SEC-bench/SEC-bench": args.secbench_rev or api.dataset_info("SEC-bench/SEC-bench").sha,
    }
    DATA.mkdir(exist_ok=True)
    for out, (repo, filename) in SOURCES.items():
        fetch(repo, filename, revs[repo], DATA / out)
        print(f"{out}: {repo}@{revs[repo]}")
    (DATA / "REVISIONS").write_text("".join(f"{r} {s}\n" for r, s in revs.items()))

    nvd = pd.read_parquet(DATA / "cve_nvd.parquet")
    with open(DATA / "secbench_cve.jsonl") as f:
        secb = [json.loads(line) for line in f]
    nvd_ids = list(nvd["instance_id"])
    secb_ids = [r["instance_id"] for r in secb]
    print(f"CVE_NVD rows: {len(nvd_ids)}, SEC-bench cve rows: {len(secb_ids)}")
    print("same IDs in same order:", nvd_ids == secb_ids)
    print("same ID set:", set(nvd_ids) == set(secb_ids))

    worklist = DATA / "cve_nvd_review_worklist.csv"
    if worklist.exists():
        with open(worklist) as f:
            wl_ids = [r["instance_id"] for r in csv.DictReader(f)]
        print(f"worklist rows: {len(wl_ids)}, same ID set as CVE_NVD:", set(wl_ids) == set(nvd_ids))
    else:
        print("worklist not found at", os.path.relpath(worklist))


if __name__ == "__main__":
    main()
