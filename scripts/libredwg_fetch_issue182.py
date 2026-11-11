#!/usr/bin/env python3
"""Download the reproducers of LibreDWG/libredwg#182 (scripts/escape_cases.py,
table ISSUE182) into a directory and check their sha256.

Usage: libredwg_fetch_issue182.py OUTDIR

The files are the PoCs the reporter (linhlhq) links in the eight comments of
the issue, in https://github.com/linhlhq/research under
PoCs/libreDWG_7b9cb829. Prints one line per file: name, size, sha256 status.
Exits 1 if a download fails or a hash differs.
"""
import hashlib
import os
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import escape_cases as ec  # noqa: E402

BASE = "https://raw.githubusercontent.com/linhlhq/research/master/PoCs/libreDWG_7b9cb829/"


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    bad = 0
    for case, name, sha, rep, fn in ec.ISSUE182:
        url = BASE + urllib.parse.quote(name, safe="")
        try:
            data = urllib.request.urlopen(url, timeout=60).read()
        except Exception as e:  # noqa: BLE001
            print("%s FAILED %s" % (name, e))
            bad += 1
            continue
        ok = hashlib.sha256(data).hexdigest() == sha
        bad += not ok
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)
        print("%s %d bytes sha256 %s" % (name, len(data), "match" if ok else "DIFFERS"))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
