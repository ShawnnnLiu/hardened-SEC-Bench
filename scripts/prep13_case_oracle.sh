#!/bin/bash
# Checks the reference entry count of scripts/prep13_cases.py for
# test/test-data/r11/ACEB10.dwg (libredwg.cve-2021-28237) against the
# drawing's own section headers: prints the `contents table` trace lines of
# `dwgread -v5` (one per pre-R13 table section, with the entry count nr:
# that the section header declares), their sum, the number of
# `-- table entry` traces decoded and the number of sanitizer reports.
#
# Usage (inside a container of the instance image, built tree):
#   bash /tmp/prep13_case_oracle.sh [<tree>]      (default /src/libredwg)
set -u
tree=${1:-/src/libredwg}
f=test/test-data/r11/ACEB10.dwg
cd "$tree" || exit 1
out=/tmp/prep13_aceb10.v5
echo "--- tree $(git rev-parse HEAD); git diff --stat: $(git diff --stat | tail -1)"
echo "--- $f sha256 $(sha256sum "$f" | cut -c1-64)"
ASAN_OPTIONS=detect_leaks=0 programs/dwgread -v5 "$f" > "$out" 2>&1
echo "--- dwgread -v5 exit status $?"
grep -E '^contents table' "$out"
echo "sum of declared entries (nr:): $(grep -E '^contents table' "$out" | grep -o 'nr:[0-9]*' | awk -F: '{s += $2} END {print s + 0}')"
echo "decoded entries (-- table entry): $(grep -c '^-- table entry' "$out")"
echo "sanitizer reports: $(grep -c -E 'ERROR: (Address|Leak)Sanitizer' "$out")"
