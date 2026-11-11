#!/bin/bash
# Runs, one after the other, the variant min of njs.cve-2023-27728 (the
# minimal patch, cases only) into logs/njs.cve-2023-27728/variants and the
# 36 ablation variants L1..L36 of the minimal patch (cases and the njs test
# suites) into logs/njs.cve-2023-27728/ablation, with
# scripts/njs_run_variant.sh. One variant container is busy at a time.
# Before each variant it waits until the memory used by all containers is
# below 5.5 GiB, and it stops when the host data volume has less than
# 30 GiB free. It replaces the ablation run of 2026-10-28, which the stop of
# the container engine interrupted (logs/njs.cve-2023-27728/ablation_run1).
# The test suites run on every ablation variant that builds, because the
# case observable is the result class only and the unit suite's
# interactive tests compare dump text.
#
# Usage: bash scripts/dumpacc_ablation_chain.sh <diffdir>
#   <diffdir> holds L1.diff .. L36.diff and MANIFEST, written by
#   python3 scripts/ablate_patch.py patches/njs.cve-2023-27728.min.diff <diffdir>
# SECB_DOCKER_OPTS (required) holds the extra docker run options.
set -u
cd "$(dirname "$0")/.." || exit 2
abl=$1
inst=njs.cve-2023-27728
img=hwiwonlee/secb.eval.x86_64.$inst
L=logs/$inst
cases="--cases scripts/dumpacc_cases.py scripts/dumpacc_expected.tsv"

[ -n "${SECB_DOCKER_OPTS:-}" ] || { echo "SECB_DOCKER_OPTS is empty"; exit 2; }
[ -f "$abl/MANIFEST" ] || { echo "missing $abl/MANIFEST"; exit 2; }
for i in $(seq 1 36); do
  [ -f "$abl/L$i.diff" ] || { echo "missing $abl/L$i.diff"; exit 2; }
done
[ ! -e "$L/ablation" ] || { echo "$L/ablation exists; move the earlier run first"; exit 2; }
[ ! -e "$L/ablation.log" ] || { echo "$L/ablation.log exists; move the earlier run first"; exit 2; }
for c in min $(seq -f 'L%g' 1 36); do
  if docker ps -a --format '{{.Names}}' | grep -qx "secb-njs-27728-$c"; then
    echo "container secb-njs-27728-$c exists; free the name first"; exit 2
  fi
done

mem_ok() {
  docker stats --no-stream --format '{{.MemUsage}}' | python3 -c '
import re, sys
unit = {"B": 1, "KiB": 2**10, "MiB": 2**20, "GiB": 2**30, "kB": 1e3, "MB": 1e6, "GB": 1e9}
total = 0
for line in sys.stdin:
    m = re.match(r"\s*([0-9.]+)\s*([A-Za-z]+)", line)
    if m:
        total += float(m.group(1)) * unit.get(m.group(2), 1)
sys.exit(0 if total < 5.5 * 2**30 else 1)'
}
disk_ok() {
  free_kb=$(df -k /System/Volumes/Data | awk 'NR == 2 {print $4}')
  [ "${free_kb:-0}" -gt $((30 * 1024 * 1024)) ]
}
gate() {
  until mem_ok; do echo "waiting for memory before $1 $(date -u +%FT%TZ)"; sleep 60; done
  if ! disk_ok; then
    echo "CHAIN STOPPED before $1: less than 30 GiB free on the host data volume $(date -u +%FT%TZ)"
    exit 3
  fi
}
lines() { if [ -f "$1" ]; then wc -l < "$1" | tr -d ' '; else echo 0; fi; }

echo "chain start $(date -u +%FT%TZ) docker-opts: $SECB_DOCKER_OPTS"
gate min
n0=$(lines "$L/variants.log")
bash scripts/njs_run_variant.sh --no-tests $cases "$img" "$L/variants" min \
  "minimal patch (the src/njs_json.c hunk of the developer patch)" "patches/$inst.min.diff"
rc=$?
echo "min rc=$rc summary_lines_added=$(( $(lines "$L/variants.log") - n0 )) $(date -u +%FT%TZ)"

mkdir -p "$L/ablation"
cp "$abl/MANIFEST" "$L/ablation/MANIFEST"
for i in $(seq 1 36); do
  gate "L$i"
  n0=$(lines "$L/ablation.log")
  bash scripts/njs_run_variant.sh $cases "$img" "$L/ablation" "L$i" "drop changed line $i" "$abl/L$i.diff"
  rc=$?
  echo "L$i rc=$rc summary_lines_added=$(( $(lines "$L/ablation.log") - n0 )) $(date -u +%FT%TZ)"
done
echo "CHAIN DONE $(date -u +%FT%TZ)"
