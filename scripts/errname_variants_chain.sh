#!/bin/bash
# Runs, one after another, the core variants of njs.cve-2023-27730 into
# logs/njs.cve-2023-27730/variants with scripts/njs_run_variant.sh:
#   before          base 4c1e2332 (tests)
#   after           developer patch patches/njs.cve-2023-27730.diff (tests)
#   assert_before   base + scripts/errname_invariant.diff (tests)
#   upstream_master origin/master, src/njs_object_prop.c diff (no tests)
# One variant container is busy at a time. Before each it waits until the
# memory used by all containers is below 5.5 GiB and stops when the host data
# volume has less than 30 GiB free. SECB_DOCKER_OPTS (required) holds the
# extra docker run options.
set -u
cd "$(dirname "$0")/.." || exit 2
inst=njs.cve-2023-27730
img=hwiwonlee/secb.eval.x86_64.$inst
L=logs/$inst
cases="--cases scripts/errname_cases.py scripts/errname_expected.tsv"

[ -n "${SECB_DOCKER_OPTS:-}" ] || { echo "SECB_DOCKER_OPTS is empty"; exit 2; }
for c in before after assert_before upstream_master; do
  if docker ps -a --format '{{.Names}}' | grep -qx "secb-njs-27730-$c"; then
    echo "container secb-njs-27730-$c exists; free the name first"; exit 2
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
    echo "CHAIN STOPPED before $1: less than 30 GiB free $(date -u +%FT%TZ)"; exit 3
  fi
}
lines() { if [ -f "$1" ]; then wc -l < "$1" | tr -d ' '; else echo 0; fi; }
runv() {
  local n0; n0=$(lines "$L/variants.log")
  gate "$1"
  bash scripts/njs_run_variant.sh "$@"
  echo "variant done rc=$? summary_lines_added=$(( $(lines "$L/variants.log") - n0 )) $(date -u +%FT%TZ)"
}

echo "chain start $(date -u +%FT%TZ) docker-opts: $SECB_DOCKER_OPTS"
runv $cases "$img" "$L/variants" before "base 4c1e2332"
runv $cases "$img" "$L/variants" after "developer patch" patches/$inst.diff
runv $cases "$img" "$L/variants" assert_before "base + errname_invariant.diff" scripts/errname_invariant.diff
runv --no-tests --ref master src/njs_object_prop.c $cases "$img" "$L/variants" upstream_master "upstream master"
echo "CHAIN DONE $(date -u +%FT%TZ)"
