#!/bin/bash
# Runs, one after another, the minimal patch and the tier-2 file-group
# variants of njs.cve-2023-27730 into logs/njs.cve-2023-27730/variants with
# scripts/njs_run_variant.sh. The signature change of njs_object_property
# (src/njs_object.h + src/njs_object_prop.c) couples all seven source files:
# every caller hunk must change with the declaration or the build fails. The
# group variants drop one file group each and are expected to fail to build,
# which is the evidence of the coupling, not a failure of the step.
#   min        the seven source hunks (developer patch minus the test hunk),
#              with tests -> tests_min
#   sig_only   only src/njs_object.h + src/njs_object_prop.c (callers unadapted)
#   no_error   all source hunks except src/njs_error.c
#   no_array   all source hunks except src/njs_array.c
#   no_objprop all source hunks except src/njs_object_prop.c
# Usage: bash scripts/errname_tier2_chain.sh <tier2-diff-dir>
# <tier2-diff-dir> holds sig_only.diff, no_error.diff, no_array.diff,
# no_objprop.diff (written by scripts/ablate_patch.py over the min patch).
# SECB_DOCKER_OPTS (required) holds the extra docker run options.
set -u
cd "$(dirname "$0")/.." || exit 2
t2=$1
inst=njs.cve-2023-27730
img=hwiwonlee/secb.eval.x86_64.$inst
L=logs/$inst
cases="--cases scripts/errname_cases.py scripts/errname_expected.tsv"

[ -n "${SECB_DOCKER_OPTS:-}" ] || { echo "SECB_DOCKER_OPTS is empty"; exit 2; }
for g in sig_only no_error no_array no_objprop; do
  [ -f "$t2/$g.diff" ] || { echo "missing $t2/$g.diff"; exit 2; }
done
for c in min sig_only no_error no_array no_objprop; do
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
  until mem_ok; do echo "waiting for memory $(date -u +%FT%TZ)"; sleep 60; done
  if ! disk_ok; then echo "CHAIN STOPPED: less than 30 GiB free $(date -u +%FT%TZ)"; exit 3; fi
}

echo "chain start $(date -u +%FT%TZ) docker-opts: $SECB_DOCKER_OPTS"
gate; bash scripts/njs_run_variant.sh $cases "$img" "$L/variants" min "minimal patch (seven source hunks)" patches/$inst.min.diff
echo "min done $(date -u +%FT%TZ)"
for g in sig_only no_error no_array no_objprop; do
  gate; bash scripts/njs_run_variant.sh --no-tests $cases "$img" "$L/variants" "$g" "tier-2 $g (compile coupling)" "$t2/$g.diff"
  echo "$g done $(date -u +%FT%TZ)"
done
echo "CHAIN DONE $(date -u +%FT%TZ)"
