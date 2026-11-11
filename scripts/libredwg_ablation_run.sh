#!/bin/bash
# Runs the variants written by scripts/ablate_patch.py through
# scripts/libredwg_run_variant.sh, one container at a time per lane.
#
# Usage: libredwg_ablation_run.sh [--reverse] <ablation dir> <lanes> <image> <outdir> [runner options...]
#
#   <ablation dir>  output of ablate_patch.py (MANIFEST and <name>.diff)
#   <lanes>         comma-separated cpusets, one lane each, e.g. 4-5 or 4-5,6-7;
#                   the variants are dealt to the lanes in MANIFEST order and
#                   each lane runs its variants one after the other
#   <image>         image the variants are built from (the built image)
#   <outdir>        e.g. logs/<instance>/ablation (summary: <outdir>.log)
#   runner options  passed to libredwg_run_variant.sh before the image, e.g.
#                   --quick --no-tests --no-corpus --cases scripts/escape_cases.py
#                   --copy scripts/escape_driver.c --inputs <dir>
#                   --env CASE_ONLY=<regex>
#
# A variant that has a line in <outdir>.log, or that another invocation has
# claimed (a directory <outdir>/.lock/<name>), is skipped, so that a second
# invocation (--reverse takes the list from its end) can share the work of a
# first one. Every container gets --memory 3g --memory-swap 3g and the lane's
# cpuset (SECB_DOCKER_OPTS is set per lane). The description of a variant is
# the MANIFEST line that says which changed lines it drops.
set -eu
reverse=0
if [ "$1" = "--reverse" ]; then reverse=1; shift; fi
abl=$1 lanes=$2 image=$3 outdir=$4; shift 4
here=$(cd "$(dirname "$0")" && pwd)
IFS=, read -r -a cpus <<< "$lanes"
names=()
while IFS= read -r line; do names+=("${line%%:*}"); done < <(grep -E '^[A-Za-z0-9_]+: drops ' "$abl/MANIFEST")
if [ $reverse = 1 ]; then
  rev=()
  for ((i = ${#names[@]} - 1; i >= 0; i--)); do rev+=("${names[$i]}"); done
  names=("${rev[@]}")
fi
mkdir -p "$outdir/.lock"
lane() {
  local idx=$1 cpu=$2 i
  shift 2
  for ((i = idx; i < ${#names[@]}; i += ${#cpus[@]})); do
    n=${names[$i]}
    if grep -q "^$n | " "$outdir.log" 2>/dev/null; then continue; fi
    mkdir "$outdir/.lock/$n" 2>/dev/null || continue
    desc="ablation, $(grep -E "^$n: drops " "$abl/MANIFEST" | sed 's/^[^:]*: //')"
    SECB_DOCKER_OPTS="--cpuset-cpus $cpu --memory 3g --memory-swap 3g" \
      "$here/libredwg_run_variant.sh" "$@" "$image" "$outdir" "$n" "$desc" "$abl/$n.diff" || true
  done
}
for ((k = 0; k < ${#cpus[@]}; k++)); do lane "$k" "${cpus[$k]}" "$@" & done
wait
