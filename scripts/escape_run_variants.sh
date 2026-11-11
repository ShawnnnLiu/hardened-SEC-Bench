#!/bin/bash
# Runs the variants of libredwg.cve-2020-21816 (the logs under
# logs/libredwg.cve-2020-21816/variants*) one after the other in one lane.
#
# Usage: escape_run_variants.sh <cpuset> <issue182 dir> [variant...]
#
#   <cpuset>        CPUs of the container, e.g. 4-5 (memory cap 3g)
#   <issue182 dir>  output of scripts/libredwg_fetch_issue182.py
#   variant         any of before after wfix after_wfix assert_after
#                   assert_before upstream_master min root assert_root
#                   (default: all but min, root and assert_root, in this
#                   order; min needs patches/*.min.diff). root applies the
#                   developer patch and e8c3edb9, the same tree as
#                   after_wfix; the name is kept from a root-cause proposal
#                   of 2026-10-28 that was withdrawn the same day
#
# Needs the local image secb.built.x86_64.libredwg.cve-2020-21816:base from
# scripts/libredwg_make_built_image.sh. Run from the repository root.
set -eu
cpu=$1 inputs=$2; shift 2
img=secb.built.x86_64.libredwg.cve-2020-21816:base
out=logs/libredwg.cve-2020-21816/variants
dev=patches/libredwg.cve-2020-21816.diff
wfix=scripts/escape_wfix.diff
inv=scripts/escape_invariant.diff
min=patches/libredwg.cve-2020-21816.min.diff
export SECB_DOCKER_OPTS="--cpuset-cpus $cpu --memory 3g --memory-swap 3g"
run() {  # run [--no-tests] [--ref ...] <name> <description> [diff...]
  local pre=()
  while [ "$1" = "--no-tests" ] || [ "$1" = "--ref" ]; do
    if [ "$1" = "--ref" ]; then pre+=("$1" "$2" "$3"); shift 3; else pre+=("$1"); shift; fi
  done
  scripts/libredwg_run_variant.sh ${pre[@]+"${pre[@]}"} --inputs "$inputs" --copy scripts/escape_driver.c \
    --cases scripts/escape_cases.py "$img" "$out" "$@"
}
variants=("$@")
[ ${#variants[@]} -gt 0 ] || variants=(before after wfix after_wfix assert_after assert_before upstream_master)
for v in "${variants[@]}"; do
  case $v in
    before) run --no-tests before "base commit 5f998146, no diff" ;;
    after) run --no-tests after "developer patch 7e4c59b6 (patches/libredwg.cve-2020-21816.diff)" "$dev" ;;
    wfix) run --no-tests wfix "upstream e8c3edb9 alone (htmlwescape only, scripts/escape_wfix.diff)" "$wfix" ;;
    after_wfix) run --no-tests after_wfix "developer patch 7e4c59b6 and upstream e8c3edb9 (the SEC-bench gold patch)" "$dev" "$wfix" ;;
    assert_before) run assert_before "base commit 5f998146 + scripts/escape_invariant.diff" "$inv" ;;
    assert_after) run assert_after "developer patch 7e4c59b6 + scripts/escape_invariant.diff" "$dev" "$inv" ;;
    min) run --no-tests min "minimal patch (patches/libredwg.cve-2020-21816.min.diff)" "$min" ;;
    root) run --no-tests root "developer patch 7e4c59b6 + upstream e8c3edb9 (the changed lines of the SEC-bench gold patch)" "$dev" "$wfix" ;;
    assert_root) run assert_root "developer patch 7e4c59b6 + upstream e8c3edb9 + scripts/escape_invariant.diff" "$dev" "$wfix" "$inv" ;;
    upstream_master) run --no-tests --ref master "programs/escape.c programs/escape.h" upstream_master "upstream master, whole tree" ;;
    *) echo "unknown variant $v" >&2; exit 2 ;;
  esac
done
