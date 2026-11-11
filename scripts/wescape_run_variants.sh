#!/bin/bash
# Runs the variants of libredwg.cve-2020-21814 (the logs under
# logs/libredwg.cve-2020-21814/variants*) one after the other in one lane.
# The counterpart of scripts/escape_run_variants.sh (libredwg.cve-2020-21816)
# with this instance's image, patches and variant names.
#
# Usage: wescape_run_variants.sh <cpuset> <issue182 dir> <master inputs dir> [variant...]
#
#   <cpuset>             CPUs of the container, e.g. 6-7 (memory cap 3g)
#   <issue182 dir>       output of scripts/libredwg_fetch_issue182.py
#   <master inputs dir>  the same files plus the blk12 and txt inputs that
#                        `escape_cases.py gen` writes from the base tree (used
#                        by upstream_master only, whose example files differ)
#   variant              any of before after cve21816_alone after_cve21816
#                        assert_before assert_after upstream_master min
#                        (default: all but min, in this order; min needs
#                        patches/libredwg.cve-2020-21814.min.diff)
#
# after is the developer patch e8c3edb9; cve21816_alone is 7e4c59b6 alone,
# the developer patch of libredwg.cve-2020-21816; after_cve21816 applies
# 7e4c59b6 and then e8c3edb9, which gives the programs/escape.c of the
# SEC-bench gold patch. Needs the local image
# secb.built.x86_64.libredwg.cve-2020-21814:base from
# scripts/wescape_make_built_image.sh. Run from the repository root.
set -eu
cpu=$1 inputs=$2 minputs=$3; shift 3
img=secb.built.x86_64.libredwg.cve-2020-21814:base
out=logs/libredwg.cve-2020-21814/variants
dev=patches/libredwg.cve-2020-21814.diff
cve21816=patches/libredwg.cve-2020-21816.diff
inv=scripts/escape_invariant.diff
min=patches/libredwg.cve-2020-21814.min.diff
export SECB_DOCKER_OPTS="--cpuset-cpus $cpu --memory 3g --memory-swap 3g"
run() {  # run [--no-tests] [--ref <ref> <paths>] [--inputs <dir>] <name> <description> [diff...]
  local pre=() inp=$inputs
  while :; do
    case "$1" in
      --no-tests) pre+=("$1"); shift ;;
      --ref) pre+=("$1" "$2" "$3"); shift 3 ;;
      --inputs) inp=$2; shift 2 ;;
      *) break ;;
    esac
  done
  scripts/libredwg_run_variant.sh ${pre[@]+"${pre[@]}"} --inputs "$inp" --copy scripts/escape_driver.c \
    --cases scripts/escape_cases.py "$img" "$out" "$@"
}
variants=("$@")
[ ${#variants[@]} -gt 0 ] || variants=(before after cve21816_alone after_cve21816 assert_before assert_after upstream_master)
for v in "${variants[@]}"; do
  case $v in
    before) run --no-tests before "base commit 5f998146, no diff" ;;
    after) run --no-tests after "developer patch e8c3edb9 (patches/libredwg.cve-2020-21814.diff)" "$dev" ;;
    cve21816_alone) run --no-tests cve21816_alone "7e4c59b6 alone, the developer patch of libredwg.cve-2020-21816 (patches/libredwg.cve-2020-21816.diff)" "$cve21816" ;;
    after_cve21816) run --no-tests after_cve21816 "7e4c59b6 then the developer patch e8c3edb9 (the changed lines of the SEC-bench gold patch)" "$cve21816" "$dev" ;;
    assert_before) run assert_before "base commit 5f998146 + scripts/escape_invariant.diff" "$inv" ;;
    assert_after) run assert_after "developer patch e8c3edb9 + scripts/escape_invariant.diff" "$dev" "$inv" ;;
    min) run --no-tests min "minimal patch (patches/libredwg.cve-2020-21814.min.diff)" "$min" ;;
    upstream_master) run --no-tests --inputs "$minputs" --ref master "programs/escape.c programs/escape.h" upstream_master "upstream master, whole tree" ;;
    *) echo "unknown variant $v" >&2; exit 2 ;;
  esac
done
