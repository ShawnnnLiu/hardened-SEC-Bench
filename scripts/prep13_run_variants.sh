#!/bin/bash
# Runs the variants of libredwg.cve-2021-28237 (logs/libredwg.cve-2021-28237/variants*)
# one after the other, through scripts/libredwg_run_variant.sh with the case
# script scripts/prep13_cases.py. The counterpart of scripts/wescape_run_variants.sh
# (libredwg.cve-2020-21814) with this instance's image, patches and variant names.
#
# Usage: prep13_run_variants.sh <cpuset> <variant>...
#
#   <cpuset>  CPUs of the variant container, e.g. 6-7 (memory cap 3g)
#   variant   before after root upstream_master assert_before assert_after min
#
# before is the image tree 49aeec4e; after is the developer patch ea0b9522;
# root is scripts/prep13_rootcand.diff (base + an unconditional realloc of
# dwg->object for num + tbl->number objects, without the developer guard);
# assert_before and assert_after add the PREP13-INVARIANT instrumentation
# (scripts/prep13_invariant_before.diff, scripts/prep13_invariant_after.diff)
# and run the test suite; min is patches/libredwg.cve-2021-28237.min.diff.
# Needs the local image secb.built.x86_64.libredwg.cve-2021-28237:base from
# scripts/libredwg_make_built_image.sh. Run from the repository root.
set -eu
cpu=$1; shift
[ $# -gt 0 ] || { echo "name at least one variant" >&2; exit 2; }
img=secb.built.x86_64.libredwg.cve-2021-28237:base
out=logs/libredwg.cve-2021-28237/variants
cases=scripts/prep13_cases.py
dev=patches/libredwg.cve-2021-28237.diff
root=scripts/prep13_rootcand.diff
invb=scripts/prep13_invariant_before.diff
inva=scripts/prep13_invariant_after.diff
min=patches/libredwg.cve-2021-28237.min.diff
export SECB_DOCKER_OPTS="--cpuset-cpus $cpu --memory 3g --memory-swap 3g"
for v in "$@"; do
  echo "=== $v started $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  case $v in
    before) scripts/libredwg_run_variant.sh --no-tests --cases "$cases" "$img" "$out" before "base commit 49aeec4e, no diff" ;;
    after) scripts/libredwg_run_variant.sh --no-tests --cases "$cases" "$img" "$out" after "developer patch ea0b9522 (patches/libredwg.cve-2021-28237.diff)" "$dev" ;;
    root) scripts/libredwg_run_variant.sh --no-tests --cases "$cases" "$img" "$out" root "base + unconditional realloc of dwg->object for num + tbl->number objects, without the developer guard (scripts/prep13_rootcand.diff)" "$root" ;;
    upstream_master) scripts/libredwg_run_variant.sh --no-tests --ref master "src/decode.c src/decode_r11.c" --cases "$cases" "$img" "$out" upstream_master "upstream master, whole tree" ;;
    assert_before) scripts/libredwg_run_variant.sh --cases "$cases" "$img" "$out" assert_before "base commit 49aeec4e + scripts/prep13_invariant_before.diff" "$invb" ;;
    assert_after) scripts/libredwg_run_variant.sh --cases "$cases" "$img" "$out" assert_after "developer patch ea0b9522 + scripts/prep13_invariant_after.diff" "$dev" "$inva" ;;
    min) scripts/libredwg_run_variant.sh --no-tests --cases "$cases" "$img" "$out" min "minimal patch (patches/libredwg.cve-2021-28237.min.diff)" "$min" ;;
    *) echo "unknown variant $v" >&2; exit 2 ;;
  esac
  echo "=== $v finished $(date -u +%Y-%m-%dT%H:%M:%SZ): $(grep "^$v | " "$out.log" | tail -1 | cut -c1-200)"
done
echo "PREP13 VARIANTS DONE"
