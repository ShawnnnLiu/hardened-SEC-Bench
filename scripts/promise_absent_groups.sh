#!/bin/bash
# Prints the --merge arguments of scripts/render_cases_table.py for the
# scripts/promise_absent_cases.py case families (njs.cve-2022-32414).
# The first matching entry names a case's group.
#   bash promise_absent_groups.sh            families by method and absent position
#   bash promise_absent_groups.sh consumers  race/any cases with index 0 absent, by consumer
set -f
F="al1 al2p fn3 hole1 sparse"; L="al2q holemid"; A="al1 al2p al2q fn3 hole1 holemid sparse"
j() { local out="" m i c; for m in $1; do for i in $2; do for c in ${3:-*}; do out="$out,${m}_${i}_$c"; done; done; done; echo "${out#,}"; }
if [ "${1:-}" = consumers ]; then
  for c in then args str json vals avar alet forin pocshape chain freeze; do
    echo --merge "first_$c=$(j 'race any' "$F" "$c")"
  done
fi
echo --merge "race_any_first=$(j 'race any' "$F")"
echo --merge "race_any_later=$(j 'race any' "$L")"
echo --merge "all_absent=$(j all "$A")"
echo --merge "allSettled_absent=$(j allSettled "$A")"
echo --merge "big=race_big_*,any_big_*,all_big_*,allSettled_big_*"
echo --merge "agg_absent=agg_al1,agg_al2q,agg_hole1,agg_holemid,agg_sparse"
echo --merge "src=src_*"
echo --merge "valid=race_*,any_*,all_*,allSettled_*,agg_dense,agg_alfull"
