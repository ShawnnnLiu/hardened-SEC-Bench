#!/bin/bash
# Prints the --merge arguments of scripts/render_cases_table.py for the
# scripts/apply_args_cases.py case groups (njs.cve-2021-46462).
# The first matching entry names a case's group.
#   bash apply_args_groups.sh          families (slow and hole split by callee kind, limit by container)
#   bash apply_args_groups.sh slow     slow-array containers
#   bash apply_args_groups.sh limit    argument counts by container and size
set -f
ALL="lam max of obj concat fcc push actor"
j() { local out="" a b; for a in $1; do for b in $2; do out="$out,${3}${a}_${b}"; done; done; echo "${out#,}"; }
case "${1:-}" in
slow)
  for c in freeze seal defenum defro defget lenback freeze256 freeze1024 freezeempty; do
    echo --merge "$c=slow_${c}_*"
  done
  for g in hole limit huge poc valid othr; do echo --merge "$g=${g}_*"; done
  echo --merge "poc=poc,poc_*"
  ;;
limit)
  for c in flatn like lenset idxbig; do
    for n in 1024 1025 2000 9000 40000; do
      echo --merge "${c}_$n=limit_${c}_lam_$n,limit_${c}_max_$n"
    done
  done
  for g in slow hole huge poc valid othr; do echo --merge "$g=${g}_*"; done
  echo --merge "poc=poc,poc_*"
  ;;
*)
  C="freeze seal defenum defro defget lenback freeze256 freeze1024 freezeempty"
  echo --merge "slow_lam=$(j "$C" lam slow_)"
  echo --merge "slow_native=$(j "$C" "max of obj concat fcc push actor" slow_)"
  H="lead mid trail all arr3 lenfast"
  echo --merge "hole_lam=$(j "$H" lam hole_)"
  echo --merge "hole_store=$(j "$H" "of push actor" hole_)"
  echo --merge "hole_convert=$(j "$H" "max concat fcc" hole_)"
  for c in flatn like lenset idxbig; do
    echo --merge "limit_$c=limit_${c}_*"
  done
  echo --merge "huge=huge_*"
  echo --merge "poc=poc,poc_*"
  echo --merge "valid=valid_*"
  echo --merge "othr=othr_*"
  ;;
esac
