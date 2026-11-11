#!/bin/bash
# Prints the --merge arguments of scripts/render_cases_table.py for the
# scripts/trimzero_cases.py case families (njs.cve-2022-38890).
# The first matching entry names a case's group.
#   bash trimzero_groups.sh   groups the faulty set (tz_idx vs the rest),
#                             the non-faulty producers and the valid inputs
set -f
KINDS="nbsp ogham ls ps bom ideo run3 mix_sp_ls mix_tab_sp_ls long40"

idxlist() {   # comma list of tz_<kind>_idx
    local out="" k
    for k in $KINDS; do out="$out,tz_${k}_idx"; done
    echo "${out#,}"
}

echo --merge "poc=poc"
echo --merge "tz_idx=$(idxlist)"
echo --merge "tz_other=tz_*"
echo --merge "prod_trim=prod_trim_*"
echo --merge "prod_trimStart=prod_trimStart_*"
echo --merge "valid_utf8=valid_mix_trail_*,valid_mix_lead_*,valid_mix_both_*,valid_nows_*"
echo --merge "valid_ascii=valid_ascii_ws_*,valid_ascii_mix_*,valid_empty_*"
