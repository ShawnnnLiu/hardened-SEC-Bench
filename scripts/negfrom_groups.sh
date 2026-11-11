#!/bin/bash
# Prints the --merge arguments of scripts/render_cases_table.py for the
# scripts/negfrom_cases.py case families (njs.cve-2022-31307).
# The first matching entry names a case's group.
#   bash negfrom_groups.sh     groups by receiver and by whether the case reaches the faulty state
set -f
S="u1 u3 u33"
VP="v1 v2 v31 v32 v33 v100 v1000 v1000000 v2147483648 v9007199254740992 inf cstr cobj cflt"
VO="v1 v2 v33 v1000 v2147483648 inf"
j() { local out="" r s t; for r in $1; do for s in $S; do for t in $2; do out="$out,lio_${r}_${s}_$t"; done; done; done; echo "${out#,}"; }
echo --merge "viol_poc=viol_poc_nospread,poc"
echo --merge "viol_prim=$(j prim "$VP")"
echo --merge "viol_obj=$(j obj "$VO")"
echo --merge "viol_proto=$(j proto "$VO")"
echo --merge "valid_negfrom=$(j 'prim obj proto' 'neg_n neg_n_tl neg_1')"
echo --merge "valid_lio=lio_prim_*,lio_obj_*,lio_proto_*"
echo --merge "rr=rr_*"
echo --merge "ctl=ctl_*"
echo --merge "d_search=d_indexOf_*,d_lastIndexOf_*,d_includes_*,d_startsWith_*,d_endsWith_*"
echo --merge "d_charslice=d_charAt_*,d_charCodeAt_*,d_slice1_*,d_slice2_*,d_substring1_*,d_substring2_*,d_substr1_*,d_substr2_*"
echo --merge "d_other=d_*"
echo --merge "x=x_*"
