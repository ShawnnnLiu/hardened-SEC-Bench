#!/bin/bash
# Prints the --merge arguments of scripts/render_cases_table.py for the
# scripts/recurdesc_cases.py case families (njs.cve-2022-31306).
set -f
echo --merge "rc_accessor=rc_get_*,rc_set_*"
echo --merge "rc_index=rc_idx0_*,rc_newidx_*"
echo --merge "rc_depth2=rc_depth2"
echo --merge "poc=poc"
echo --merge "reent_value=rc_value_*"
echo --merge "reent_wec=rc_writable_*,rc_enumerable_*,rc_configurable_*"
echo --merge "ctl=ctl_*"
echo --merge "valid=valid_*"
