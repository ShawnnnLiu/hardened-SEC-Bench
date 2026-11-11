#!/bin/bash
# Prints the --merge arguments of scripts/render_cases_table.py for the
# scripts/whiteout_cases.py case families (njs.cve-2023-27727).
# The first matching entry names a case's group, so the explicit
# wrong_fallback list comes before the wrong_* prefix.
#   faulty         accessor tombstone read by njs_object_property (base: ASAN)
#   wrong_fallback data tombstone whose consumer probes a function slot and
#                  falls back cleanly (valueOf, toJSON): OK on base although
#                  the tombstone is returned
#   wrong_value    data tombstone whose consumer uses the returned value
#                  (error dump, join, defineProperty, string conversion):
#                  wrong result on base
#   valid          controls that reach no tombstone through njs_object_property
#   poc            the dataset proof-of-concept (added by the runner)
echo --merge "faulty=faulty_*"
echo --merge "wrong_fallback=wrong_data_prim_vo,wrong_dataro_prim_vo,wrong_assign_prim_vo,wrong_data_json,wrong_dataro_json,wrong_assign_json"
echo --merge "wrong_value=wrong_*"
echo --merge "valid=valid_*"
echo --merge "poc=poc"
