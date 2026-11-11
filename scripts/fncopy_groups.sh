#!/bin/bash
# Prints the --merge arguments of scripts/render_cases_table.py for the
# scripts/fncopy_cases.py case families (njs.cve-2022-43284).
# Grouped by structure x retrigger; within each group the five value cases
# (undef, null, num, str, obj) differ only for undef on the base build.
#   self_ref/self_call     a self-reference closure binding (the PoC shape);
#                          self_call+undef gives a sanitizer report on base
#   local_ref/local_call   a function in an enclosing function, not self-naming
#   global_ref/global_call a function declaration at script top level
#   valid                  controls that never assign undefined to a live
#                          function binding
#   masked                 the invariant is violated but the wrong value is
#                          overwritten, so the output is correct (INV only)
#   poc                    the dataset proof-of-concept (added by the runner)
echo --merge "self_ref=self_ref_*"
echo --merge "self_call=self_call_*"
echo --merge "local_ref=local_ref_*"
echo --merge "local_call=local_call_*"
echo --merge "global_ref=global_ref_*"
echo --merge "global_call=global_call_*"
echo --merge "valid=valid_*"
echo --merge "masked=masked_*"
echo --merge "poc=poc"
