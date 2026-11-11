#!/bin/bash
# Prints the --merge arguments for scripts/render_cases_table.py over the
# njs.cve-2022-34029 case set (scripts/awaiterr_cases.py). Groups:
#   trig_ctor   the throwing-constructor trigger inside a function (6)
#   trig_tdz    the uninitialised-binding trigger inside a function (6)
#   top         the two triggers at module top level, benign (2)
#   ctl         controls that reach the AWAIT opcode without failing (12)
#   valid       sanity cases with no async (2)
# The dataset PoC (case "poc") stays its own group.
echo "--merge trig_ctor=trig_ctor_* --merge trig_tdz=trig_tdz_* --merge top=top_* --merge ctl=ctl_* --merge valid=valid_*"
