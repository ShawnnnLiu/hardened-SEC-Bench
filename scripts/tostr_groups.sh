#!/bin/bash
# Prints the --merge arguments for scripts/render_cases_table.py over the
# njs.cve-2022-29369 case set (scripts/tostr_cases.py). Groups:
#   trig_selfmod   the self-modifying-key trigger over seven contexts (7)
#   trig_unittest  the dataset global-corruption trigger, single-call (3)
#   ctl            controls that reach METHOD_FRAME without the second-
#                  conversion failure (9)
#   valid          a real method call and the no-call sanity cases (5)
# The dataset PoC (case "poc") stays its own group.
echo "--merge trig_selfmod=trig_selfmod_* --merge trig_unittest=trig_unittest_* --merge ctl=ctl_* --merge valid=valid_*"
