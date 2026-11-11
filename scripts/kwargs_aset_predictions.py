"""Predicted result class of every scripts/kwargs_aset_cases.sh case under
each hypothesis, for scripts/check_predictions.py (mruby.cve-2022-1276).

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG,
ASAN, INV (STACK-INVARIANT compile error) or - (not modelled).

dev: the developer's model, from the message of c8c083cb75: with 13
  positional arguments, the keyword hash and the right-hand side make 15
  arguments, one more than the 14 registers, so only n == 13 fails, and
  the patch (pack at n == 13) fixes every case.
ours: H1, the CVE path: after gen_hash(s, ..., VAL, 0) has pushed the
  hash, the n < 14 branch of gen_assignment() pushes once more, so for 0
  to 12 positional arguments the right-hand side lands one register past
  the last argument read (WRONG for a Ruby-defined []=, OK by the script's
  definition for String#[]=, which only checks for a sanitizer report), and
  at n == 13 the final OP_ARRAY starts one register late and the VM reads
  an Integer as the argument array (ASAN). With 14 or more positional
  arguments or a splat, gen_values() packs the arguments (n = 15) and the
  else branch accounts for the stack correctly (OK). The developer patch
  moves n == 13 to the packed path and leaves 0 to 12 WRONG; the
  root-cause patch cancels the push (OK).
  H2, the residual: a 60-pair keyword hash is flushed at the stack limit
  and the final branch of gen_hash() leaves a second hash, so kwbig cases
  are WRONG for 0 to 12 positional arguments and ASAN for 13 to 16 under
  before, after and root, and OK under root_hash (the gen_hash() fix).
  assert_<v>: a STACK-INVARIANT check at the end of the argument block of
  gen_assignment() (scripts/kwargs_aset_invariant.diff) fails for every
  case in which H1 or H2 leaves an extra value: on the base build all
  keyword cases with at most 13 positional arguments and all kwbig cases;
  with the root-cause patch only the kwbig cases.
opasgn_kw_n1 is compiled by NODE_OP_ASGN, outside both hypotheses (-).

This file was written on 2026-10-12 after the case logs of mruby.cve-2022-1276
existed; for later instances the predictions are written before the
`before` variant runs.
"""
cols = ["dev:before", "dev:after", "ours:before", "ours:after", "ours:root",
        "ours:root_hash", "ours:assert_before", "ours:assert_root"]
rows = []


def add(name, dev_before, dev_after, before, after, root, root_hash, a_before, a_root):
    rows.append([name, dev_before, dev_after, before, after, root, root_hash, a_before, a_root])


for n in range(17):
    dev_b = "ASAN" if n == 13 else "OK"
    # H1 for a Ruby-defined []= receiving the arguments
    if n <= 12:
        h1 = ("WRONG", "WRONG", "OK", "OK", "INV", "OK")
    elif n == 13:
        h1 = ("ASAN", "OK", "OK", "OK", "INV", "OK")
    else:
        h1 = ("OK", "OK", "OK", "OK", "OK", "OK")
    add(f"nokw_n{n}", "OK", "OK", "OK", "OK", "OK", "OK", "OK", "OK")
    for form in ("kw", "kwsplat", "kw2"):
        add(f"{form}_n{n}", dev_b, "OK", *h1)
    # H2: 60-pair hash
    h2 = ("WRONG", "WRONG", "WRONG") if n <= 12 else ("ASAN", "ASAN", "ASAN")
    add(f"kwbig_n{n}", dev_b, "OK", *h2, "OK", "INV", "INV")
    add(f"kwval_n{n}", dev_b, "OK", *h1)
    add(f"masgn_n{n}", dev_b, "OK", *h1)

add("splat_kw", "OK", "OK", "OK", "OK", "OK", "OK", "OK", "OK")
add("splat_mid_kw", "OK", "OK", "OK", "OK", "OK", "OK", "OK", "OK")
add("chain_kw", "OK", "OK", "WRONG", "WRONG", "OK", "OK", "INV", "OK")
add("opasgn_kw_n1", "-", "-", "-", "-", "-", "-", "-", "-")
for n in range(15):
    # String#[]= reads its arguments with mrb_get_args; only a sanitizer report counts
    if n <= 12:
        add(f"str_kw_n{n}", "OK", "OK", "OK", "OK", "OK", "OK", "INV", "OK")
    elif n == 13:
        add(f"str_kw_n{n}", "ASAN", "OK", "ASAN", "OK", "OK", "OK", "INV", "OK")
    else:
        add(f"str_kw_n{n}", "OK", "OK", "OK", "OK", "OK", "OK", "OK", "OK")

print("\t".join(["case"] + cols))
for r in rows:
    print("\t".join(r))
