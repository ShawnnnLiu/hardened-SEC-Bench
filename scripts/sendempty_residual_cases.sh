#!/bin/bash
# 15-argument probe for mruby.cve-2022-0570, separate from the mrb_f_send
# array-bounds bug. The blind second reading (phase 1) reported that a call
# with exactly 15 positional arguments to a splat or fixed-arity method faults
# with a NULL dereference at the first mrb_f_send / in the general argument
# path, not the empty-packed-array overflow: gen_values (codegen.c, limit 14)
# returns 15 values unpacked while the call still carries n = 15 =
# CALL_MAXARGS, so the callee misreads the first argument value as the packed
# array. This probe checks `def f(*a); a.size; end` at 13..20 arguments on each
# build, to see whether 15 faults and whether the developer patch (which only
# guards the mrb_f_send empty-array read) changes it. CRuby returns the count
# for every arity.
#
# Usage (inside the instance container): sendempty_residual_cases.sh <mruby binary>
set -u
MRUBY=$1
D=$(mktemp -d)
ok=0; wrong=0; asan=0; total=0

probe() { # name, nargs, expected
  local f=$D/$1.rb args out val
  args=$(seq -s, 1 "$2")
  printf 'def f(*a); print "<<" + a.size.to_s + ">>"; end\nf(%s)\n' "$args" > "$f"
  out=$("$MRUBY" "$f" 2>&1); total=$((total+1))
  if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then
    asan=$((asan+1)); printf '%-10s ASAN %s\n' "$1" "$(grep -m1 -o 'SEGV\|heap-buffer-overflow' <<<"$out" | head -1)"
  else
    val=$(sed -n 's/.*<<\(.*\)>>.*/\1/p' <<<"$out" | tail -1)
    if [ "$val" = "$3" ]; then ok=$((ok+1)); printf '%-10s OK\n' "$1"
    else wrong=$((wrong+1)); printf '%-10s WRONG got=%s\n' "$1" "${val:-<none>}"; fi
  fi
}

probe splat13 13 "13"
probe splat14 14 "14"
probe splat15 15 "15"
probe splat16 16 "16"
probe splat17 17 "17"
probe splat20 20 "20"

echo "summary: $ok OK, $wrong WRONG, $asan ASAN of $total"
rm -rf "$D"
