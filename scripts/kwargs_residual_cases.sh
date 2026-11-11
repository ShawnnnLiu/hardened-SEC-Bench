#!/bin/bash
# Keyword hashes that reach the final branch of gen_hash() with a hash
# already started (a leading **h, or a flush at the compiler stack limit):
# index assignment with literal pairs after **h, calls with **h followed
# by more than 14 literal pairs, calls with more than about 47 pairs, and
# hash literals as a control. One mruby process per case; each case is
# compared with the CRuby 2.7 result.
# Usage (inside the instance container): kwargs_residual_cases.sh <mruby binary>
# Passing `ruby` instead of an mruby binary runs the same cases on the
# image's CRuby, which checks the expected values.
set -u
MRUBY=$1
D=$(mktemp -d)
ok=0; wrong=0; asan=0; total=0

run_case() { # name, ruby source printing the value, expected output
  local f=$D/$1.rb out res
  printf '%s\n' "$2" > "$f"
  out=$("$MRUBY" "$f" 2>&1)
  total=$((total+1))
  if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then
    asan=$((asan+1))
    res="ASAN $(grep -m1 -o 'AddressSanitizer: [A-Za-z-]* on [a-z ]*address 0x[0-9a-f]*' <<<"$out")"
  elif [ "$(tail -1 <<<"$out")" = "$3" ]; then
    ok=$((ok+1)); res=OK
  else
    wrong=$((wrong+1)); res="WRONG got=$(tail -1 <<<"$out")"
  fi
  printf '%-26s %s\n' "$1" "$res"
}

pairs() { for i in $(seq 1 $1); do printf 'k%d: %d, ' $i $i; done | sed 's/, $//'; }
ipairs() { for i in $(seq 0 $(($1-1))); do printf '%d=>%d, ' $i $i; done | sed 's/, $//'; }

# index assignment: literal pairs after a double splat
recorder='class R; def []=(*a); $got = a; end; end; o = R.new; h = {z: 0}'
for n in 0 1 2 5 11 12 13 14; do
  args=$(seq -s, 1 $n); args=${args:+$args,}
  exp=$(seq -s', ' 1 $n); exp="[${exp:+$exp, }"
  run_case "aset_splat_kw_n$n"    "$recorder; o[${args}**h, k: 99] = :rhs; p \$got"        "${exp}{:z=>0, :k=>99}, :rhs]"
  run_case "aset_splat_kw2_n$n"   "$recorder; o[${args}**h, k: 99, j: 98] = :rhs; p \$got" "${exp}{:z=>0, :k=>99, :j=>98}, :rhs]"
  run_case "aset_kw_splat_kw_n$n" "$recorder; o[${args}k: 99, **h, j: 98] = :rhs; p \$got" "${exp}{:k=>99, :z=>0, :j=>98}, :rhs]"
done

# calls and hash literals: a double splat followed by n literal pairs
def='def f(*a, **k); p [a.size, k.size]; end; h = {z: 0}'
for n in 1 13 14 15 16 20 30 40 46; do
  run_case "call_splat_first_n$n" "$def; f(1, **h, $(pairs $n))"   "[1, $((n+1))]"
  run_case "lit_splat_first_n$n"  "h = {z: 0}; p({**h, $(pairs $n)}.size)" "$((n+1))"
done

# calls and hash literals: long keyword lists without a splat
for n in 40 47 48 60 80 120; do
  run_case "call_kw_n$n"     "$def; f(1, $(pairs $n))" "[1, $n]"
  run_case "call_kwonly_n$n" "$def; f($(pairs $n))"    "[0, $n]"
  run_case "lit_hash_n$n"    "p({$(pairs $n)}.size)"   "$n"
done
run_case "merge_int_keys_127" "p({}.merge($(ipairs 127)).size)" "127"

echo "summary: $ok OK, $wrong WRONG, $asan ASAN of $total"
