#!/bin/bash
# Index assignment with keyword arguments: one mruby process per case.
# Each case calls a Ruby-defined []=(*a) and compares the received
# arguments with the CRuby 2.7 result; str_* cases use String#[]= (a C
# function reading its arguments with mrb_get_args) and only check for
# a sanitizer report.
# Usage (inside the instance container): kwargs_aset_cases.sh <mruby binary>
# Passing `ruby` instead of an mruby binary runs the same cases on the
# image's CRuby, which checks the expected values.
set -u
MRUBY=$1
D=$(mktemp -d)
ok=0; wrong=0; asan=0; total=0

recorder='class R; def []=(*a); $got = a; end; def [](*a); $ref = a; R.new; end; end; o = R.new'

run_case() { # name, setup, statement, expected arguments
  local f=$D/$1.rb out res
  printf '%s\n%s\n%s\nexp = %s\nputs($got == exp ? "OK" : "WRONG got=#{$got.inspect}")\n' \
    "$recorder" "$2" "$3" "$4" > "$f"
  out=$("$MRUBY" "$f" 2>&1)
  total=$((total+1))
  if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then
    asan=$((asan+1))
    res="ASAN $(grep -m1 -o 'AddressSanitizer: [A-Za-z-]* on [a-z ]*address 0x[0-9a-f]*' <<<"$out")"
  else
    res=$(tail -1 <<<"$out")
    case $res in OK) ok=$((ok+1));; *) wrong=$((wrong+1));; esac
  fi
  printf '%-22s %s\n' "$1" "$res"
}

big=$(for i in $(seq 1 60); do printf 'k%d: %d, ' $i $i; done); big=${big%, }

for n in $(seq 0 16); do
  args=$(seq -s, 1 $n); exp="[$args"
  [ $n -gt 0 ] && args="$args," && exp="$exp,"
  run_case "nokw_n$n"     ""          "o[${args%,}] = :rhs"                 "${exp}:rhs]"
  run_case "kw_n$n"       ""          "o[${args}k: 99] = :rhs"              "${exp}{k: 99}, :rhs]"
  run_case "kwsplat_n$n"  ""          "o[${args}**{k: 99}] = :rhs"          "${exp}{k: 99}, :rhs]"
  run_case "kw2_n$n"      "h={j: 98}" "o[${args}k: 99, **h] = :rhs"         "${exp}{k: 99, j: 98}, :rhs]"
  run_case "kwbig_n$n"    ""          "o[${args}${big}] = :rhs"             "${exp}{${big}}, :rhs]"
  run_case "kwval_n$n"    ""          "v = (o[${args}k: 99] = :rhs); raise 'value' unless v == :rhs" "${exp}{k: 99}, :rhs]"
  run_case "masgn_n$n"    ""          "o[${args}k: 99], b = :rhs, 2"       "${exp}{k: 99}, :rhs]"
done

run_case "splat_kw"       "a=[1,2]" "o[*a, k: 99] = :rhs"         "[1, 2, {k: 99}, :rhs]"
run_case "splat_mid_kw"   "a=[2,3]" "o[1, *a, 4, k: 99] = :rhs"   "[1, 2, 3, 4, {k: 99}, :rhs]"
run_case "chain_kw"       ""        "o[1, k: 1][2, j: 2] = :rhs"  "[2, {j: 2}, :rhs]"
# op-assign is compiled by a different path (NODE_OP_ASGN), not gen_assignment
run_case "opasgn_kw_n1"   ""        "o[1, k: 99] &&= :rhs"        "[1, {k: 99}, :rhs]"

for n in $(seq 0 14); do
  args=$(for i in $(seq 1 $n); do printf '0,'; done)
  run_case "str_kw_n$n" "s='='" "begin; s[${args}k: 99] = 0; rescue => e; \$got = e.class; end" "\$got"
done

echo "summary: $ok OK, $wrong WRONG, $asan ASAN of $total"
rm -rf "$D"
