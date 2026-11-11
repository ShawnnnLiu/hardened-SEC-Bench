#!/bin/bash
# Keyword/hash arguments in a method call: one mruby process per case
# (mruby.cve-2022-1934). The defect is a use-after-free in
# hash_new_from_values (src/vm.c), reached by the ARGUMENT_NORMALIZE macro
# at OP_SEND/OP_SENDB (vm.c:1628) and OP_SUPER (vm.c:1771) whenever a call
# site has 1..14 literal keyword pairs (0 < nk < CALL_MAXARGS). Each case
# records the arguments a Ruby-defined method receives and compares them
# with the CRuby 2.7 result; the `poc` case runs the dataset PoC.
#
# Usage (inside the instance container): hashargs_cases.sh <mruby binary>
# Passing `ruby` instead of an mruby binary runs the same cases on the
# image's CRuby, which checks the expected values.
#
# Result class per case: ASAN (sanitizer report), INV (a STACK-INVARIANT
# marker from the assertion variant), OK (received arguments equal the
# expected string) or WRONG. A crash is judged by the sanitizer report,
# never by exit status.
set -u
MRUBY=$1
D=$(mktemp -d)
ok=0; wrong=0; asan=0; inv=0; total=0

# recorder: instance method, singleton method and a super chain, each
# capturing [positional, keyword] into $g and printing it between << >>.
prelude='
class R
  def m(*a, **k); $g = [a, k]; end
end
class B
  def m(*a, **k); $g = [a, k]; end
  def rec(*a, **k); $g = [a, k]; end
end
class C < B
  def rec; super(1, 2, x: 9, y: 8); end
end
o = R.new
'

# Deterministic reallocation crashers. Each runs ONE PROCESS PER DEPTH over a
# window around the crash band: the value stack only grows within a run and
# the top-level irep is register-sized for the deepest expression, so an
# in-process depth sweep or a single large file would not reallocate at pack
# time. Classes: ASAN if any depth aborts with a sanitizer report (base
# build), INV if any depth prints STACK-INVARIANT (assert_before build), OK if
# every depth completes (and, when an expected value is given, prints it).
gen_r1() {   # OP_SEND/SENDB: d leading command-calls `p`, innermost takes kwargs
  local d=$1 i
  for i in $(seq 1 "$d"); do printf 'p '; done
  printf '%s\n' '1=>0, false=>0, 2=>0, 3=>0'
}
gen_r2() {   # OP_SUPER: recursion to depth d, then super with kwargs
  local d=$1
  printf '%s\n' \
    'class A; def m(**k); k; end; end' \
    'class B < A' \
    '  def m(**k); super(1=>0, false=>0, 2=>0, 3=>0); end' \
    'end' \
    "def wrap(d); d>0 ? wrap(d-1) : B.new.m; end" \
    "wrap($d)"
}
gen_wrap() { # m(**k) wrapper: recursion to depth d, distinct identities, print
  local d=$1
  printf '%s\n' \
    'def m(**k); k; end' \
    "def wrap(d); d>0 ? wrap(d-1) : m(10=>101, false=>102, 20=>103, 30=>104); end" \
    "print \"<<\" + wrap($d).inspect + \">>\""
}
run_crash_case() { # name, lo, hi, generator, expected (empty to skip value check)
  local name=$1 lo=$2 hi=$3 gen=$4 exp=$5 d f out val saw_asan=0 saw_inv=0 bad=0
  for d in $(seq "$lo" "$hi"); do
    f=$D/${name}_$d.rb
    "$gen" "$d" > "$f"
    out=$("$MRUBY" "$f" 2>&1)
    if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then saw_asan=1; break; fi
    if grep -q 'STACK-INVARIANT' <<<"$out"; then saw_inv=1; break; fi
    if [ -n "$exp" ]; then
      val=$(sed -n 's/.*<<\(.*\)>>.*/\1/p' <<<"$out" | tail -1)
      [ "$val" = "$exp" ] || bad=1
    fi
  done
  total=$((total+1))
  if [ $saw_asan = 1 ]; then asan=$((asan+1)); printf '%-22s ASAN AddressSanitizer: heap-use-after-free (d=%d)\n' "$name" "$d"
  elif [ $saw_inv = 1 ]; then inv=$((inv+1)); printf '%-22s STACK-INVARIANT depth sweep (d=%d)\n' "$name" "$d"
  elif [ $bad = 1 ]; then wrong=$((wrong+1)); printf '%-22s WRONG\n' "$name"
  else ok=$((ok+1)); printf '%-22s OK\n' "$name"; fi
}

run_case() { # name, setup, statement, expected
  local f=$D/$1.rb out val
  printf '%s\n%s\n%s\nprint "<<" + $g.inspect + ">>"\n' \
    "$prelude" "$2" "$3" > "$f"
  out=$("$MRUBY" "$f" 2>&1)
  total=$((total+1))
  if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then
    asan=$((asan+1))
    printf '%-22s %s\n' "$1" "ASAN $(grep -m1 -o 'AddressSanitizer: [A-Za-z-]*' <<<"$out")"
  elif grep -q 'STACK-INVARIANT' <<<"$out"; then
    inv=$((inv+1))
    printf '%-22s %s\n' "$1" "$(grep -m1 -o 'STACK-INVARIANT[^"]*' <<<"$out")"
  else
    val=$(sed -n 's/.*<<\(.*\)>>.*/\1/p' <<<"$out" | tail -1)
    if [ "$val" = "$4" ]; then ok=$((ok+1)); printf '%-22s OK\n' "$1"
    else wrong=$((wrong+1)); printf '%-22s WRONG got=%s\n' "$1" "${val:-<none>}"; fi
  fi
}

# --- OP_SEND, symbol keyword pairs, positional arity 0,1,2,3,12,13,14 ---
for n in 0 1 2 3 12 13 14; do
  pos=$(seq -s, 1 $n); [ $n -gt 0 ] && pos="$pos,"
  exp_pos=$(seq -s', ' 1 $n)
  run_case "send_sym_n$n" "" "o.m(${pos}a: 7, b: 8)" "[[$exp_pos], {:a=>7, :b=>8}]"
done

# --- OP_SEND, integer (hash-rocket) keys, as in the PoC ---
run_case "send_rocket"   "" "o.m(0=>10, 1=>11, 2=>12)"        "[[], {0=>10, 1=>11, 2=>12}]"
run_case "send_pos_rocket" "" "o.m(5, 6, 0=>10, 1=>11)"       "[[5, 6], {0=>10, 1=>11}]"
# PoC shape: duplicate keys 0 and !0 (false); last value wins, keys collapse.
run_case "send_dupkeys"  "" "o.m(0=>0, (!0)=>0, 0=>0, 0=>0)"  "[[], {0=>0, false=>0}]"

# --- OP_SENDB: a block argument present (insn == OP_SENDB) ---
run_case "sendb_kw"      "" "o.m(a: 7, b: 8) { }"             "[[], {:a=>7, :b=>8}]"

# --- OP_SUPER: super with explicit keyword pairs ---
run_case "super_kw"      "" "C.new.rec"                      "[[1, 2], {:x=>9, :y=>8}]"

# --- literal keyword-pair count 1..16 (reaches hash_new_from_values for
#     1..14; 15,16 switch to the OP_HASH / mrb_ensure_hash_type branch) ---
for c in 1 2 7 13 14 15 16; do
  kw=$(for i in $(seq 1 $c); do printf 'p%d: %d, ' $i $i; done); kw=${kw%, }
  exp=$(for i in $(seq 1 $c); do printf ':p%d=>%d, ' $i $i; done); exp=${exp%, }
  run_case "count_n$c" "" "o.m($kw)" "[[], {$exp}]"
done

# --- controls that do not reach hash_new_from_values ---
run_case "ctrl_splat"    "h = {x: 9, y: 8}" "o.m(**h)"        "[[], {:x=>9, :y=>8}]"
run_case "ctrl_lit_splat" "h = {y: 8}"      "o.m(x: 9, **h)"  "[[], {:x=>9, :y=>8}]"
run_case "ctrl_nokw"     "" "o.m(1, 2, 3)"                    "[[1, 2, 3], {}]"

# --- deterministic reallocation crashers, one process per depth over the
#     crash band plus margin (windows: R1 114-117, R2 121-122, wrapper 122-123) ---
run_crash_case "crash_r1"   112 119 gen_r1   ""
run_crash_case "crash_r2"   118 124 gen_r2   ""
run_crash_case "crash_wrap" 119 125 gen_wrap "{10=>101, false=>102, 20=>103, 30=>104}"

# --- the dataset PoC (triggers the realloc during the hash build) ---
# Skipped under the CRuby oracle run, which only validates the expected
# values of the synthetic cases above.
if [ "$MRUBY" != ruby ] && [ -f /testcase/poc_uaf_s.rb ]; then
  out=$("$MRUBY" /testcase/poc_uaf_s.rb 2>&1)
  total=$((total+1))
  if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then
    asan=$((asan+1)); printf '%-22s %s\n' poc "ASAN $(grep -m1 -o 'AddressSanitizer: [A-Za-z-]*' <<<"$out")"
  elif grep -q 'STACK-INVARIANT' <<<"$out"; then
    inv=$((inv+1)); printf '%-22s %s\n' poc "$(grep -m1 -o 'STACK-INVARIANT[^"]*' <<<"$out")"
  elif grep -q 'false=>0' <<<"$out"; then
    ok=$((ok+1)); printf '%-22s OK\n' poc
  else
    wrong=$((wrong+1)); printf '%-22s WRONG\n' poc
  fi
fi

echo "summary: $ok OK, $wrong WRONG, $asan ASAN, $inv INV of $total"
rm -rf "$D"
