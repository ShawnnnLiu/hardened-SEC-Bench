#!/bin/bash
# Discarded hash / keyword-hash literals with a `**` splat
# (mruby.cve-2022-0240). The defect is in gen_hash()
# (mrbgems/mruby-compiler/core/codegen.c): when the hash value is discarded
# (val == 0, NOVAL), the function still emits OP_HASH / OP_HASHADD / OP_HASHCAT
# and the matching pop_n()/push() whenever a `**` splat (NODE_KW_REST_ARGS)
# makes `update` true with a pair present. Those pop/push calls move the
# compiler stack pointer although nothing was pushed for the discarded value,
# so every following instruction is emitted one or two registers too low and
# overwrites locals and temporaries. The symptom is layout dependent: a wrong
# result, a runtime TypeError (OP_HASHADD on a non-hash register), a
# compile-time "stack pointer underflow", or, when the shifted code reaches
# OP_SCLASS on an internal object whose class pointer is NULL, the SEGV in
# prepare_singleton_class reported by the dataset PoC. The developer patch
# guards only that one consumer (mrb_singleton_class_ptr); it leaves the
# compiler corruption, so every other form stays wrong.
#
# Usage (inside the instance container): nvalhash_cases.sh <mruby binary>
# Passing `ruby` instead of an mruby binary runs the same cases on the image's
# CRuby, which validates the expected values of the synthetic cases.
#
# Result class per case: ASAN (sanitizer report), INV (a STACK-INVARIANT
# marker from the assertion variant, printed at compile time), OK (printed
# sentinel equals the expected string) or WRONG. A crash is judged by the
# sanitizer report, never by exit status.
set -u
MRUBY=$1
D=$(mktemp -d)
ok=0; wrong=0; asan=0; inv=0; total=0

# Each synthetic case defines locals, runs the hash statement under test with
# its value discarded, then returns a sentinel computed from the locals. If
# the statement corrupts the compiler stack pointer the sentinel is wrong or
# the program aborts. The wrapper catches runtime exceptions and prints
# E:<class> so a TypeError is a value, not a crash.
run_case() { # name, body, expected
  local f=$D/$1.rb out val
  { printf 'def t\n  x = 111\n  y = 222\n'
    printf '  %s\n' "$2"
    printf '  [x, y]\nend\n'
    printf 'begin; print "<<" + t.inspect + ">>"; rescue => e; print "<<E:" + e.class.to_s + ">>"; end\n'
  } > "$f"
  out=$("$MRUBY" "$f" 2>&1)
  total=$((total+1))
  if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then
    asan=$((asan+1)); printf '%-20s %s\n' "$1" "ASAN $(grep -m1 -o 'AddressSanitizer: [A-Za-z-]*\|SEGV' <<<"$out")"
  elif grep -q 'STACK-INVARIANT' <<<"$out"; then
    inv=$((inv+1)); printf '%-20s %s\n' "$1" "$(grep -m1 -o 'STACK-INVARIANT[^"]*' <<<"$out")"
  else
    val=$(sed -n 's/.*<<\(.*\)>>.*/\1/p' <<<"$out" | tail -1)
    if [ "$val" = "$3" ]; then ok=$((ok+1)); printf '%-20s OK\n' "$1"
    else wrong=$((wrong+1)); printf '%-20s WRONG got=%s\n' "$1" "${val:-<none>}"; fi
  fi
}

# --- reaching forms: a `**` splat in a discarded hash/kw-hash literal ---
# CRuby ignores the discarded literal and returns [111, 222].
run_case splat_pair    '[**{}, k: 0]'          "[111, 222]"
run_case pair_splat    '[k: 0, **{}]'          "[111, 222]"
run_case two_splat     '[**{}, **{}]'          "[111, 222]"
run_case splat0_pair   '[**0, m: 0]'           "[111, 222]"
run_case pair_splat_pair '[a: 1, **{}, b: 2]'  "[111, 222]"
run_case splat_pairs   '[**{}, k: 0, j: 1]'    "[111, 222]"

# --- controls that do not change the stack pointer in gen_hash ---
# bare `**` with no following pair, no splat at all: no pop/push, so no
# corruption; the discarded literal is ignored and the sentinel is correct.
run_case bare_splat    '[**{}]'                "[111, 222]"
run_case bare_splat0   '[**0]'                 "[111, 222]"
run_case pair_only     '[k: 0, j: 1]'          "[111, 222]"
run_case nohash        '[1, 2]'                "[111, 222]"

# --- value-context controls: the same `**` forms with the value kept
#     (gen_hash is called with val == 1); the fix only adds `val &&` guards,
#     so these paths are unchanged and correct on every build. ---
run_case val_arr_splat 'z = [**{c: 9}, k: 0]; raise "x" unless z == [{c: 9, k: 0}]' "[111, 222]"
run_case val_hash_splat 'h = {**{c: 9}, k: 0}; raise "x" unless h == {c: 9, k: 0}'  "[111, 222]"

# --- the dataset PoC. On the base build the discarded `[**0, m: 0]` corrupts
#     the stack so the following `def c.e` emits OP_SCLASS on an object with a
#     NULL class pointer (SEGV in prepare_singleton_class). The PoC's `c` is
#     `{0=>0,nil=>nil}[0]`, the Integer 0, so CRuby raises "can't define
#     singleton (TypeError)" at `def c.e`; the developer patch (NULL-class
#     guard) and the root-cause patch (no corruption, c == 0) both reach that
#     same TypeError, which equals CRuby. The PoC therefore does not separate
#     the developer patch from the root-cause patch; the synthetic cases above
#     do. Expected class: CRuby raises the TypeError, so OK is a clean
#     "can't define singleton". Skipped under the CRuby oracle run (the
#     oracle validates the synthetic values). ---
if [ "$MRUBY" != ruby ] && [ -f /testcase/poc ]; then
  out=$("$MRUBY" /testcase/poc 2>&1)
  total=$((total+1))
  if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then
    asan=$((asan+1)); printf '%-20s %s\n' poc "ASAN $(grep -m1 -o 'SEGV\|AddressSanitizer: [A-Za-z-]*' <<<"$out" | head -1) prepare_singleton_class"
  elif grep -q 'STACK-INVARIANT' <<<"$out"; then
    inv=$((inv+1)); printf '%-20s %s\n' poc "$(grep -m1 -o 'STACK-INVARIANT[^"]*' <<<"$out")"
  elif grep -q "can't define singleton" <<<"$out"; then
    # matches CRuby (TypeError on `def 0.e`): dev patch and root-cause patch.
    ok=$((ok+1)); printf '%-20s OK\n' poc
  else
    wrong=$((wrong+1)); printf '%-20s WRONG got=%s\n' poc "$(tail -1 <<<"$out")"
  fi
fi

echo "summary: $ok OK, $wrong WRONG, $asan ASAN, $inv INV of $total"
rm -rf "$D"
