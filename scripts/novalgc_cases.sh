#!/bin/bash
# Discarded hash / keyword-hash literals with a `**` splat
# (mruby.cve-2022-0326). The defect is in gen_hash()
# (mrbgems/mruby-compiler/core/codegen.c): when the hash value is discarded
# (val == 0, NOVAL), the function still emits OP_HASH / OP_HASHADD / OP_HASHCAT
# and the matching pop_n()/push() whenever a `**` splat (NODE_KW_REST_ARGS)
# makes `update` true with a pair present. Those pop/push calls move the
# compiler stack pointer although nothing was pushed for the discarded value,
# so every following instruction is emitted one or two registers too low and
# overwrites locals and temporaries. The symptom is layout dependent: a wrong
# result, a runtime TypeError (OP_HASHADD on a non-hash register), a
# compile-time "stack pointer underflow", or a SEGV. The dataset PoC of this
# instance reaches the SEGV at exit-time garbage collection (NULL dereference
# in iv_free <- mrb_gc_free_iv <- obj_free), because the corruption damages an
# object whose instance-variable table pointer is invalid when the heap is
# freed at mrb_close.
#
# gen_hash() at the base adb16fc6 moves the stack pointer for a discarded
# value in three branches:
#   K  the OP_HASH/OP_HASHADD flush of pending pairs before a `**`,
#   C  the OP_HASHCAT after a `**` when pairs were pending or an update happened,
#   F  the final OP_HASHADD of pairs after an update.
# The developer patch (b611c43a5) guards F only (len>0 -> val&&len>0) and
# deletes an unreachable `if (update) return -1;`. So after the patch the F
# forms (a `**` before a pair) are correct, while the K/C forms (a pair before
# a `**`, or two `**`) stay wrong; those K/C forms are fixed upstream by the
# separate commit ae3c99767.
#
# Usage (inside the instance container): novalgc_cases.sh <mruby binary>
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
# E:<class> so a TypeError is a value, not a crash. A sanitizer report that
# fires only at exit-time GC appears in the captured output and is classed
# ASAN even when the sentinel printed first.
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
    asan=$((asan+1)); printf '%-22s %s\n' "$1" "ASAN $(grep -m1 -o 'AddressSanitizer: [A-Za-z-]*\|SEGV' <<<"$out")"
  elif grep -q 'STACK-INVARIANT' <<<"$out"; then
    inv=$((inv+1)); printf '%-22s %s\n' "$1" "$(grep -m1 -o 'STACK-INVARIANT[^"]*' <<<"$out")"
  else
    val=$(sed -n 's/.*<<\(.*\)>>.*/\1/p' <<<"$out" | tail -1)
    if [ "$val" = "$3" ]; then ok=$((ok+1)); printf '%-22s OK\n' "$1"
    else wrong=$((wrong+1)); printf '%-22s WRONG got=%s\n' "$1" "${val:-<none>}"; fi
  fi
}

# --- reaching forms: a `**` splat in a discarded hash/kw-hash literal ---
# CRuby ignores the discarded literal and returns [111, 222].
# Branch taken (K/C/F) noted; F is guarded by the developer patch, K/C are not.
run_case splat_pair    '[**{}, k: 0]'          "[111, 222]"   # F
run_case pair_splat    '[k: 0, **{}]'          "[111, 222]"   # K C
run_case two_splat     '[**{}, **{}]'          "[111, 222]"   # C
run_case splat0_pair   '[**0, m: 0]'           "[111, 222]"   # F   (PoC form)
run_case pair_splat_pair '[a: 1, **{}, b: 2]'  "[111, 222]"   # K C F
run_case splat_pairs   '[**{}, k: 0, j: 1]'    "[111, 222]"   # F

# --- controls that do not change the stack pointer in gen_hash ---
run_case bare_splat    '[**{}]'                "[111, 222]"
run_case bare_splat0   '[**0]'                 "[111, 222]"
run_case pair_only     '[k: 0, j: 1]'          "[111, 222]"
run_case nohash        '[1, 2]'                "[111, 222]"

# --- value-context controls: the same `**` forms with the value kept
#     (gen_hash is called with val == 1); the fix only adds `val &&` guards,
#     so these paths are unchanged and correct on every build. ---
run_case val_arr_splat 'z = [**{c: 9}, k: 0]; raise "x" unless z == [{c: 9, k: 0}]' "[111, 222]"
run_case val_hash_splat 'h = {**{c: 9}, k: 0}; raise "x" unless h == {c: 9, k: 0}'  "[111, 222]"

# --- the PoC form (splat0_pair, F branch) in the surroundings of the dataset
#     PoC: top level, one block, two nested blocks, a loop left by break, and a
#     string interpolation, each followed by a hash local, and each with and
#     without an explicit GC.start. The dataset crash is at exit-time GC, so a
#     mid-program collection (GC.start) may bring the fault forward or change
#     its class. All of these take the F branch, which the developer patch
#     guards, so all are expected OK after the patch. Expected sentinel
#     [111, 222] on CRuby (the discarded literal is ignored). ---
# The splat0_pair literal is kept in discarded (val == 0, NOVAL) position in
# every surrounding by placing the hash local right after it, inside the
# surrounding: it is never the last expression of its block, so it is never
# compiled with val == 1. (A `**0` literal as a block's return value would
# raise a value-context TypeError unrelated to this defect; that is avoided.)
run_case sp_top       '[**0, m: 0]; h = {a: 1}'                              "[111, 222]"
run_case sp_top_gc    '[**0, m: 0]; h = {a: 1}; GC.start'                    "[111, 222]"
run_case sp_blk1      '1.times{ [**0, m: 0]; h = {a: 1} }'                   "[111, 222]"
run_case sp_blk1_gc   '1.times{ [**0, m: 0]; h = {a: 1} }; GC.start'         "[111, 222]"
run_case sp_blk2      '1.times{ 1.times{ [**0, m: 0]; h = {a: 1} } }'        "[111, 222]"
run_case sp_blk2_gc   '1.times{ 1.times{ [**0, m: 0]; h = {a: 1} } }; GC.start' "[111, 222]"
run_case sp_loop      'while true; [**0, m: 0]; h = {a: 1}; break; end'      "[111, 222]"
run_case sp_loop_gc   'while true; [**0, m: 0]; h = {a: 1}; break; end; GC.start' "[111, 222]"
run_case sp_str       's = "#{ [**0, m: 0]; h = {a: 1}; 0 }"'                "[111, 222]"
run_case sp_str_gc    's = "#{ [**0, m: 0]; h = {a: 1}; 0 }"; GC.start'      "[111, 222]"

# --- the K/C leftover forms (a pair before a `**`, two `**`, a pair-`**`-pair)
#     in the same crash-prone layout (two nested blocks, a hash local, an
#     explicit GC.start). These probe whether the forms the developer patch
#     leaves (K/C) can reach a sanitizer report, not only a wrong sentinel, in
#     the dataset PoC's surroundings; the result bears on whether the leftover
#     is a memory-safety defect. Written as case rows (no probe container). ---
run_case kc_ps_blk2   '1.times{ 1.times{ [k: 0, **{}]; h = {a: 1} } }; GC.start'       "[111, 222]"   # K C
run_case kc_ts_blk2   '1.times{ 1.times{ [**{}, **{}]; h = {a: 1} } }; GC.start'       "[111, 222]"   # C
run_case kc_psp_blk2  '1.times{ 1.times{ [a: 1, **{}, b: 2]; h = {a: 1} } }; GC.start' "[111, 222]"   # K C F

# --- the mruby.cve-2022-0240 PoC, run as a program on this base. adb16fc6
#     already contains the 0240 developer fix (31fa3304, the class.c NULL-class
#     guard), so the `def c.e` on the Integer 0 raises "can't define singleton
#     (TypeError)" (= CRuby) instead of the 0240 SEGV, even though the F-branch
#     corruption is still present at base. Skipped under the CRuby oracle run. ---
if [ "$MRUBY" != ruby ]; then
  f=$D/poc0240.rb
  printf '%s\n' '1.times{b={}; a=0; [**0,m:0]; c={0=>0,nil=>nil}[0]; def m()end; def c.e()end}' > "$f"
  out=$("$MRUBY" "$f" 2>&1)
  total=$((total+1))
  if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then
    asan=$((asan+1)); printf '%-22s %s\n' poc0240 "ASAN $(grep -m1 -o 'SEGV\|AddressSanitizer: [A-Za-z-]*' <<<"$out" | head -1)"
  elif grep -q 'STACK-INVARIANT' <<<"$out"; then
    inv=$((inv+1)); printf '%-22s %s\n' poc0240 "$(grep -m1 -o 'STACK-INVARIANT[^"]*' <<<"$out")"
  elif grep -q "can't define singleton" <<<"$out"; then
    ok=$((ok+1)); printf '%-22s OK\n' poc0240
  else
    wrong=$((wrong+1)); printf '%-22s WRONG got=%s\n' poc0240 "$(tail -1 <<<"$out")"
  fi
fi

# --- the dataset PoC of this instance. On the base build the discarded
#     `[**0, m: 0]` (splat0_pair, F branch) in its nested-block surroundings
#     corrupts the stack so that an object with an invalid instance-variable
#     table reaches the exit-time GC: SEGV in iv_free. CRuby 2.7 rejects the
#     PoC as a syntax error (it uses mruby-only syntax), so there is no CRuby
#     value to compare; the correct behaviour on mruby is a clean run with no
#     output (the discarded literals are no-ops). OK means no sanitizer report,
#     no STACK-INVARIANT and no Ruby-level error. Skipped under CRuby. ---
if [ "$MRUBY" != ruby ] && [ -f /testcase/poc ]; then
  out=$("$MRUBY" /testcase/poc 2>&1)
  total=$((total+1))
  if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then
    asan=$((asan+1)); printf '%-22s %s\n' poc "ASAN $(grep -m1 -o 'SEGV\|AddressSanitizer: [A-Za-z-]*' <<<"$out" | head -1) iv_free"
  elif grep -q 'STACK-INVARIANT' <<<"$out"; then
    inv=$((inv+1)); printf '%-22s %s\n' poc "$(grep -m1 -o 'STACK-INVARIANT[^"]*' <<<"$out")"
  elif grep -qiE 'error|exception' <<<"$out"; then
    wrong=$((wrong+1)); printf '%-22s WRONG got=%s\n' poc "$(tail -1 <<<"$out")"
  else
    ok=$((ok+1)); printf '%-22s OK\n' poc
  fi
fi

echo "summary: $ok OK, $wrong WRONG, $asan ASAN, $inv INV of $total"
rm -rf "$D"
