#!/bin/bash
# Non-hash reaching OP_HASHADD (mruby.cve-2022-0614 and mruby.cve-2022-0623,
# one shared developer patch ff3a5ebed). In mrb_vm_exec (src/vm.c) the OP_HASHADD
# handler does `hash = regs[a]; mrb_assert(mrb_hash_p(hash));` and then
# `for (...) mrb_hash_set(mrb, hash, regs[i], regs[i+1]);`. mrb_assert is
# compiled out in the release build, so when regs[a] is not a hash,
# mrb_hash_set operates on the non-hash object: hash_modify -> mrb_check_frozen
# reads the object header of a bad pointer (SEGV at a small address for an
# immediate value), or the hash-table path (h_set/ar_set/entry_deleted_p) reads
# the object's fields as a hash table. The compiler produces a non-hash in
# regs[a] for a hash or array literal whose first entry is a double-splat of a
# non-hash and which has at least one more pair: e.g. {**0, m:0} compiles to
# LOADI_0 R2 ; HASHADD R2 1, so R2 holds the Integer 0 (the **0 operand) and
# OP_HASHADD runs on it. The developer patch replaces the assert with
# mrb_ensure_hash_type(mrb, hash), which raises TypeError before mrb_hash_set.
#
# A trailing double-splat ({m:0, **0}) compiles to OP_HASHCAT, whose accumulator
# regs[a] is a real hash built by a preceding OP_HASH, so it is not this bug;
# OP_HASHCAT raises TypeError for a non-hash merge source and does not crash
# (cases hcat, hsplat below confirm the OP_HASHADD scope is the crash path).
#
# Usage (inside the instance container): hashtype_cases.sh <mruby binary>
# Passing `ruby` runs only the value controls on the image's CRuby, which
# validates their expected values (the crasher and boundary cases raise
# exceptions on CRuby and are skipped there).
#
# Result class per case: ASAN (sanitizer report), INV (a HASHADD-INVARIANT
# marker from the assertion variant), OK, or WRONG. A crash is judged by the
# sanitizer report, never by exit status. For a crasher or boundary case OK
# means no sanitizer report (a controlled Ruby exception); for a value control
# OK means the printed value equals the CRuby reference.
set -u
MRUBY=$1
D=$(mktemp -d)
ok=0; wrong=0; asan=0; inv=0; total=0
is_ruby=0; [ "$MRUBY" = ruby ] && is_ruby=1

classify() { # name, output
  local name=$1 out=$2
  total=$((total+1))
  if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then
    asan=$((asan+1)); printf '%-14s ASAN %s\n' "$name" "$(grep -m1 -oE 'heap-buffer-overflow|SEGV' <<<"$out")"
  elif grep -q 'HASHADD-INVARIANT' <<<"$out"; then
    inv=$((inv+1)); printf '%-14s %s\n' "$name" "$(grep -m1 -o 'HASHADD-INVARIANT[^"]*' <<<"$out")"
  else
    ok=$((ok+1)); printf '%-14s OK\n' "$name"
  fi
}

# A crasher / boundary with no value: OK = no sanitizer report. Skipped under
# the CRuby oracle (these raise exceptions, not values).
sym_case() { # name, program
  [ $is_ruby = 1 ] && return
  local f=$D/$1.rb out; printf '%s\n' "$2" > "$f"
  out=$("$MRUBY" "$f" 2>&1)
  classify "$1" "$out"
}

# A value control: must print the expected value (equal to CRuby) on every build.
val_case() { # name, program, expected
  local f=$D/$1.rb out val; printf '%s\n' "$2" > "$f"
  out=$("$MRUBY" "$f" 2>&1); total=$((total+1))
  if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then
    asan=$((asan+1)); printf '%-14s ASAN\n' "$1"
  elif grep -q 'HASHADD-INVARIANT' <<<"$out"; then
    inv=$((inv+1)); printf '%-14s HASHADD-INVARIANT\n' "$1"
  else
    val=$(sed -n 's/.*<<\(.*\)>>.*/\1/p' <<<"$out" | tail -1)
    if [ "$val" = "$3" ]; then ok=$((ok+1)); printf '%-14s OK\n' "$1"
    else wrong=$((wrong+1)); printf '%-14s WRONG got=%s\n' "$1" "${val:-<none>}"; fi
  fi
}

# --- crashers: a non-hash in regs[a] at OP_HASHADD (leading double-splat of a
#     non-hash, with a trailing pair) ---
sym_case hint     'x={**0,m:0}'      # Integer splat (the PoC construct type)
sym_case hfloat   'x={**1.5,m:0}'    # Float splat
sym_case hsym     'x={**:z,m:0}'     # Symbol splat
sym_case hint_arr 'x=[**0,m:0]'      # array-wrapped trailing hash, same bug
sym_case hstr     'x={**"abc",m:0}'  # String splat (a heap object, not an immediate)

# --- boundary: a trailing double-splat goes through OP_HASHCAT (accumulator is
#     a real hash); the non-hash merge raises TypeError, no crash ---
sym_case hcat     'x={m:0,**0}'      # OP_HASHCAT path, TypeError on base, no crash
sym_case hsplat   'x={**0}'          # double-splat only, no trailing pair, no crash

# --- value controls: regs[a] is a real hash at OP_HASHADD; must keep the value ---
val_case cvalid   'h={**{a:1},m:0}; print "<<#{h[:a]},#{h[:m]},#{h.size}>>"'   "1,0,2"
val_case ckw      'h={m:0}; print "<<#{h[:m]},#{h.size}>>"'                     "0,1"
val_case cmerge   'g={x:1}; h={**g,m:2}; print "<<#{h[:x]},#{h[:m]},#{h.size}>>"' "1,2,2"
val_case cplain   'h={a:1,b:2}; print "<<#{h[:a]},#{h[:b]},#{h.size}>>"'        "1,2,2"

# --- the dataset PoC (/testcase/poc; a fuzzer input containing [**0,m:0]) ---
if [ $is_ruby = 0 ] && [ -f /testcase/poc ]; then
  out=$("$MRUBY" /testcase/poc 2>&1)
  classify poc "$out"
fi

echo "summary: $ok OK, $wrong WRONG, $asan ASAN, $inv INV of $total"
rm -rf "$D"
