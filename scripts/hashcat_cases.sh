#!/bin/bash
# Non-hash and operand-as-accumulator at OP_HASHCAT (mruby.cve-2022-0630,
# developer patch = OP_HASHCAT hunk of ee06bbb4). This is the OP_HASHCAT
# sibling of the OP_HASHADD bug of mruby.cve-2022-0614/0623 (shared developer
# patch ff3a5ebed); the 0614 rows (hint..cplain) are kept unchanged as the
# OP_HASHADD family and the value controls.
#
# Root cause (gen_hash, mrbgems/mruby-compiler/core/codegen.c): a hash or array
# literal whose FIRST element is a double-splat (NODE_KW_REST_ARGS) gets no
# OP_HASH; gen_hash reuses the splat operand's own register as the accumulator.
# A second splat then emits OP_HASHCAT regs[a] on that operand register:
#   [**0, **8]  -> LOADI R(0) ; (operand 8) ; HASHCAT R  -> mrb_hash_merge(0, 8)
# mrb_hash_merge calls hash_modify(hash1=regs[a]) first; for a non-hash operand
# hash_modify -> mrb_check_frozen reads a bad pointer (SEGV at a small address),
# the reported crash. The merge source regs[a+1] is already type-checked by
# mrb_ensure_hash_type in mrb_hash_merge. The developer patch inserts
# mrb_ensure_hash_type(mrb, regs[a]) in the OP_HASHCAT handler before
# mrb_hash_merge, so a non-hash accumulator raises TypeError (OK after).
#
# When the first splat operand is a hash variable, the accumulator ALIASES it,
# so {**h, **{b:2}} mutates h (OP_HASHCAT) just as {**h, b:2} mutates h
# (OP_HASHADD). A single leading splat {**1} with no following op leaves the
# operand itself as the literal's value (wrong result). Neither is fixed by the
# OP_HASHCAT type check; upstream 12d51807a fixes all of them by emitting an
# empty OP_HASH accumulator before the first splat (gen_hash).
#
# Usage (inside a variant container): hashcat_cases.sh <mruby binary>
# Passing `ruby` runs only the value cases on the image's CRuby 2.7 and records
# the reference values (the crasher cases raise exceptions on CRuby and are
# skipped there).
#
# Result class per case: ASAN (sanitizer report), INV (a HASHCAT-INVARIANT
# marker from the assertion variant), OK, or WRONG. A crash is judged by the
# sanitizer report, never by exit status. For a crasher case OK means no
# sanitizer report (a controlled Ruby exception); for a value case OK means the
# printed value equals the CRuby reference.
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
  elif grep -q 'HASHCAT-INVARIANT' <<<"$out"; then
    inv=$((inv+1)); printf '%-14s %s\n' "$name" "$(grep -m1 -o 'HASHCAT-INVARIANT[^"]*' <<<"$out")"
  else
    ok=$((ok+1)); printf '%-14s OK\n' "$name"
  fi
}

# A crasher with no value: OK = no sanitizer report. Skipped under the CRuby
# oracle (these raise exceptions, not values).
sym_case() { # name, program
  [ $is_ruby = 1 ] && return
  local f=$D/$1.rb out; printf '%s\n' "$2" > "$f"
  out=$("$MRUBY" "$f" 2>&1)
  classify "$1" "$out"
}

# A value case: must print the expected sentinel (equal to CRuby) on every
# build. Runs on CRuby too (the begin/rescue forms produce a sentinel there).
val_case() { # name, program, expected
  local f=$D/$1.rb out val; printf '%s\n' "$2" > "$f"
  out=$("$MRUBY" "$f" 2>&1); total=$((total+1))
  if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then
    asan=$((asan+1)); printf '%-14s ASAN\n' "$1"
  elif grep -q 'HASHCAT-INVARIANT' <<<"$out"; then
    inv=$((inv+1)); printf '%-14s HASHCAT-INVARIANT\n' "$1"
  else
    val=$(sed -n 's/.*<<\(.*\)>>.*/\1/p' <<<"$out" | tail -1)
    if [ "$val" = "$3" ]; then ok=$((ok+1)); printf '%-14s OK\n' "$1"
    else wrong=$((wrong+1)); printf '%-14s WRONG got=%s\n' "$1" "${val:-<none>}"; fi
  fi
}

# ============================================================================
# Kept mruby.cve-2022-0614/0623 rows: OP_HASHADD non-hash crashers (leading
# double-splat of a non-hash with a trailing PAIR). The 0630 developer patch
# does NOT touch OP_HASHADD, so these are expected to stay ASAN after it (the
# cross-CVE leftover, fixed by the 0614 developer patch or by 12d51807a).
# ============================================================================
sym_case hint     'x={**0,m:0}'      # Integer splat
sym_case hfloat   'x={**1.5,m:0}'    # Float splat
sym_case hsym     'x={**:z,m:0}'     # Symbol splat
sym_case hint_arr 'x=[**0,m:0]'      # array-wrapped trailing hash
sym_case hstr     'x={**"abc",m:0}'  # String splat (a heap object)

# Boundary (trailing splat -> OP_HASHCAT with a real-hash accumulator; the
# non-hash merge source raises TypeError; {**0} alone has no second op)
sym_case hcat     'x={m:0,**0}'      # OP_HASHCAT accumulator is a real hash
sym_case hsplat   'x={**0}'          # single splat, no crash (value is the operand)

# Value controls at OP_HASHADD (regs[a] is a real hash); must keep the value
val_case cvalid   'h={**{a:1},m:0}; print "<<#{h[:a]},#{h[:m]},#{h.size}>>"'       "1,0,2"
val_case ckw      'h={m:0}; print "<<#{h[:m]},#{h.size}>>"'                         "0,1"
val_case cmerge   'g={x:1}; h={**g,m:2}; print "<<#{h[:x]},#{h[:m]},#{h.size}>>"'   "1,2,2"
val_case cplain   'h={a:1,b:2}; print "<<#{h[:a]},#{h[:b]},#{h.size}>>"'            "1,2,2"

# ============================================================================
# New OP_HASHCAT non-hash accumulator crashers (two leading splats, first a
# non-hash). The developer patch turns these into TypeError (OK after). On
# assert_before they fire HASHCAT-INVARIANT (INV).
# ============================================================================
sym_case kc2int   'x=[**0,**8]'          # the PoC construct: two Integer splats
sym_case kc2hash  'x=[**0,**{a:1}]'      # non-hash accumulator, HASH merge source
sym_case kc2nil   'x={**nil,**{a:1}}'    # nil accumulator
sym_case kc2str   'x={**"s",**{a:1}}'    # String accumulator (heap object)
sym_case kc2call  'def m(**k);k;end; m(**0,**{a:1})'   # method-call kwargs
sym_case kc23     'x={**0,**8,**9}'      # three splats

# ============================================================================
# OP_HASHCAT aliasing: hash first operand + a second splat mutates the operand.
# A wrong result (no sanitizer report); the developer patch does not fix it.
# ============================================================================
val_case kalias   'h={a:1}; x={**h,**{b:2}}; print "<<#{h.size}|#{x.size}>>"'       "1|2"
val_case kaliasarr 'h={a:1}; x=[**h,**{b:2}]; print "<<#{h.size}|#{x.class}>>"'      "1|Array"
val_case kafroz   'h={a:1}.freeze; begin; x={**h,**{b:2}}; print "<<#{h.size}|#{x.size}>>"; rescue=>e; print "<<E:#{e.class}>>"; end'   "1|2"

# ============================================================================
# Single leading non-hash splat alone: the literal's value is the operand
# (wrong result) instead of a conversion / error. Only k1nil is a clean
# divergence against the CRuby 2.7 oracle; {**1} returns the operand on CRuby
# 2.7 too (not TypeError) and [**1] segfaults CRuby 2.7 itself, so those two
# forms the lane lists give no usable oracle and are dropped (see note).
# ============================================================================
val_case k1nil    'begin; x={**nil}; print "<<V:#{x.inspect}>>"; rescue=>e; print "<<E:#{e.class}>>"; end' "E:TypeError"

# ============================================================================
# OP_HASHADD aliasing cross-CVE control (hash first operand + a PAIR): same
# gen_hash defect, manifests via OP_HASHADD (the 0614/0623 wrong-result form).
# ============================================================================
val_case kpalias  'h={a:1}; x={**h,b:2}; print "<<#{h.size}|#{x.size}>>"'           "1|2"

# ============================================================================
# Controls that must stay correct on every build (a pair precedes the splat, so
# OP_HASH builds a fresh accumulator; Hash#merge does not alias).
# ============================================================================
val_case kcpair   'h={a:1}; x={k:9,**h}; print "<<#{h.size}|#{x.size}>>"'           "1|2"
val_case kmerge   'h={a:1}; x=h.merge(b:2); print "<<#{h.size}|#{x.size}>>"'         "1|2"

# ============================================================================
# The dataset PoC (/testcase/poc1; a fuzzer input containing [**0,**8,m:0])
# ============================================================================
if [ $is_ruby = 0 ] && [ -f /testcase/poc1 ]; then
  out=$("$MRUBY" /testcase/poc1 2>&1)
  classify poc "$out"
fi

echo "summary: $ok OK, $wrong WRONG, $asan ASAN, $inv INV of $total"
rm -rf "$D"
