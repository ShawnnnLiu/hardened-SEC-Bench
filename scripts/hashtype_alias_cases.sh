#!/bin/bash
# Residual aliasing cases for mruby.cve-2022-0614 / mruby.cve-2022-0623.
# These share the codegen root cause of the reported crash but a different
# symptom class (a wrong result, not a sanitizer report), and the developer
# patch (a runtime type check at OP_HASHADD) does not fix them.
#
# gen_hash (mrbgems/mruby-compiler/core/codegen.c, base) builds a hash literal
# whose first entry is a double-splat (NODE_KW_REST_ARGS) with no preceding
# pair by using the splat operand's own register as the accumulator: it emits
# no OP_HASH to create a fresh hash and then appends trailing pairs with
# OP_HASHADD onto the operand. When the operand is a non-hash this is the
# reported crash; when the operand IS a hash, the accumulator aliases the
# source hash, so {**h, k:v} mutates h in place. CRuby builds a copy and leaves
# h unchanged. At origin/master the first splat emits `OP_HASH cursp(),0` (a
# fresh accumulator) then OP_HASHCAT, which fixes both the crash and the
# aliasing; the developer patch here fixes only the crash.
#
# Usage: hashtype_alias_cases.sh <mruby-or-ruby binary>
# OK  = matches the CRuby 2.7 reference (the source hash is NOT mutated).
# WRONG = the source hash was mutated (the aliasing defect).
set -u
BIN=$1
D=$(mktemp -d)
ok=0; wrong=0; asan=0; total=0

alias_case() { # name, program-printing-<<...>> , expected
  local f=$D/$1.rb out val; printf '%s\n' "$2" > "$f"
  out=$("$BIN" "$f" 2>&1); total=$((total+1))
  if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then
    asan=$((asan+1)); printf '%-14s ASAN\n' "$1"
  else
    val=$(sed -n 's/.*<<\(.*\)>>.*/\1/p' <<<"$out" | tail -1)
    if [ "$val" = "$3" ]; then ok=$((ok+1)); printf '%-14s OK (source unchanged: %s)\n' "$1" "$val"
    else wrong=$((wrong+1)); printf '%-14s WRONG got=%s expected=%s (source hash mutated)\n' "$1" "${val:-<none>}" "$3"; fi
  fi
}

# {**h, k:v}: with a trailing pair. CRuby leaves h == {a:1}; the aliasing
# mutates h to {a:1,b:2}, so h.key?(:b) becomes true.
alias_case alias_pair  'h={a:1}; x={**h,b:2}; print "<<#{h.key?(:b)}>>"'          "false"
# {**h} then mutate the result: CRuby copies, so x[:b]=2 does not touch h; the
# aliasing makes x the same object as h, so h gains :b.
alias_case alias_only  'h={a:1}; x={**h}; x[:b]=2; print "<<#{h.key?(:b)}>>"'     "false"
# the result value is itself correct on both (the wrong result is the side
# effect on the source), shown for context.
alias_case result_ok   'h={a:1}; x={**h,b:2}; print "<<#{x[:a]},#{x[:b]}>>"'      "1,2"

echo "summary: $ok OK, $wrong WRONG, $asan ASAN of $total"
rm -rf "$D"
