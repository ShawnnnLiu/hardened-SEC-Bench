#!/bin/bash
# Residual value-context defect of gen_hash() found while stress testing
# mruby.cve-2022-0240. It is independent of the CVE crash (which is the
# value-less / NOVAL path) and is NOT in patches/mruby.cve-2022-0240.root.diff.
#
# In value context, a hash/keyword-hash literal whose FIRST element is a `**`
# splat does not create a fresh base hash: the literal aliases the splat
# source, and any following `key: value` pair is added into the source, so
# the source is mutated. gen_hash() at the base commit lacks
# the "insert an empty hash before the first NODE_KW_REST_ARGS" step that
# upstream 12d51807a (2022-02-18) added; the developer patch (src/class.c)
# does not touch the compiler, so it does not fix this either. The CVE
# root-cause patch adds `val &&` guards to the NOVAL stack-emitting branches
# only, so it leaves value-context behaviour unchanged. The defect is fixed
# at upstream master (the Prism gen_hash carries the 12d51807a empty-hash
# step).
#
# Usage (inside the instance container): nvalhash_residual_cases.sh <mruby binary>
# Passing `ruby` runs the reference interpreter (CRuby 2.7), which gives the
# expected values.
set -u
MRUBY=$1
D=$(mktemp -d)
ok=0; wrong=0; total=0

run() { # name, body, expected
  local f=$D/$1.rb out val
  { printf 'def t\n'; printf '  %s\n' "$2"; printf 'end\n'
    printf 'begin; print "<<" + t.inspect + ">>"; rescue => e; print "<<E:" + e.class.to_s + ">>"; end\n'
  } > "$f"
  out=$("$MRUBY" "$f" 2>&1)
  total=$((total+1))
  val=$(sed -n 's/.*<<\(.*\)>>.*/\1/p' <<<"$out" | tail -1)
  if [ "$val" = "$3" ]; then ok=$((ok+1)); printf '%-18s OK\n' "$1"
  else wrong=$((wrong+1)); printf '%-18s WRONG got=%s\n' "$1" "${val:-<none>}"; fi
}

# `**` splat first, then a pair: expected a fresh hash, source unchanged.
run alias_empty  'a = {}; h = {**a, k: 1}; [a, h, a.equal?(h)]'        "[{}, {:k=>1}, false]"
run alias_nonempty 'a = {x: 9}; h = {**a, k: 1}; [a, h, a.equal?(h)]'  "[{:x=>9}, {:x=>9, :k=>1}, false]"
# bare `**` splat first, no pair: expected a fresh copy, not an alias.
run bare         'a = {x: 9}; h = {**a}; [a, h, a.equal?(h)]'          "[{:x=>9}, {:x=>9}, false]"
# control: a pair precedes the splat, so a fresh base hash is established.
run pair_first   'a = {}; h = {k: 1, **a}; [a, h, a.equal?(h)]'        "[{}, {:k=>1}, false]"

echo "summary: $ok OK, $wrong WRONG of $total"
rm -rf "$D"
