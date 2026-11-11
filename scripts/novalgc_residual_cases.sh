#!/bin/bash
# Deep-frame crash probes for mruby.cve-2022-0326, in the exact structure of
# the dataset PoC (a `1.times` block containing a string interpolation with a
# hash local `b={}`, the discarded `**`-splat hash literal, and a trailing
# assignment). This is the structure in which the NOVAL gen_hash stack
# underflow overwrites a live local register and the shutdown garbage collector
# faults (SEGV in iv_free / mrb_gc_free_iv / obj_free). The blind second
# reading (phase 2) found that after the developer patch a K/C-branch form
# ([m:0,**0], a pair before the `**`) in this frame still reaches the identical
# shutdown SEGV, while the main case set (run_case wrapper and nested blocks
# without the interpolation) showed only a wrong result. These probes record
# the symptom class of the K/C leftover in the crash frame.
#
# Usage (inside the instance container): novalgc_residual_cases.sh <mruby binary>
# Skipped under the CRuby oracle (CRuby 2.7 rejects a bare `**0` literal).
#
# Result class per probe: ASAN (sanitizer report), INV (STACK-INVARIANT marker
# from the assertion variant), or OK (clean run, the correct no-op behaviour of
# a discarded literal). A crash is judged by the sanitizer report, never by
# exit status.
set -u
MRUBY=$1
[ "$MRUBY" = ruby ] && { echo "summary: skipped under CRuby oracle"; exit 0; }
D=$(mktemp -d)
ok=0; asan=0; inv=0; total=0

probe() { # name, program
  local f=$D/$1.rb out; printf '%s\n' "$2" > "$f"
  out=$("$MRUBY" "$f" 2>&1)
  total=$((total+1))
  if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then
    asan=$((asan+1)); printf '%-18s ASAN %s\n' "$1" "$(grep -m1 -o 'SEGV\|heap-buffer-overflow' <<<"$out" | head -1) $(grep -m1 -o 'iv_free\|obj_free' <<<"$out" | head -1)"
  elif grep -q 'STACK-INVARIANT' <<<"$out"; then
    inv=$((inv+1)); printf '%-18s %s\n' "$1" "$(grep -m1 -o 'STACK-INVARIANT[^"]*' <<<"$out")"
  else
    ok=$((ok+1)); printf '%-18s OK\n' "$1"
  fi
}

# F branch (a `**` splat before a pair): the dataset PoC form. Guarded by the
# developer patch, so OK after; the reader's minimal crasher on the base.
probe f_deep      '1.times{ "#{b={};[**0,m:0];s=0}" }'
# K branch + C branch (a pair before a `**`): left unguarded by the developer
# patch. The second reading reports this reaches the same shutdown SEGV AFTER
# the patch (the B1 check: a sanitizer report of the same faulty state remains).
probe kc_deep     '1.times{ "#{b={};[m:0,**0];s=0}" }'
# C branch (two `**` splats): left unguarded; the reader reports a one-slot
# underflow (a wrong result / controlled error, not a shutdown SEGV).
probe ts_deep     '1.times{ "#{b={};[**0,**1];s=0}" }'
# K, C and F (a pair, a `**`, a pair): left unguarded at K and C.
probe kcf_deep    '1.times{ "#{b={};[a:1,**0,b:2];s=0}" }'
# control: the same frame with no `**` splat; no stack move, clean on every build.
probe nosplat_deep '1.times{ "#{b={};[m:0];s=0}" }'

echo "summary: $ok OK, $asan ASAN, $inv INV of $total"
rm -rf "$D"
