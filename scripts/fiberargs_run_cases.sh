#!/bin/bash
# Runs the case table of mruby.cve-2018-12248 (scripts/fiberargs_cases.tsv, printed
# by scripts/fiberargs_cases.py) with one interpreter and classifies every case.
#
# Usage (inside the instance container):
#   fiberargs_run_cases.sh ruby <cases.tsv>                  # reference values
#   fiberargs_run_cases.sh <mruby binary> <cases.tsv> <expected.tsv>
#
# With `ruby` (the image's CRuby 2.7.0) it prints `<name><TAB><value>` for every
# case, the expected values of scripts/fiberargs_expected.tsv; rows whose program
# starts with `@` (the dataset PoC /testcase/poc.rb) get the value `*` (judged by
# the sanitizer report only).
#
# Otherwise it prints one line per case and a summary line. Result class: ASAN
# (an AddressSanitizer or LeakSanitizer report), INV (a FIBERARGS-INVARIANT abort
# from the assertion variant), TIMEOUT (the case exceeded the per-case limit), OK
# (the printed value equals the CRuby value, or no sanitizer report for a `*` row)
# or WRONG (got=<value>). A crash is judged by the sanitizer report, never by exit
# status. Each case runs in its own process under a per-case timeout (the w family
# builds a 300000-element array and can be slow under emulation).
#
# Copy of scripts/classreal_run_cases.sh with the FIBERARGS-INVARIANT marker, the
# per-case timeout, a TIMEOUT class, a wider name column, and this header.
set -u
BIN=$1 CASES=$2 EXP=${3:-}
LIMIT=${CASE_TIMEOUT:-180}
D=$(mktemp -d)
ok=0; wrong=0; asan=0; inv=0; timeout_n=0; total=0

value() { sed -n 's/.*<<\(.*\)>>.*/\1/p' <<<"$1" | tail -1; }

while IFS=$'\t' read -r name family program; do
  [ -z "$name" ] && continue
  if [ "${program:0:1}" = "@" ]; then f=${program:1}
  else f=$D/$name.rb; printf '%s\n' "$program" > "$f"; fi
  if [ "$BIN" = ruby ]; then
    if [ "${program:0:1}" = "@" ]; then printf '%s\t*\n' "$name"
    else printf '%s\t%s\n' "$name" "$(value "$(timeout "$LIMIT" ruby "$f" 2>/dev/null)")"; fi
    continue
  fi
  out=$(timeout "$LIMIT" "$BIN" "$f" 2>&1); rc=$?
  total=$((total+1))
  exp=$(awk -F'\t' -v n="$name" '$1 == n {print $2; exit}' "$EXP")
  if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then
    asan=$((asan+1))
    printf '%-18s ASAN %s in %s\n' "$name" \
      "$(sed -n 's/.*ERROR: AddressSanitizer: \([A-Za-z-]*\).*/\1/p' <<<"$out" | head -1)" \
      "$(sed -n 's/^ *#0 0x[0-9a-f]* in \([^ ]*\).*/\1/p' <<<"$out" | head -1)"
  elif grep -q 'ERROR: LeakSanitizer' <<<"$out"; then
    asan=$((asan+1)); printf '%-18s ASAN LeakSanitizer: detected memory leaks\n' "$name"
  elif grep -q 'FIBERARGS-INVARIANT' <<<"$out"; then
    inv=$((inv+1)); printf '%-18s %s\n' "$name" "$(grep -m1 -o 'FIBERARGS-INVARIANT[^"]*' <<<"$out")"
  elif [ "$rc" = 124 ]; then
    timeout_n=$((timeout_n+1)); printf '%-18s TIMEOUT (%ss)\n' "$name" "$LIMIT"
  elif [ "$exp" = "*" ]; then
    ok=$((ok+1)); printf '%-18s OK\n' "$name"
  else
    got=$(value "$out")
    if [ -n "$exp" ] && [ "$got" = "$exp" ]; then ok=$((ok+1)); printf '%-18s OK\n' "$name"
    else wrong=$((wrong+1)); printf '%-18s WRONG got=%s\n' "$name" "${got:-<none>}"; fi
  fi
done < "$CASES"

[ "$BIN" = ruby ] || echo "summary: $ok OK, $wrong WRONG, $asan ASAN, $inv INV, $timeout_n TIMEOUT of $total"
rm -rf "$D"
