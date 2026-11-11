#!/bin/bash
# Runs the case table of mruby.cve-2018-12249 (scripts/classreal_cases.tsv,
# printed by scripts/classreal_cases.py) with one interpreter and classifies
# every case.
#
# Usage (inside the instance container):
#   classreal_run_cases.sh ruby <cases.tsv>                  # reference values
#   classreal_run_cases.sh <mruby binary> <cases.tsv> <expected.tsv>
#
# With `ruby` (the image's CRuby 2.7.0) it prints `<name><TAB><value>` for
# every case, the expected values of scripts/classreal_expected.tsv; rows whose
# program starts with `@` (a file such as /testcase/poc.rb) get the
# value `*` (judged by the sanitizer report only).
#
# Otherwise it prints one line per case and a summary line. Result class:
# ASAN (an AddressSanitizer or LeakSanitizer report), INV (an
# CLASSREAL-INVARIANT compile error from the assertion variant), OK (the
# printed value equals the CRuby value, or no sanitizer report for a `*`
# row) or WRONG (got=<value>). An ASAN line gives the report class and the
# function of frame #0. A crash is judged by the sanitizer report, never by
# exit status. Each case runs in its own process.
set -u
BIN=$1 CASES=$2 EXP=${3:-}
D=$(mktemp -d)
ok=0; wrong=0; asan=0; inv=0; total=0

value() { sed -n 's/.*<<\(.*\)>>.*/\1/p' <<<"$1" | tail -1; }

while IFS=$'\t' read -r name family program; do
  [ -z "$name" ] && continue
  if [ "${program:0:1}" = "@" ]; then f=${program:1}
  else f=$D/$name.rb; printf '%s\n' "$program" > "$f"; fi
  if [ "$BIN" = ruby ]; then
    if [ "${program:0:1}" = "@" ]; then printf '%s\t*\n' "$name"
    else printf '%s\t%s\n' "$name" "$(value "$(ruby "$f" 2>/dev/null)")"; fi
    continue
  fi
  out=$("$BIN" "$f" 2>&1)
  total=$((total+1))
  exp=$(awk -F'\t' -v n="$name" '$1 == n {print $2; exit}' "$EXP")
  if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then
    asan=$((asan+1))
    printf '%-14s ASAN %s in %s\n' "$name" \
      "$(sed -n 's/.*ERROR: AddressSanitizer: \([A-Za-z-]*\).*/\1/p' <<<"$out" | head -1)" \
      "$(sed -n 's/^ *#0 0x[0-9a-f]* in \([^ ]*\).*/\1/p' <<<"$out" | head -1)"
  elif grep -q 'ERROR: LeakSanitizer' <<<"$out"; then
    asan=$((asan+1)); printf '%-14s ASAN LeakSanitizer: detected memory leaks\n' "$name"
  elif grep -q 'CLASSREAL-INVARIANT' <<<"$out"; then
    inv=$((inv+1)); printf '%-14s %s\n' "$name" "$(grep -m1 -o 'CLASSREAL-INVARIANT[^"]*' <<<"$out")"
  elif [ "$exp" = "*" ]; then
    ok=$((ok+1)); printf '%-14s OK\n' "$name"
  else
    got=$(value "$out")
    if [ -n "$exp" ] && [ "$got" = "$exp" ]; then ok=$((ok+1)); printf '%-14s OK\n' "$name"
    else wrong=$((wrong+1)); printf '%-14s WRONG got=%s\n' "$name" "${got:-<none>}"; fi
  fi
done < "$CASES"

[ "$BIN" = ruby ] || echo "summary: $ok OK, $wrong WRONG, $asan ASAN, $inv INV of $total"
rm -rf "$D"
