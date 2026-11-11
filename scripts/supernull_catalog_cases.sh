#!/bin/bash
# Runs the programs of the blind second reading of mruby.cve-2022-1201 (phase 3)
# on one interpreter and prints one tab-separated line per program:
#   <dir>/<name>  <class>  <detail>
# class: ASAN (sanitizer report; detail = function of frame 0 and fault address),
#        INV (a SUPER-INVARIANT marker from an instrumented build), TIMEOUT, or
#        OK (no sanitizer report; detail = value=<text printed between << and >>>,
#        exc=<exception class of the last output line>, or none).
# A crash is judged by the sanitizer report, never by exit status.
#
# Programs: the reader's case sets (own_inputs_copy, fr, cases .. cases6; 138
# programs), its probes (4) and its matrix (480), taken from
# logs/mruby.cve-2022-1201/second_reading/phase3/ and copied into the container.
#
# Expected results, written before the run on the root-cause build (the root
# patch merges the two re-derivation branches under one NULL + ICLASS check,
# which is equivalent in behaviour to the reader's variant F5; the base and
# developer columns repeat the reader's counts):
#   base:      63 ASAN of the 138 case-set programs, 192 ASAN of the 480 matrix programs
#   developer: 23 ASAN of 138, 96 ASAN of 480 (all through the prepended-class branch)
#   root:      0 ASAN of 138 and of 480; for each program the same class and detail
#              as the reader's F5 build (variants_cases.tsv, variants_matrix.tsv)
#
# Usage (inside the instance container):
#   supernull_catalog_cases.sh <mruby binary | ruby> <dir>...
set -u
BIN=$1; shift
echo "# binary: $BIN"
if [ -d /src/mruby/.git ]; then
  echo "# HEAD $(git -C /src/mruby rev-parse HEAD)"
  echo "# git diff --stat: $(git -C /src/mruby diff --stat | tail -n 1)"
fi
echo "# dirs: $*"
echo "# program	class	detail"
for d in "$@"; do
  for f in "$d"/*.rb; do
    [ -e "$f" ] || continue
    n=$(basename "$f" .rb); dn=$(basename "$d")
    out=$(timeout 60 "$BIN" "$f" 2>&1); rc=$?
    if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then
      frame=$(grep -m1 -E '^ *#0 ' <<<"$out" | sed -E 's/^ *#0 0x[0-9a-f]+ in ([^ ]+).*/\1/')
      addr=$(grep -m1 -o 'on unknown address 0x[0-9a-f]*' <<<"$out" | sed 's/on unknown address //')
      printf '%s/%s\tASAN\t%s %s\n' "$dn" "$n" "$frame" "$addr"
    elif grep -q 'SUPER-INVARIANT' <<<"$out"; then
      printf '%s/%s\tINV\t\n' "$dn" "$n"
    elif [ $rc -eq 124 ]; then
      printf '%s/%s\tTIMEOUT\t\n' "$dn" "$n"
    else
      val=$(sed -n 's/.*<<\(.*\)>>.*/\1/p' <<<"$out" | tail -n 1)
      if [ -n "$val" ]; then
        printf '%s/%s\tOK\tvalue=%s\n' "$dn" "$n" "$val"
      else
        exc=$(grep -v '^TRACE-BRANCH' <<<"$out" | tail -n 1 | sed -n 's/.*(\([A-Za-z0-9_:]*\))$/\1/p')
        if [ -n "$exc" ]; then printf '%s/%s\tOK\texc=%s\n' "$dn" "$n" "$exc"
        else printf '%s/%s\tOK\tnone\n' "$dn" "$n"; fi
      fi
    fi
  done
done
