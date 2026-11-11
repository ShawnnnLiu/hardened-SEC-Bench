#!/bin/bash
# Runs the violating cases of scripts/negfrom_cases.py that printed the
# reference value on the base build (latent cases, the violating cases that
# are OK in variants/before.cases.log) once with each of several heap
# states, to show that their class depends on the memory around the string
# and not on the case (njs.cve-2022-31307).
# A heap state is a prefix that allocates K strings of 1 to 97 characters
# before the case's own statements; K = 0 is the case unchanged, but the
# file name differs from the one of the variant run, which changes the
# memory layout as well.
#
# Usage: negfrom_latent.sh <running container with the base build> <before.cases.log> [K...]
#   default K: 0 1 7 50 400
# Prints one line per run: <case> k=<K> OK|ASAN [<program counter of the report>],
# then a summary. Each run is one njs process.
set -eu
c=$1 log=$2; shift 2
ks=${*:-0 1 7 50 400}
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
python3 -B "$here/negfrom_cases.py" "$work/cases" > /dev/null
# violating cases (viol = 1 in cases.tsv) whose result in the variant log is OK
latent=$(awk -F'\t' 'NR==FNR { if ($7 == "1") v[$1] = 1; next } ($1 in v) && $2 == "OK" { print $1 }' \
  "$work/cases/cases.tsv" <(awk '/^[A-Za-z_0-9]+ +(OK|WRONG|ASAN)/ { print $1 "\t" $2 }' "$log"))
mkdir -p "$work/run"
for name in $latent; do
  for k in $ks; do
    if [ "$k" = 0 ]; then pre=""; else
      pre="var junk = []; for (var i = 0; i < $k; i++) junk.push('x'.repeat(i % 97 + 1));"; fi
    { [ -n "$pre" ] && echo "$pre"; cat "$work/cases/$name.js"; } > "$work/run/${name}__k$k.js"
  done
done
echo "--- container $c, binary /src/njs/build/njs, HEAD $(docker exec "$c" git -C /src/njs rev-parse HEAD)"
echo "--- latent cases: $(echo $latent | wc -w | tr -d ' '); heap states K: $ks"
docker exec "$c" rm -rf /tmp/latent
docker exec "$c" mkdir -p /tmp/latent
docker cp "$work/run/." "$c:/tmp/latent/"
docker exec "$c" bash -c 'cd /tmp/latent && for f in *.js; do
  out=$(/src/njs/build/njs $f 2>&1)
  n=${f%.js}
  if echo "$out" | grep -q "ERROR: AddressSanitizer"; then
    pc=$(echo "$out" | grep -m1 "ERROR: Addr" | sed "s/.*(pc \(0x[0-9a-f]*\).*/\1/")
    echo "${n%%__k*} k=${n##*__k} ASAN pc=$pc"
  else
    echo "${n%%__k*} k=${n##*__k} OK"
  fi
done' | sort > "$work/out.txt"
cat "$work/out.txt"
echo "summary: $(awk '{n++} $3 == "ASAN" {a++} END {print n+0 " runs; " a+0 " ASAN"}' "$work/out.txt"); \
cases with at least one ASAN: $(awk '$3 == "ASAN" {print $1}' "$work/out.txt" | sort -u | wc -l | tr -d ' ') of $(echo $latent | wc -w | tr -d ' ')"
for k in $ks; do
  echo "summary k=$k: $(awk -v k="k=$k" '$2 == k {n++} $2 == k && $3 == "ASAN" {a++} END {print n+0 " runs; " a+0 " ASAN"}' "$work/out.txt")"
done
