#!/bin/bash
# Builds one patch variant of mruby.cve-2022-0717 in a fresh container and
# records the build, the PoC, the index-assignment cases
# (scripts/arypush_cases.tsv run by scripts/arypush_run_cases.sh against the
# CRuby values of scripts/arypush_expected.tsv), the compiler output digest
# (scripts/mrbc_digest.sh) and, unless --no-tests is given, mruby's
# regression tests (scripts/run_tests.sh). Copy of scripts/run_variant.sh
# with the case runner, the ARYPUSH-INVARIANT marker, SECB_DOCKER_OPTS and
# this header changed.
#
# Usage: arypush_run_variant.sh [--no-tests] <image> <outdir> <name> <description> [<diff>...]
#
# Several diffs are applied in the order given, e.g. the developer patch
# followed by an instrumentation diff. Writes
# <outdir>/<name>.{diff,build.log,poc.log,cases.log,digest.log,tests.log},
# where <name>.diff is the resulting `git diff` against the base commit, and
# appends a one-line summary to <outdir>.log. A crash is judged by the
# presence of a sanitizer report, not by exit status.
#
# Extra `docker run` options come from SECB_DOCKER_OPTS (default empty).
set -eu
tests=1
if [ "$1" = "--no-tests" ]; then tests=0; shift; fi
image=$1 outdir=$2 name=$3 desc=$4; shift 4
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$outdir"
out=$outdir/$name
opts=${SECB_DOCKER_OPTS:-}
echo "SECB_DOCKER_OPTS=$opts"

# secb-<project>-<cve number>-<role>, e.g. secb-mruby-0717-after
inst=${image##*.x86_64.}; cve=${inst##*-}
c=secb-mruby-$cve-$name
docker run -d --name "$c" --platform linux/amd64 $opts "$image" sleep infinity >/dev/null
trap 'docker rm -f "$c" >/dev/null' EXIT
docker exec "$c" mkdir -p /tmp/scripts
for s in run_tests.sh mrbc_digest.sh arypush_run_cases.sh arypush_cases.tsv arypush_expected.tsv; do
  docker cp "$here/$s" "$c:/tmp/scripts/$s"
done
i=0
for diff in "$@"; do
  i=$((i+1))
  docker cp "$diff" "$c:/tmp/variant$i.diff"
  docker exec "$c" git -C /src/mruby apply "/tmp/variant$i.diff"
done
docker exec "$c" git -C /src/mruby diff > "$out.diff"

docker exec "$c" secb build > "$out.build.log" 2>&1 || true
if ! grep -q 'BUILD COMPLETED SUCCESSFULLY' "$out.build.log"; then
  printf '%s | %s | build=FAIL\n' "$name" "$desc" >> "$outdir.log"
  exit 0
fi

docker exec "$c" secb repro > "$out.poc.log" 2>&1 || true
if grep -q 'ERROR: AddressSanitizer' "$out.poc.log"; then poc=crash
elif grep -q 'ARYPUSH-INVARIANT' "$out.poc.log"; then poc=invariant
else poc=no-crash; fi

docker exec "$c" bash /tmp/scripts/arypush_run_cases.sh /src/mruby/bin/mruby \
  /tmp/scripts/arypush_cases.tsv /tmp/scripts/arypush_expected.tsv > "$out.cases.log" 2>&1 || true
cases=$(tail -1 "$out.cases.log" | sed 's/^summary: //')

docker exec "$c" bash /tmp/scripts/mrbc_digest.sh /src/mruby/bin/mrbc > "$out.digest.log" 2>&1 || true
digest=$(shasum -a 256 < "$out.digest.log" | cut -c1-12)

if [ $tests = 1 ]; then
  docker exec "$c" bash /tmp/scripts/run_tests.sh > "$out.tests.log" 2>&1 || true
  t=$(grep -E '^ +(OK|KO|Crash|Skip):|rake test exit' "$out.tests.log" | tr -s ' ' | paste -sd' ' -)
else
  t="not run"
fi

printf '%s | %s | build=OK | poc=%s | cases: %s | digest=%s | tests: %s\n' \
  "$name" "$desc" "$poc" "$cases" "$digest" "$t" >> "$outdir.log"
