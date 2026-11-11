#!/bin/bash
# Builds one patch variant of mruby.cve-2018-12248 in a fresh container and records
# the build, the PoC, the fiber-argument cases (scripts/fiberargs_cases.tsv run by
# scripts/fiberargs_run_cases.sh against the CRuby values of
# scripts/fiberargs_expected.tsv) and, unless --no-tests is given, mruby's
# regression tests (scripts/fiberargs_run_tests.sh). Copy of
# scripts/classreal_run_variant.sh with the case runner, the FIBERARGS-INVARIANT
# marker, the fiberargs_* scripts, the test runner and this header changed; the
# compiler-output digest is dropped because the patch changes the runtime
# mrbgems/mruby-fiber/src/fiber.c, not code generation.
#
# Usage: fiberargs_run_variant.sh [--no-tests] <image> <outdir> <name> <description> [<diff>...]
#
# Several diffs are applied in the order given. Writes
# <outdir>/<name>.{diff,build.log,poc.log,cases.log,tests.log} and appends a
# one-line summary to <outdir>.log. A crash is judged by the presence of a
# sanitizer report, not by exit status.
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

inst=${image##*.x86_64.}; cve=${inst##*-}
c=secb-mruby-$cve-$name
docker run -d --name "$c" --platform linux/amd64 $opts "$image" sleep infinity >/dev/null
trap 'docker rm -f "$c" >/dev/null' EXIT
docker exec "$c" mkdir -p /tmp/scripts
for s in fiberargs_run_tests.sh fiberargs_run_cases.sh fiberargs_cases.tsv fiberargs_expected.tsv; do
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
elif grep -q 'ERROR: LeakSanitizer' "$out.poc.log"; then poc=leak
elif grep -q 'FIBERARGS-INVARIANT' "$out.poc.log"; then poc=invariant
else poc=no-crash; fi

docker exec "$c" bash /tmp/scripts/fiberargs_run_cases.sh /src/mruby/bin/mruby \
  /tmp/scripts/fiberargs_cases.tsv /tmp/scripts/fiberargs_expected.tsv > "$out.cases.log" 2>&1 || true
cases=$(tail -1 "$out.cases.log" | sed 's/^summary: //')

if [ $tests = 1 ]; then
  docker exec "$c" bash /tmp/scripts/fiberargs_run_tests.sh > "$out.tests.log" 2>&1 || true
  t=$(grep -E '^ +(OK|KO|Crash|Skip):|minirake test exit|mrbtest -v exit' "$out.tests.log" | tr -s ' ' | paste -sd' ' -)
else
  t="not run"
fi

printf '%s | %s | build=OK | poc=%s | cases: %s | digest=n/a | tests: %s\n' \
  "$name" "$desc" "$poc" "$cases" "$t" >> "$outdir.log"
