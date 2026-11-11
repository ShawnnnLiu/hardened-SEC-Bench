#!/bin/bash
# Builds one patch variant of mruby.cve-2022-1201 in a fresh container and
# records the build, the PoC, the super-with-NULL-target-class cases
# (scripts/supernull_cases.sh) and, unless --no-tests is given, mruby's
# regression tests (scripts/run_tests.sh).
#
# Usage: supernull_run_variant.sh [--no-tests] <image> <outdir> <name> <description> [<diff>...]
#
# Several diffs are applied in the order given, e.g. the root-cause patch
# followed by an instrumentation diff. Writes
# <outdir>/<name>.{diff,build.log,poc.log,cases.log,tests.log}, where
# <name>.diff is the resulting `git diff` against the base commit, and appends
# a one-line summary to <outdir>.log. A crash is judged by the presence of an
# AddressSanitizer report, not by exit status.
#
# No compiler-output digest is taken: the patch changes src/vm.c (the VM), not
# code generation, so the compiled output of the tree is unaffected by
# construction; the super cases and the regression tests are the behavioural
# oracles.
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

# secb-<project>-<cve number>-<role>, e.g. secb-mruby-1201-root
inst=${image##*.x86_64.}; cve=${inst##*-}
c=secb-mruby-$cve-$name
docker run -d --name "$c" --platform linux/amd64 $opts "$image" sleep infinity >/dev/null
trap 'docker rm -f "$c" >/dev/null' EXIT
docker exec "$c" mkdir -p /tmp/scripts
for s in run_tests.sh supernull_cases.sh; do
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
elif grep -q 'SUPER-INVARIANT' "$out.poc.log"; then poc=invariant
else poc=no-crash; fi

docker exec "$c" bash /tmp/scripts/supernull_cases.sh /src/mruby/build/host/bin/mruby > "$out.cases.log" 2>&1 || true
cases=$(tail -1 "$out.cases.log" | sed 's/^summary: //')

if [ $tests = 1 ]; then
  docker exec "$c" bash /tmp/scripts/run_tests.sh > "$out.tests.log" 2>&1 || true
  t=$(grep -E '^ +(OK|KO|Crash|Skip):|rake test exit' "$out.tests.log" | tr -s ' ' | paste -sd' ' -)
else
  t="not run"
fi

printf '%s | %s | build=OK | poc=%s | cases: %s | tests: %s\n' \
  "$name" "$desc" "$poc" "$cases" "$t" >> "$outdir.log"
