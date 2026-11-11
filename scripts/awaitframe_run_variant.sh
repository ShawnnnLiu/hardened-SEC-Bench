#!/bin/bash
# Builds one patch variant of an njs SEC-bench instance in a fresh container
# and records the build, the PoC, the JavaScript cases of a topic and,
# unless --no-tests is given, the njs test suites (scripts/njs_run_tests.sh).
# The njs counterpart of scripts/run_variant.sh and
# scripts/gpac_run_variant.sh, with the same summary format.
#
# Usage: scripts/njs_run_variant.sh [--no-tests] [--ref <ref> <path>]
#          --cases <generator.py> <expected.tsv>
#          <image> <outdir> <name> <description> [<diff>...]
#
# <generator.py> writes the case files (e.g. scripts/promise_absent_cases.py)
# and <expected.tsv> holds the reference engine's outputs for them
# (scripts/njs_cases.py --oracle). The diffs are applied with plain
# `git apply` in the order given, e.g. the developer patch followed by an
# instrumentation diff. With --ref, the tree is first checked out at <ref>
# fetched from https://github.com/nginx/njs (e.g. master, or a commit
# hash), and <name>.diff starts with the `git diff` of <path> between the
# base commit and <ref>; the diffs, if any, are applied on top.
# Writes <outdir>/<name>.{diff,build.log,poc.log,cases.log[,tests.log]} and
# appends a one-line summary to <outdir>.log. A crash is judged by the
# presence of a sanitizer report, not by exit status. The cases are the
# generator's files plus the dataset PoC (case "poc", expected to print
# nothing and end without a sanitizer report), run by scripts/njs_cases.py.
# The container is secb-njs-<cve>-<name>; extra `docker run` options are
# taken from SECB_DOCKER_OPTS (default empty) and printed in the build log
# header.
set -eu
tests=1 ref="" refpath=""
if [ "$1" = "--no-tests" ]; then tests=0; shift; fi
if [ "$1" = "--ref" ]; then ref=$2 refpath=$3; shift 3; fi
[ "$1" = "--cases" ] || { echo "missing --cases" >&2; exit 2; }
gen=$2 expected=$3; shift 3
image=$1 outdir=$2 name=$3 desc=$4; shift 4
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$outdir"
out=$outdir/$name
opts=${SECB_DOCKER_OPTS:-}

# secb-<project>-<cve number>-<role>, e.g. secb-njs-32414-root
inst=${image##*.x86_64.}; cve=${inst##*-}
c=secb-njs-$cve-$name
# shellcheck disable=SC2086
docker run -d --name "$c" --platform linux/amd64 $opts "$image" sleep infinity >/dev/null
trap 'docker rm -f "$c" >/dev/null' EXIT
docker exec "$c" mkdir -p /tmp/scripts
for s in njs_cases.py njs_run_tests.sh; do
  docker cp "$here/$s" "$c:/tmp/scripts/$s"
done
docker cp "$gen" "$c:/tmp/scripts/cases_gen.py"
docker cp "$expected" "$c:/tmp/scripts/expected.tsv"

: > "$out.diff"
if [ -n "$ref" ]; then
  docker exec "$c" bash -c "cd /src/njs && git fetch -q --depth=1 https://github.com/nginx/njs '$ref' && git checkout -q FETCH_HEAD &&
    git diff \$(cat /testcase/base_commit_hash) HEAD -- '$refpath'" > "$out.diff" 2>&1 || {
    printf '%s | %s | build=FAIL (fetch of %s)\n' "$name" "$desc" "$ref" >> "$outdir.log"; exit 0; }
  desc="$desc, $(docker exec "$c" git -C /src/njs rev-parse HEAD)"
fi
i=0
for diff in "$@"; do
  i=$((i+1))
  docker cp "$diff" "$c:/tmp/variant$i.diff"
  docker exec "$c" bash -c "cd /src/njs && git apply /tmp/variant$i.diff" > "$out.apply.log" 2>&1 || {
    printf '%s | %s | build=FAIL (git apply of %s)\n' "$name" "$desc" "$(basename "$diff")" >> "$outdir.log"; exit 0; }
  rm -f "$out.apply.log"
done
if [ $i -gt 0 ]; then
  docker exec "$c" bash -c 'cd /src/njs && git diff' >> "$out.diff"
fi

{ echo "--- container $c image $image docker-opts: ${opts:-<none>}"
  echo "--- HEAD $(docker exec "$c" git -C /src/njs rev-parse HEAD)"
  docker exec "$c" secb build 2>&1; } > "$out.build.log" || true
if ! grep -q 'BUILD COMPLETED SUCCESSFULLY' "$out.build.log"; then
  printf '%s | %s | build=FAIL\n' "$name" "$desc" >> "$outdir.log"
  exit 0
fi

docker exec "$c" secb repro > "$out.poc.log" 2>&1 || true
if grep -q -E 'ERROR: AddressSanitizer|runtime error:' "$out.poc.log"; then poc=crash
elif grep -q -E '\b[A-Z]+-INVARIANT\b' "$out.poc.log"; then poc=invariant
else poc=no-crash; fi

pocfile=${SECB_POC:-/testcase/poc.js}
docker exec "$c" bash -c "python3 -B /tmp/scripts/cases_gen.py /tmp/cases > /dev/null &&
  CASE_JOBS=1 python3 -B /tmp/scripts/njs_cases.py /src/njs/build/njs /tmp/cases /tmp/scripts/expected.tsv \
    --extra poc='$pocfile'" > "$out.cases.log" 2>&1 || true
cases=$(tail -1 "$out.cases.log" | sed 's/^summary: //')
digest=$(sed -n 's/.*valid outputs \([0-9a-f]*\)$/\1/p' "$out.cases.log" | tail -1)

if [ $tests = 1 ]; then
  docker exec "$c" bash /tmp/scripts/njs_run_tests.sh > "$out.tests.log" 2>&1 || true
  t=$(grep -m1 '^SUMMARY' "$out.tests.log" | sed 's/^SUMMARY //' || echo "no summary")
else
  t="not run"
fi

printf '%s | %s | build=OK | poc=%s | cases: %s | digest=%s | tests: %s\n' \
  "$name" "$desc" "$poc" "$cases" "$digest" "$t" >> "$outdir.log"
