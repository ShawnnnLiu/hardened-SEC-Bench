#!/bin/bash
# Builds an upstream mruby commit (normally origin/master) in a fresh
# container of the mruby.cve-2022-0326 image and runs the PoC and the
# discarded-splat-hash cases (scripts/novalgc_cases.sh). The --ref part of
# scripts/run_residual_variant.sh, with this instance's case runner and
# SECB_DOCKER_OPTS.
#
# Usage: novalgc_run_master.sh <image> <outdir> <name> <description> <commit>
#
# The commit is fetched inside the container from
# https://github.com/mruby/mruby with depth 1 and checked out over the base
# tree. Writes <outdir>/<name>.build.log (starting with the checked-out
# HEAD), <name>.poc.log and <name>.cases.log, and appends a summary row to
# <outdir>.log. Compiler digest and regression tests are not run for such a
# variant (the tree differs from the base). A crash is judged by the
# presence of a sanitizer report, not by exit status.
#
# upstream master uses the prism front end (gen_hash in
# mrbgems/mruby-compiler/src/codegen.c, a different build), so the build may
# fail in this image; that is recorded as build=FAIL with the first error.
#
# Extra `docker run` options come from SECB_DOCKER_OPTS (default empty).
set -eu
image=$1 outdir=$2 name=$3 desc=$4 ref=$5
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
docker cp "$here/novalgc_cases.sh" "$c:/tmp/scripts/novalgc_cases.sh"

docker exec -w /src/mruby "$c" git fetch -q --depth 1 https://github.com/mruby/mruby "$ref"
docker exec -w /src/mruby "$c" git -c advice.detachedHead=false checkout -q FETCH_HEAD
head=$(docker exec -w /src/mruby "$c" git rev-parse HEAD)

{ echo "HEAD $head"; docker exec "$c" secb build 2>&1 || true; } > "$out.build.log"
if ! grep -q 'BUILD COMPLETED SUCCESSFULLY' "$out.build.log"; then
  printf '%s | %s | build=FAIL | %s\n' "$name" "$desc" "$(grep -m1 -iE 'error|No such|cannot|fatal' "$out.build.log" | head -1)" >> "$outdir.log"
  exit 0
fi

docker exec "$c" secb repro > "$out.poc.log" 2>&1 || true
if grep -q 'ERROR: AddressSanitizer' "$out.poc.log"; then poc=crash; else poc=no-crash; fi

docker exec "$c" bash /tmp/scripts/novalgc_cases.sh /src/mruby/build/host/bin/mruby > "$out.cases.log" 2>&1 || true
cases=$(tail -1 "$out.cases.log" | sed 's/^summary: //')

printf '%s | %s | build=OK | poc=%s | cases: %s | digest=not run | tests: not run\n' \
  "$name" "$desc" "$poc" "$cases" >> "$outdir.log"
