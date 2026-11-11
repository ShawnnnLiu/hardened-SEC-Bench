#!/bin/bash
# Builds one variant of mruby.cve-2022-0326 in a fresh container and runs
# scripts/novalgc_residual_cases.sh on it (the deep-frame crash probes). Copy
# of scripts/run_residual_variant.sh (mruby.cve-2022-1276); the case script
# name, the mruby binary path (build/host/bin/mruby for this instance) and this
# header differ.
#
# Usage: scripts/novalgc_run_residual_variant.sh [--ref <commit>] <image> <outdir> <name> <description> [<diff>]
#
# Without --ref the variant is the base commit plus <diff>, and only
# <outdir>/<name>.residual.log is written, so the existing logs of that variant
# are left as produced. A crash is judged by the presence of an AddressSanitizer
# report, not by exit status. Extra docker run options come from
# SECB_DOCKER_OPTS.
set -eu
ref=
if [ "$1" = "--ref" ]; then ref=$2; shift 2; fi
image=$1 outdir=$2 name=$3 desc=$4 diff=${5:-}
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$outdir"
out=$outdir/$name
opts=${SECB_DOCKER_OPTS:-}

inst=${image##*.x86_64.}; cve=${inst##*-}
c=secb-mruby-$cve-$name
docker run -d --name "$c" --platform linux/amd64 $opts "$image" sleep infinity >/dev/null
trap 'docker stop "$c" >/dev/null' EXIT
docker exec "$c" mkdir -p /tmp/scripts
for s in novalgc_cases.sh novalgc_residual_cases.sh; do
  docker cp "$here/$s" "$c:/tmp/scripts/$s"
done

if [ -n "$ref" ]; then
  if docker exec "$c" test -e /src/mruby/build; then
    echo "/src/mruby/build exists in the image; not building $ref over it" >&2; exit 1
  fi
  docker exec -w /src/mruby "$c" git fetch -q --depth 1 https://github.com/mruby/mruby "$ref"
  docker exec -w /src/mruby "$c" git -c advice.detachedHead=false checkout -q FETCH_HEAD
fi
if [ -n "$diff" ]; then
  docker cp "$diff" "$c:/tmp/variant.diff"
  docker exec -w /src/mruby "$c" git apply /tmp/variant.diff
fi
head=$(docker exec -w /src/mruby "$c" git rev-parse HEAD)
stat=$(docker exec -w /src/mruby "$c" git diff --stat)

build=$(docker exec "$c" secb build 2>&1 || true)
if grep -q 'BUILD COMPLETED SUCCESSFULLY' <<<"$build"; then b=OK; else b=FAIL; fi

if [ -n "$ref" ]; then
  { echo "HEAD $head"; echo "$build"; } > "$out.build.log"
fi
{
  echo "variant $name: $desc"
  echo "HEAD $head"
  echo "--- git diff --stat"; [ -n "$stat" ] && echo "$stat"
  echo "--- secb build: $b"
} > "$out.residual.log"
if [ $b = FAIL ]; then
  [ -n "$ref" ] && printf '%s | %s | build=FAIL\n' "$name" "$desc" >> "$outdir.log"
  exit 0
fi
docker exec "$c" bash /tmp/scripts/novalgc_residual_cases.sh /src/mruby/build/host/bin/mruby >> "$out.residual.log" 2>&1 || true

if [ -n "$ref" ]; then
  docker exec "$c" secb repro > "$out.poc.log" 2>&1 || true
  if grep -q 'ERROR: AddressSanitizer' "$out.poc.log"; then poc=crash; else poc=no-crash; fi
  docker exec "$c" bash /tmp/scripts/novalgc_cases.sh /src/mruby/build/host/bin/mruby > "$out.cases.log" 2>&1 || true
  cases=$(tail -1 "$out.cases.log" | sed 's/^summary: //')
  printf '%s | %s | build=OK | poc=%s | cases: %s | digest=not run | tests: not run\n' \
    "$name" "$desc" "$poc" "$cases" >> "$outdir.log"
fi
