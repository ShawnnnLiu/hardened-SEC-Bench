#!/bin/bash
# Builds one variant of an mruby SEC-bench instance in a fresh container and
# runs scripts/kwargs_residual_cases.sh on it.
#
# Usage: scripts/run_residual_variant.sh [--ref <commit>] <image> <outdir> <name> <description> [<diff>]
#
# Without --ref the variant is the base commit plus <diff>, as in
# scripts/run_variant.sh, and only <outdir>/<name>.residual.log is written,
# so the existing logs of that variant are left as produced.
#
# With --ref the base tree is replaced by <commit> of upstream mruby (fetched
# inside the container, with its submodules), which makes a new variant:
# <name>.build.log (starting with the checked-out HEAD), <name>.poc.log,
# <name>.cases.log (scripts/kwargs_aset_cases.sh) and <name>.residual.log,
# plus a summary row in <outdir>.log. Compiler digest and regression tests
# are not run for such a variant.
#
# A crash is judged by the presence of an AddressSanitizer report, not by
# exit status.
set -eu
ref=
if [ "$1" = "--ref" ]; then ref=$2; shift 2; fi
image=$1 outdir=$2 name=$3 desc=$4 diff=${5:-}
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$outdir"
out=$outdir/$name

# secb-<project>-<cve number>-<role>, e.g. secb-mruby-1276-upstream_master
inst=${image##*.x86_64.}; cve=${inst##*-}
c=secb-mruby-$cve-$name
docker run -d --name "$c" --platform linux/amd64 "$image" sleep infinity >/dev/null
trap 'docker stop "$c" >/dev/null' EXIT
docker exec "$c" mkdir -p /tmp/scripts
for s in kwargs_aset_cases.sh kwargs_residual_cases.sh; do
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
docker exec "$c" bash /tmp/scripts/kwargs_residual_cases.sh /src/mruby/bin/mruby >> "$out.residual.log" 2>&1 || true

if [ -n "$ref" ]; then
  docker exec "$c" secb repro > "$out.poc.log" 2>&1 || true
  if grep -q 'ERROR: AddressSanitizer' "$out.poc.log"; then poc=crash; else poc=no-crash; fi
  docker exec "$c" bash /tmp/scripts/kwargs_aset_cases.sh /src/mruby/bin/mruby > "$out.cases.log" 2>&1 || true
  cases=$(tail -1 "$out.cases.log" | sed 's/^summary: //')
  printf '%s | %s | build=OK | poc=%s | cases: %s | digest=not run | tests: not run\n' \
    "$name" "$desc" "$poc" "$cases" >> "$outdir.log"
fi
