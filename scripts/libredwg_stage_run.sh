#!/bin/bash
# Runs the stages apply, build, PoC and tests of one patch of a libredwg
# SEC-bench instance in a fresh container of the instance image, with the
# same commands and log layout as the stages of the developer patch
# (apply.log, build_after.log, poc_after.log, tests_after.log).
#
# Usage: libredwg_stage_run.sh <image> <patch> <suffix> <logdir> [--no-tests]
#
#   <image>   the SEC-bench image (not the built image: the build is full)
#   <patch>   the diff to apply with plain `git apply`
#   <suffix>  stage name, e.g. min: writes apply_min.log, build_min.log,
#             poc_min.log and tests_min.log to <logdir>
#
# The container is secb-libredwg-<cve number>-<suffix>; extra `docker run`
# options are taken from SECB_DOCKER_OPTS (default empty). The build and PoC
# logs end in a line with the wall-clock time of the command.
set -eu
image=$1 patch=$2 suffix=$3 logdir=$4; tests=1
[ "${5:-}" = "--no-tests" ] && tests=0
here=$(cd "$(dirname "$0")" && pwd)
opts=${SECB_DOCKER_OPTS:-}
inst=${image##*.x86_64.}; inst=${inst%%:*}; cve=${inst##*-}
c=secb-libredwg-$cve-$suffix
mkdir -p "$logdir"
# shellcheck disable=SC2086
docker run -d --name "$c" --platform linux/amd64 $opts "$image" sleep infinity >/dev/null
trap 'docker rm -f "$c" >/dev/null' EXIT
docker cp "$patch" "$c:/tmp/patch.diff"
docker cp "$here/libredwg_run_tests.sh" "$c:/tmp/libredwg_run_tests.sh"
TIMEFORMAT='%R s wall clock'
{ docker exec "$c" git -C /src/libredwg rev-parse HEAD
  docker exec "$c" bash -c 'cd /src/libredwg && git apply --check -v /tmp/patch.diff 2>&1 && git apply /tmp/patch.diff && echo APPLIED && git diff --stat' 2>&1
} > "$logdir/apply_$suffix.log" || { echo "apply failed, see $logdir/apply_$suffix.log" >&2; exit 1; }
{ echo "--- container $c image $image docker-opts: ${opts:-<none>}"
  { time docker exec "$c" secb build 2>&1; } 2>&1
} > "$logdir/build_$suffix.log" || true
{ { time docker exec "$c" secb repro 2>&1; } 2>&1; } > "$logdir/poc_$suffix.log" || true
if [ $tests = 1 ]; then
  { time docker exec "$c" bash /tmp/libredwg_run_tests.sh /src/libredwg 2>&1; } > "$logdir/tests_$suffix.log" 2>&1 || true
fi
grep -c 'ERROR: AddressSanitizer' "$logdir/poc_$suffix.log" | sed 's/^/poc sanitizer reports: /'
tail -n 1 "$logdir/tests_$suffix.log" 2>/dev/null | cut -c1-200 || true
