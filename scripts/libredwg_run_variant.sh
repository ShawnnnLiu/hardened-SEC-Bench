#!/bin/bash
# Builds one patch variant of a libredwg SEC-bench instance in a fresh
# container and records the build, the PoC, the cases of a topic, a corpus
# check over the tracked DWG files and, unless --no-tests is given, the
# test suite (scripts/libredwg_run_tests.sh). The libredwg counterpart of
# scripts/gpac_run_variant.sh and scripts/njs_run_variant.sh, with the same
# summary format.
#
# Usage: scripts/libredwg_run_variant.sh [--no-tests] [--no-corpus] [--quick]
#          [--env KEY=VALUE]... [--ref <ref> <path>] [--inputs <dir>]
#          [--copy <file>]... --cases <cases.py> <image> <outdir> <name>
#          <description> [<diff>...]
#
# <image> is the SEC-bench image or a local image committed from a built
# container (scripts/libredwg_make_built_image.sh), in which `secb build`
# recompiles only what the variant changes. <cases.py> is the case script
# of the topic (e.g. scripts/escape_cases.py); it is run as
#   python3 cases.py run --inputs /tmp/scripts/inputs    (cases.log)
#   python3 cases.py corpus                              (digest.log)
# and prints a final `summary:` line (run) and `corpus:` line (corpus).
# --copy files (e.g. scripts/escape_driver.c) are placed next to it;
# --inputs <dir> is copied to /tmp/scripts/inputs. The diffs are applied
# with plain `git apply` in the order given, e.g. the developer patch
# followed by an instrumentation diff. With --ref, the tree is checked out
# at <ref> fetched from https://github.com/LibreDWG/libredwg (e.g. master)
# instead, <name>.diff is the `git diff` of <path> between the base commit
# and <ref>, and the diffs, if any, are applied on top.
# Writes <outdir>/<name>.{diff,build.log,poc.log,cases.log,digest.log
# [,tests.log]} and appends a one-line summary to <outdir>.log. A crash is
# judged by the presence of a sanitizer report, not by exit status (poc=timeout
# when `secb repro` runs longer than POC_TIMEOUT seconds, default 120). With
# tests, the last line of tests.log fingerprints the complete make output.
# digest= is <valid-output digest of the cases>/<corpus digest>.
# --quick builds with `make -j$(nproc)` instead of `secb build` (autogen and
# configure are not rerun; the tree of a built image is already configured)
# and says so in the build log header. --env KEY=VALUE is passed to the
# case and corpus runs (e.g. CASE_ONLY=<regex> to run a subset of the cases).
# The container is secb-libredwg-<cve number>-<name>; extra `docker run`
# options are taken from SECB_DOCKER_OPTS (default empty) and printed in the
# build log header.
set -eu
tests=1 corpus=1 quick=0 ref="" refpath="" inputs="" cases="" copies=() envs=()
while [ $# -gt 0 ]; do
  case "$1" in
    --no-tests) tests=0; shift ;;
    --no-corpus) corpus=0; shift ;;
    --quick) quick=1; shift ;;
    --env) envs+=("-e" "$2"); shift 2 ;;
    --ref) ref=$2 refpath=$3; shift 3 ;;
    --inputs) inputs=$2; shift 2 ;;
    --copy) copies+=("$2"); shift 2 ;;
    --cases) cases=$2; shift 2 ;;
    *) break ;;
  esac
done
[ -n "$cases" ] || { echo "missing --cases" >&2; exit 2; }
image=$1 outdir=$2 name=$3 desc=$4; shift 4
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$outdir"
out=$outdir/$name
opts=${SECB_DOCKER_OPTS:-}
casesbase=$(basename "$cases")

# secb-<project>-<cve number>-<role>, e.g. secb-libredwg-21816-after
inst=${image##*.x86_64.}; inst=${inst%%:*}; cve=${inst##*-}
c=secb-libredwg-$cve-$name
# shellcheck disable=SC2086
docker run -d --name "$c" --platform linux/amd64 $opts "$image" sleep infinity >/dev/null
trap 'docker rm -f "$c" >/dev/null' EXIT
docker exec "$c" mkdir -p /tmp/scripts/inputs
docker cp "$here/libredwg_run_tests.sh" "$c:/tmp/scripts/libredwg_run_tests.sh"
docker cp "$cases" "$c:/tmp/scripts/$casesbase"
for f in ${copies[@]+"${copies[@]}"}; do
  docker cp "$f" "$c:/tmp/scripts/$(basename "$f")"
done
if [ -n "$inputs" ]; then docker cp "$inputs/." "$c:/tmp/scripts/inputs"; fi

: > "$out.diff"
if [ -n "$ref" ]; then
  docker exec "$c" bash -c "cd /src/libredwg && base=\$(git rev-parse HEAD) &&
    git fetch -q --depth=1 https://github.com/LibreDWG/libredwg '$ref' && git checkout -q -f FETCH_HEAD &&
    git diff \$base HEAD -- $refpath" > "$out.diff" 2>&1 || {
    printf '%s | %s | build=FAIL (fetch of %s)\n' "$name" "$desc" "$ref" >> "$outdir.log"; exit 0; }
  desc="$desc, $(docker exec "$c" git -C /src/libredwg rev-parse HEAD)"
fi
i=0
for diff in "$@"; do
  i=$((i+1))
  docker cp "$diff" "$c:/tmp/variant$i.diff"
  docker exec "$c" bash -c "cd /src/libredwg && git apply /tmp/variant$i.diff" > "$out.apply.log" 2>&1 || {
    printf '%s | %s | build=FAIL (git apply of %s)\n' "$name" "$desc" "$(basename "$diff")" >> "$outdir.log"; exit 0; }
  rm -f "$out.apply.log"
done
if [ $i -gt 0 ]; then
  docker exec "$c" bash -c 'cd /src/libredwg && git diff' >> "$out.diff"
fi

{ echo "--- container $c image $image docker-opts: ${opts:-<none>}"
  echo "--- image id $(docker inspect --format '{{.Id}}' "$image")"
  echo "--- HEAD $(docker exec "$c" git -C /src/libredwg rev-parse HEAD)"
  echo "--- started $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [ $quick = 1 ]; then
    echo "--- build: make -j (autogen and configure not rerun)"
    if docker exec "$c" bash -c 'cd /src/libredwg && make -j$(nproc) 2>&1'; then
      echo "BUILD COMPLETED SUCCESSFULLY!"
    else
      echo "BUILD FAILED!"
    fi
  else
    docker exec "$c" secb build 2>&1
  fi
  echo "--- finished $(date -u +%Y-%m-%dT%H:%M:%SZ)"; } > "$out.build.log" || true
if ! grep -q 'BUILD COMPLETED SUCCESSFULLY' "$out.build.log"; then
  printf '%s | %s | build=FAIL\n' "$name" "$desc" >> "$outdir.log"
  exit 0
fi

prc=0
docker exec "$c" timeout -k 5 "${POC_TIMEOUT:-120}" secb repro > "$out.poc.log" 2>&1 || prc=$?
if grep -q -E 'ERROR: AddressSanitizer|runtime error:' "$out.poc.log"; then poc=crash
elif grep -q -E '\b[A-Z]+-INVARIANT\b' "$out.poc.log"; then poc=invariant
elif [ $prc = 124 ] || [ $prc = 137 ]; then poc=timeout
else poc=no-crash; fi

docker exec ${envs[@]+"${envs[@]}"} "$c" bash -c "python3 -B /tmp/scripts/$casesbase run --inputs /tmp/scripts/inputs" > "$out.cases.log" 2>&1 || true
cases_sum=$(tail -1 "$out.cases.log" | sed 's/^summary: //')
digest=$(sed -n 's/.*valid outputs \([0-9a-f]*\)$/\1/p' "$out.cases.log" | tail -1)

if [ $corpus = 1 ]; then
  docker exec ${envs[@]+"${envs[@]}"} "$c" bash -c "python3 -B /tmp/scripts/$casesbase corpus" > "$out.digest.log" 2>&1 || true
  cdigest=$(sed -n 's/^corpus: .*digest \([0-9a-f]*\)$/\1/p' "$out.digest.log" | tail -1)
  digest="$digest/$cdigest"
fi

if [ $tests = 1 ]; then
  docker exec "$c" bash /tmp/scripts/libredwg_run_tests.sh /src/libredwg > "$out.tests.log" 2>&1 || true
  # fingerprint of the complete make output (the log keeps only its tail)
  docker exec "$c" bash -c 'f=/tmp/libredwg_make_check.out; echo "--- make output: $(wc -c < $f | tr -d " ") bytes, sha256 $(sha256sum $f | cut -c1-64), ok $(grep -c "^ok " $f), not ok $(grep -c "^not ok" $f), PASS $(grep -c "^PASS:" $f), invariant markers $(grep -c -E "[A-Z]+-INVARIANT" $f)"' >> "$out.tests.log" 2>&1 || true
  t=$(grep -m1 '^SUMMARY tests=' "$out.tests.log" | sed 's/^SUMMARY //' || echo "no summary")
else
  t="not run"
fi

printf '%s | %s | build=OK | poc=%s | cases: %s | digest=%s | tests: %s\n' \
  "$name" "$desc" "$poc" "$cases_sum" "$digest" "$t" >> "$outdir.log"
