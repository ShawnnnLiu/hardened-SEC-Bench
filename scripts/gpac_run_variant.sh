#!/bin/bash
# Builds one patch variant of a gpac SEC-bench instance in a fresh container
# and records the build, the PoC, the WAVE input cases and, unless
# --no-tests is given, the GPAC test suite. The gpac counterpart of
# scripts/run_variant.sh, with the same arguments and summary format.
#
# Usage: scripts/gpac_run_variant.sh [--no-tests] [--ref <ref> <path>] <image> <outdir> <name> <description> [<diff>...]
#
# Several diffs are applied in the order given, e.g. the root-cause patch
# followed by an instrumentation diff.
# Writes <outdir>/<name>.{diff,build.log,poc.log,cases.log[,tests.log]},
# where <name>.diff is the resulting `git diff` against the base commit, and
# appends a one-line summary to <outdir>.log. A crash is judged by the
# presence of a sanitizer report, not by exit status. The cases are the
# files in /testcase other than *.diff and base_commit_hash, then the inputs
# written by scripts/make_wav_cases.py, run by scripts/rfpcm_wav_cases.py
# against the generator's expected.tsv; digest= is the valid-output digest
# from the cases summary. The container is secb-<project>-<cve>-<name>.
# Tests need GPAC_MEDIA=<dir> holding the
# external_media/ mirror and external_media.sha256 from
# scripts/gpac_mirror_media.py.
# With --ref, the tree is checked out at <ref> fetched from
# https://github.com/gpac/gpac (e.g. master) instead of having a diff
# applied, and <name>.diff is the `git diff` of <path> between the base
# commit and <ref>.
set -eu
tests=1 ref="" refpath=""
if [ "$1" = "--no-tests" ]; then tests=0; shift; fi
if [ "$1" = "--ref" ]; then ref=$2 refpath=$3; shift 3; fi
image=$1 outdir=$2 name=$3 desc=$4; shift 4
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$outdir"
out=$outdir/$name

# secb-<project>-<cve number>-<role>, e.g. secb-gpac-5586-root
inst=${image##*.x86_64.}; cve=${inst##*-}
c=secb-gpac-$cve-$name
docker run -d --name "$c" --platform linux/amd64 "$image" sleep infinity >/dev/null
trap 'docker rm -f "$c" >/dev/null' EXIT
docker exec "$c" mkdir -p /tmp/scripts
for s in rfpcm_wav_cases.py make_wav_cases.py gpac_run_tests.sh; do
  docker cp "$here/$s" "$c:/tmp/scripts/$s"
done
if [ -n "$ref" ]; then
  docker exec "$c" bash -c "cd /src/gpac && git fetch -q --depth=1 https://github.com/gpac/gpac '$ref' && git checkout -q FETCH_HEAD &&
    git diff \$(cat /testcase/base_commit_hash) HEAD -- '$refpath'" > "$out.diff"
  desc="$desc, $(docker exec "$c" git -C /src/gpac rev-parse HEAD)"
else
  i=0
  for diff in "$@"; do
    i=$((i+1))
    docker cp "$diff" "$c:/tmp/variant$i.diff"
    docker exec "$c" bash -c "cd /src/gpac && git apply /tmp/variant$i.diff"
  done
  docker exec "$c" bash -c 'cd /src/gpac && git diff' > "$out.diff"
fi

docker exec "$c" secb build > "$out.build.log" 2>&1 || true
if ! grep -q 'BUILD COMPLETED SUCCESSFULLY' "$out.build.log"; then
  printf '%s | %s | build=FAIL\n' "$name" "$desc" >> "$outdir.log"
  exit 0
fi

docker exec "$c" secb repro > "$out.poc.log" 2>&1 || true
if grep -q -E 'ERROR: AddressSanitizer|runtime error:' "$out.poc.log"; then poc=crash; else poc=no-crash; fi

docker exec "$c" bash -c 'python3 /tmp/scripts/make_wav_cases.py /tmp/cases | sed -n "s/^oracle: /--- oracle: /p" &&
  python3 /tmp/scripts/rfpcm_wav_cases.py /tmp/cases/expected.tsv $(ls /testcase/* | grep -v -e "\.diff$" -e /base_commit_hash$) \
    /tmp/cases/bad_*.wav /tmp/cases/valid_*.wav' > "$out.cases.log" 2>&1 || true
cases=$(tail -1 "$out.cases.log" | sed 's/^summary: //')
digest=$(sed -n 's/.*valid outputs \([0-9a-f]*\)$/\1/p' "$out.cases.log" | tail -1)

if [ $tests = 1 ]; then
  docker exec "$c" bash -c 'apt-get update -qq > /dev/null 2>&1; apt-get install -y -qq time > /dev/null 2>&1'
  docker cp "$GPAC_MEDIA/external_media" "$c:/external_media"
  docker cp "$GPAC_MEDIA/external_media.sha256" "$c:/external_media.sha256"
  docker exec "$c" bash /tmp/scripts/gpac_run_tests.sh /src/gpac/testsuite /external_media \
    /external_media.sha256 -timeout=180 > "$out.tests.log" 2>&1 || true
  t=$(grep -m1 '^SUMMARY' "$out.tests.log" | sed 's/^SUMMARY //' || echo "no summary")
else
  t="not run"
fi

printf '%s | %s | build=OK | poc=%s | cases: %s | digest=%s | tests: %s\n' \
  "$name" "$desc" "$poc" "$cases" "$digest" "$t" >> "$outdir.log"
