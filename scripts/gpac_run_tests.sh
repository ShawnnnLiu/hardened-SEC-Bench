#!/bin/bash
# Run the GPAC test suite (gpac/testsuite) against the build in /src/gpac.
#
# Usage, inside a SEC-bench gpac container after "secb build":
#   gpac_run_tests.sh TESTSUITE_SRC MEDIA_DIR MANIFEST [make_tests.sh args...]
#
# TESTSUITE_SRC  checkout of gpac/testsuite at the commit pinned by the gpac
#                tree (git ls-tree HEAD testsuite); copied, never written to
# MEDIA_DIR      local mirror of the suite's external media
# MANIFEST       sha256sum list for MEDIA_DIR; checked before the run
#
# Same as "make test_suite" (make_tests.sh -precommit -p=0) except that
# -precommit is not used: it is -sync-media plus -warn, and the media are
# instead taken from MEDIA_DIR, while -warn would copy every failing
# subtest log into the console output. Extra args go to make_tests.sh.
# Prints a header, the make_tests.sh output, then one "RESULT" line per
# test taken from results/all_results.xml. The results directory, with
# every subtest log, is left in $RESULTS_TGZ (default
# /tmp/testsuite_results.tgz). If MARKER is set, a line
# "MARKER <text> lines=<n>" counts the lines of the results directory that
# contain <text>, followed by up to 5 of them.
set -u
SRC_TS=$1
MEDIA=$2
MANIFEST=$3
shift 3
RUN=/tmp/testsuite

cd /src/gpac
echo "HEAD $(git rev-parse HEAD)"
echo "--- git diff --stat"
git diff --stat
echo "testsuite $(git -C "$SRC_TS" rev-parse HEAD) (pinned $(git ls-tree HEAD testsuite | awk '{print $3}'))"
echo "external_media manifest $(sha256sum < "$MANIFEST" | cut -d' ' -f1), $(wc -l < "$MANIFEST") files, $(find "$MEDIA" -type f | wc -l) on disk"
(cd "$MEDIA" && sha256sum --quiet -c "$MANIFEST") && echo "external_media check OK" || { echo "external_media check FAILED"; exit 1; }
echo "ASAN_OPTIONS=${ASAN_OPTIONS-<unset>}"
echo "nproc $(nproc)"

rm -rf "$RUN"
cp -a "$SRC_TS" "$RUN"
ln -s "$MEDIA" "$RUN/external_media"
export PATH=/src/gpac/bin/gcc:$PATH
# make_tests.sh colours its output with tput; TERM=dumb makes tput a no-op
export TERM=dumb
echo "--- make_tests.sh -p=0 $*"
cd "$RUN"
./make_tests.sh -p=0 "$@"
echo "make_tests exit=$?"

echo "--- per-test results (results/all_results.xml)"
python3 - "$RUN/results/all_results.xml" <<'EOF'
import sys
import xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
s = root.find("TestSuiteResults")
print("SUMMARY", " ".join(f"{k}={v}" for k, v in s.attrib.items()))
for t in sorted(root.iter("test"), key=lambda t: t.get("name")):
    print("RESULT", t.get("name"), t.get("result"))
EOF
if [ -n "${MARKER:-}" ]; then
  # an instrumented build prints MARKER when its invariant check fires;
  # the results directory holds every subtest's logs
  echo "MARKER $MARKER lines=$(grep -r -a -F -- "$MARKER" "$RUN/results" | wc -l)"
  grep -r -a -F -h -- "$MARKER" "$RUN/results" | head -5 | sed 's/^/MARKER-LINE /'
fi
RESULTS_TGZ=${RESULTS_TGZ:-/tmp/testsuite_results.tgz}
mkdir -p "$(dirname "$RESULTS_TGZ")"
tar -C "$RUN" -czf "$RESULTS_TGZ" results
