#!/bin/bash
# Runs LibreDWG's own test suite (`make -k check`) in a built tree of a
# SEC-bench libredwg image and prints the per-test results.
#
# Usage: libredwg_run_tests.sh [<tree>]      (default /src/libredwg)
#
# configure.ac uses the automake serial-tests harness, which writes no
# per-test .log/.trs files; it prints one "PASS: <test>" / "FAIL: <test>"
# (SKIP, XFAIL, XPASS, ERROR) line per test in the make output. This script
# lists those lines prefixed with the directory make was in, sorted, then
# the totals, the per-directory result lines, the *.log files the tests
# leave behind (alive.test keeps <dwg>-<prog>.log for every failing run)
# and the tail of the make output. The last line is
# "SUMMARY tests=<n> pass=<n> fail=<n> skip=<n> xfail=<n> xpass=<n> error=<n> make_exit=<rc>".
# Run with the same environment on every build that is compared.
set -u
tree=${1:-/src/libredwg}
cd "$tree" || exit 1
out=/tmp/libredwg_make_check.out
echo "--- HEAD $(git rev-parse HEAD)"
echo "--- git diff --stat"
git diff --stat
echo "--- ASAN_OPTIONS=${ASAN_OPTIONS-<unset>} UBSAN_OPTIONS=${UBSAN_OPTIONS-<unset>} nproc=$(nproc)"
start=$(date +%s)
touch /tmp/libredwg_tests.start
make -k -j"$(nproc)" check > "$out" 2>&1
rc=$?
end=$(date +%s)
echo "--- make -k -j$(nproc) check exit=$rc elapsed=$((end - start))s"

# Attribute each result line to the directory make reports entering.
results=$(awk '
  /Entering directory/ { d = $NF; gsub(/[`'"'"']/, "", d); sub("^'"$tree"'/?", "", d); if (d == "") d = "."; dir = d }
  /^(PASS|FAIL|SKIP|XFAIL|XPASS|ERROR): / { r = $1; sub(/:$/, "", r); $1 = ""; sub(/^ /, ""); print dir "/" $0 " " r }
' "$out" | sort)
echo "--- per-test results"
printf '%s\n' "$results"
count() { printf '%s\n' "$results" | grep -c " $1\$"; }
n=$(printf '%s\n' "$results" | grep -c .)
echo "--- per-directory result lines"
grep -E '^(All [0-9]+ tests passed|[0-9]+ of [0-9]+ tests? failed|[0-9]+ tests? (were|was) not run|.*tests? (passed|failed).*)' "$out" | sed 's/^/  /'
echo "--- logs left by failing tests"
find . -name '*.log' -newer /tmp/libredwg_tests.start 2>/dev/null | sort | while read -r f; do
  case "$f" in */config.log) continue ;; esac
  echo "=== $f"
  tail -n 40 "$f"
done
echo "--- tail of make output"
tail -n 150 "$out"
echo "SUMMARY tests=$n pass=$(count PASS) fail=$(count FAIL) skip=$(count SKIP) xfail=$(count XFAIL) xpass=$(count XPASS) error=$(count ERROR) make_exit=$rc"
