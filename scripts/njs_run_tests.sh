#!/bin/bash
# Runs the njs test suites of the tree in /src/njs, inside a SEC-bench njs
# container after "secb build", with the compiler flags of that build (the
# Makefile written by ./configure under the secb CFLAGS).
#
# Usage: bash njs_run_tests.sh [<suite>...]   (default: unit lib test262 shell)
#
# Suites, as defined by "make test" and "make lib_test" at the base commit:
#   unit     build/njs_unit_test -v; prints each test script before running
#            it and, for a failing test, an njs("...") expected/got block;
#            each suite ends with "<suite> tests: PASSED|FAILED [p/t]"
#   lib      build/{random,rbtree,lvlhsh,unicode}_unit_test
#   test262  test/test262 --binary=build/njs with NJS_TEST_VERBOSE=1, one
#            "<test> <log> PASSED|FAILED" line per test file under test/
#   shell    expect -f test/shell_test.exp (interactive shell); the script
#            has no per-test pass/fail output (expect timeouts are not
#            failures at this commit), so only its exit status and the
#            number of spawned sessions are reported
# Every suite runs to completion even if an earlier one fails. Each
# section ends with "SUITE <name> exit=<status> seconds=<s>". The last line
# is
#   SUMMARY unit p/t exit=<s>; lib p/4; test262 p/t exit=<s>; shell exit=<s> sessions=<n>
set -u
cd /src/njs
suites=${*:-unit lib test262 shell}
echo "HEAD $(git rev-parse HEAD)"
git diff --stat
echo "nproc $(nproc) ASAN_OPTIONS=${ASAN_OPTIONS:-<unset>}"

make -j"$(nproc)" build/njs build/njs_unit_test build/random_unit_test \
  build/rbtree_unit_test build/lvlhsh_unit_test build/unicode_unit_test > /tmp/njs_test_build.log 2>&1
echo "test build exit=$? ($(grep -c . /tmp/njs_test_build.log) lines of make output)"

unit="not run" lib="not run" t262="not run" shell="not run"
for s in $suites; do
  echo "=== SUITE $s"
  start=$(date +%s)
  log=/tmp/njs_suite_$s.log
  case $s in
    unit)
      build/njs_unit_test -v > $log 2>&1
      rc=$?
      cat $log
      unit=$(sed -n 's/^TOTAL: [A-Z]* \[\([0-9]*\/[0-9]*\)\]$/\1/p' $log)
      unit="${unit:-no total} exit=$rc"
      ;;
    lib)
      n=0
      : > $log
      for b in random rbtree lvlhsh unicode; do
        build/${b}_unit_test >> $log 2>&1; r=$?
        echo "lib ${b}_unit_test exit=$r" >> $log
        [ $r = 0 ] && n=$((n+1))
      done
      cat $log
      rc=0; [ $n = 4 ] || rc=1
      lib="$n/4"
      ;;
    test262)
      NJS_TEST_VERBOSE=1 test/test262 --binary=build/njs > $log 2>&1
      rc=$?
      cat $log
      t262=$(sed -n 's/^TOTAL: [A-Z]* \[\([0-9]*\/[0-9]*\)\]$/\1/p' $log)
      t262="${t262:-no total} exit=$rc"
      ;;
    shell)
      INPUTRC=test/inputrc PATH=build:$PATH expect -f test/shell_test.exp > $log 2>&1
      rc=$?
      cat $log
      n=$(grep -a -o 'spawn -nottycopy njs' $log | wc -l | tr -d ' ')
      echo "shell sessions spawned: $n"
      shell="exit=$rc sessions=$n"
      ;;
  esac
  echo "SUITE $s exit=$rc seconds=$(( $(date +%s) - start ))"
done
echo "SUMMARY unit $unit; lib $lib; test262 $t262; shell $shell"
