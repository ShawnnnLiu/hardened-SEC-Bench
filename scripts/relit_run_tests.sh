#!/bin/bash
# Runs the njs test suites of the tree in /src/njs for njs.cve-2019-13617
# (njs 0.3.6, base commit 15fc1a04), inside a SEC-bench njs container after
# "secb build", with the compiler flags of that build.  Topic copy of
# scripts/njs_run_tests.sh: the 0.3.6 tree has a different set of suites
# (no test262, the fourth lib test is utf8 not unicode, the interactive
# shell suite is test/njs_expect_test.exp not test/shell_test.exp, and
# there is a separate build/njs_interactive_test binary).  The output
# format (=== SUITE, SUITE exit=, the unit per-test lines and TOTAL, the
# lib "lib <name> exit=" lines, the shell session count) matches
# scripts/njs_run_tests.sh so that scripts/njs_compare_tests.py parses it.
#
# Usage: bash relit_run_tests.sh [<suite>...]   (default: unit lib inter shell)
#
# Suites:
#   unit   build/njs_unit_test v; prints each test script and, for a
#          failing one, an njs("...") expected/got block; ends with
#          TOTAL: PASSED|FAILED [p/t].  The 0.3.6 binary enables verbose
#          with the bare flag "v" (it reads argv[1][0]), not "-v".
#   lib    build/{random,rbtree,lvlhsh,utf8}_unit_test
#   inter  build/njs_interactive_test v (its own per-test binary; ends
#          with "njs interactive tests passed"; no TOTAL; compared by exit
#          status, njs_compare_tests.py ignores the suite name "inter")
#   shell  expect -f test/njs_expect_test.exp; no per-test pass/fail
#          output, so only its exit status and the number of spawned
#          sessions are reported (njs_compare_tests.py shell handling)
# test262 does not exist at this base and is not run.
# Every suite runs to completion even if an earlier one fails.  The last
# line is
#   SUMMARY unit p/t exit=<s>; lib p/4; inter exit=<s>; shell exit=<s> sessions=<n>
set -u
cd /src/njs
suites=${*:-unit lib inter shell}
echo "HEAD $(git rev-parse HEAD)"
git diff --stat
echo "nproc $(nproc) ASAN_OPTIONS=${ASAN_OPTIONS:-<unset>}"
make -j"$(nproc)" build/njs build/njs_unit_test build/random_unit_test \
  build/rbtree_unit_test build/lvlhsh_unit_test build/utf8_unit_test \
  build/njs_interactive_test > /tmp/njs_test_build.log 2>&1
echo "test build exit=$? ($(grep -c . /tmp/njs_test_build.log) lines of make output)"
unit="not run" lib="not run" inter="not run" shell="not run"
for s in $suites; do
  echo "=== SUITE $s"
  start=$(date +%s)
  log=/tmp/njs_suite_$s.log
  case $s in
    unit)
      build/njs_unit_test v > $log 2>&1
      rc=$?
      cat $log
      unit=$(sed -n 's/^TOTAL: [A-Z]* \[\([0-9]*\/[0-9]*\)\]$/\1/p' $log)
      unit="${unit:-no total} exit=$rc"
      ;;
    lib)
      n=0
      : > $log
      for b in random rbtree lvlhsh utf8; do
        build/${b}_unit_test >> $log 2>&1; r=$?
        echo "lib ${b}_unit_test exit=$r" >> $log
        [ $r = 0 ] && n=$((n+1))
      done
      cat $log
      rc=0; [ $n = 4 ] || rc=1
      lib="$n/4"
      ;;
    inter)
      build/njs_interactive_test v > $log 2>&1
      rc=$?
      cat $log
      inter="exit=$rc"
      ;;
    shell)
      INPUTRC=test/inputrc PATH=build:$PATH expect -f test/njs_expect_test.exp > $log 2>&1
      rc=$?
      cat $log
      n=$(grep -a -o 'spawn -nottycopy njs' $log | wc -l | tr -d ' ')
      echo "shell sessions spawned: $n"
      shell="exit=$rc sessions=$n"
      ;;
  esac
  echo "SUITE $s exit=$rc seconds=$(( $(date +%s) - start ))"
done
echo "SUMMARY unit $unit; lib $lib; inter $inter; shell $shell"
