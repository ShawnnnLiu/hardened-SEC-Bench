#!/bin/bash
# Runs mruby 1.4.0-era (mruby.cve-2018-10199, base fabc4608) regression tests with
# the secb build flags: first ./minirake test (the 2018 test target, Rakefile task
# :test => ["all"]; it runs the library tests and bintest), then the library tests
# again with the verbose test driver (build/test/bin/mrbtest -v), which prints one
# line per test, so that two builds can be compared per test rather than by totals.
# Copy of scripts/classreal_run_tests.sh with only the header changed; if
# build/test/bin/mrbtest -v is absent or prints no per-test lines at this base, the
# comparison falls back to the failing/skipped test names plus totals (recorded).
# Usage (inside the instance container): iocopy_run_tests.sh
cd /src/mruby
echo "HEAD $(git rev-parse HEAD)"
echo "--- git diff --stat"; git diff --stat
export CFLAGS="-w -Wno-yacc -Wno-incompatible-pointer-types -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link"
export LDFLAGS="$CFLAGS" LD=clang
echo "CFLAGS=$CFLAGS"; echo "ASAN_OPTIONS=${ASAN_OPTIONS:-<unset>}"
echo "--- ./minirake test"
./minirake test 2>&1; echo "minirake test exit=$?"
echo "--- build/test/bin/mrbtest -v"
build/test/bin/mrbtest -v 2>&1; echo "mrbtest -v exit=$?"
