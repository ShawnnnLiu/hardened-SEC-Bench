#!/bin/bash
# Runs mruby 1.4.1-era (mruby.cve-2018-12248, base ff0a4f78) regression tests with
# the secb build flags: first ./minirake test (the 2018 test target), then the
# library tests again with the verbose driver (build/test/bin/mrbtest -v), one line
# per test, so two builds can be compared per test. Copy of
# scripts/classreal_run_tests.sh with only the header changed; if
# build/test/bin/mrbtest -v is absent or prints no per-test lines, the comparison
# falls back to the failing/skipped test names plus totals (recorded).
# Usage (inside the instance container): fiberargs_run_tests.sh
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
