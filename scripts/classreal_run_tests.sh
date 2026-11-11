#!/bin/bash
# Runs mruby 1.4.1 (mruby.cve-2018-12249) regression tests with the secb build
# flags: first ./minirake test (the 2018 test target, Rakefile task :test =>
# ["all"]; it runs the library tests and bintest), then the library tests again
# with the verbose test driver (build/test/bin/mrbtest -v), which prints one
# line per test, so that two builds can be compared per test rather than by
# totals. Copy of scripts/run_tests.sh and scripts/mruby_run_tests_verbose.sh
# adapted to the 2018 ./minirake build and the build/test/bin/mrbtest path.
# Usage (inside the instance container): classreal_run_tests.sh
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
