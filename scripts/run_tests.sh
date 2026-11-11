#!/bin/bash
# Runs mruby's regression tests (rake -m test) with the secb build flags.
# Usage (inside the instance container): run_tests.sh
cd /src/mruby
echo "HEAD $(git rev-parse HEAD)"
echo "--- git diff --stat"; git diff --stat
export CFLAGS="-w -Wno-yacc -Wno-incompatible-pointer-types -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link"
export LDFLAGS="$CFLAGS" LD=clang
echo "CFLAGS=$CFLAGS"; echo "ASAN_OPTIONS=${ASAN_OPTIONS:-<unset>}"
echo "--- rake -m test"
rake -m test 2>&1; echo "rake test exit=$?"
