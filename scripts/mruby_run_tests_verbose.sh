#!/bin/bash
# Runs mruby's regression tests with the secb build flags: first
# scripts/run_tests.sh (rake -m test, lib tests and bintest), then the lib
# tests again with the verbose test driver (build/host/bin/mrbtest -v),
# which prints one line per test, so that two builds can be compared per
# test rather than by totals.
# Usage (inside the instance container, run_tests.sh in the same
# directory): mruby_run_tests_verbose.sh
here=$(cd "$(dirname "$0")" && pwd)
bash "$here/run_tests.sh"
cd /src/mruby
echo "--- build/host/bin/mrbtest -v"
build/host/bin/mrbtest -v 2>&1; echo "mrbtest -v exit=$?"
