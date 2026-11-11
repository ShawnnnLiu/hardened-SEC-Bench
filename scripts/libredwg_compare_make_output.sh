#!/bin/bash
# Compares the complete output of two `make check` runs of
# scripts/libredwg_run_tests.sh (the file /tmp/libredwg_make_check.out of the
# container of each run): size, sha256, number of `ok`, `not ok` and
# `PASS:`/`FAIL:` lines of each file, and the result of `cmp` (byte
# comparison) and, if they differ, whether the sorted lines are identical
# (the order of the compile lines of a parallel make varies) or else the
# first differing lines.
#
# With sed options after the two files (e.g. -e 's/Makefile:880/Makefile:881/'),
# it also prints the sha256 of the first file after those substitutions, to
# compare with the fingerprint line of a tests.log written by
# scripts/libredwg_run_variant.sh (the Makefile of a tree built from the
# committed image is regenerated, which shifts two line numbers of the
# output).
#
# Usage: libredwg_compare_make_output.sh <before.out> <after.out> [sed options]
set -u
a=$1 b=$2
shift 2
for f in "$a" "$b"; do
  echo "$(basename "$f"): $(wc -c < "$f" | tr -d ' ') bytes, sha256 $(shasum -a 256 "$f" | cut -c1-64)," \
       "ok $(grep -c '^ok ' "$f"), not ok $(grep -c '^not ok' "$f")," \
       "PASS $(grep -c '^PASS:' "$f"), FAIL $(grep -c '^FAIL:' "$f"), XFAIL $(grep -c '^XFAIL:' "$f"), SKIP $(grep -c '^SKIP:' "$f")"
done
if cmp -s "$a" "$b"; then echo "cmp: the two outputs are byte-identical"
else
  echo "cmp: the outputs differ"
  sa=$(LC_ALL=C sort "$a" | shasum -a 256 | cut -c1-64); sb=$(LC_ALL=C sort "$b" | shasum -a 256 | cut -c1-64)
  if [ "$sa" = "$sb" ]; then echo "sorted lines: identical (sha256 $sa), so the outputs differ in the order of lines only"
  else echo "sorted lines: differ; first differing lines of the sorted outputs:"; diff <(LC_ALL=C sort "$a") <(LC_ALL=C sort "$b") | head -20; fi
fi
if [ $# -gt 0 ]; then
  echo "first file after sed $*: sha256 $(sed "$@" "$a" | shasum -a 256 | cut -c1-64)"
fi
