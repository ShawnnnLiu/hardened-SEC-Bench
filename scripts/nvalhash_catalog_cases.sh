#!/bin/bash
# Runs the programs of the blind second reading of mruby.cve-2022-0240 (phase 2)
# on one interpreter and prints, for every program, its exit status, standard
# output and standard error between fixed markers:
#   @@@ BEGIN <dir>/<name> rc=<status>
#   @@@ STDOUT
#   ...
#   @@@ STDERR
#   ...
#   @@@ END
# Each program is run from its own directory under its relative file name, so
# that the file name in an error message is the same for every interpreter.
# Leak detection is off, so that only memory errors are reported. A crash is
# judged by the sanitizer report, never by exit status.
#
# Programs: the reader's 34 inputs (groups a to d), 5 inputs of batch E, 1 input of
# batch F and 56 probes, taken from logs/mruby.cve-2022-0240/second_reading/phase2/
# and copied into the container.
#
# Expected results, written before the root build was run (the root patch adds
# `val &&` to the three stack-emitting branches of gen_hash(), which keeps the
# compiler stack pointer of a discarded literal unchanged; it does not create a
# fresh base hash for a leading `**` in value context):
#   base:       the reader's base classes (5 ASAN of the 34 inputs of groups a to d)
#   developer:  the reader's patched classes (0 ASAN of 34; `Object.extend(c)` ASAN
#               in e1 and the probe that passes `c` to `Object.extend`)
#   root:       no ASAN report on any program; the programs that need only the stack
#               accounting (a3, a4, a5, a8, b1 to b5, c1 to c5, e1, e2) equal the
#               reference; the value-context inputs with a leading `**` (b6, c6 to
#               c9) stay WRONG
#
# Usage (inside the instance container):
#   nvalhash_catalog_cases.sh <mruby binary | ruby> <dir>...
set -u
BIN=$1; shift
export ASAN_OPTIONS=detect_leaks=0
echo "# binary: $BIN"
if [ -d /src/mruby/.git ]; then
  echo "# HEAD $(git -C /src/mruby rev-parse HEAD)"
  echo "# git diff --stat: $(git -C /src/mruby diff --stat | tail -n 1)"
fi
echo "# dirs: $*"
OUT=/tmp/nvc_stdout.txt; ERR=/tmp/nvc_stderr.txt
for d in "$@"; do
  dn=$(basename "$d")
  for f in "$d"/*.rb; do
    [ -e "$f" ] || continue
    n=$(basename "$f" .rb)
    (cd "$d" && timeout 120 "$BIN" "$n.rb" > "$OUT" 2> "$ERR"); rc=$?
    printf '@@@ BEGIN %s/%s rc=%s\n@@@ STDOUT\n' "$dn" "$n" "$rc"
    cat "$OUT"
    printf '\n@@@ STDERR\n'
    cat "$ERR"
    printf '\n@@@ END\n'
  done
done
