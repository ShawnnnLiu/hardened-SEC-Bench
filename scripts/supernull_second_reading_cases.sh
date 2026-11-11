#!/bin/bash
# Additional entry points to the OP_SUPER NULL target class (mruby.cve-2022-1201)
# found by the blind second reading and absent from supernull_cases.sh: `super`
# reached through module_eval / class_eval called from inside a method (so the
# `mid == 0` guard does not fire), around instance_eval on an immediate receiver.
# c6 and c7 take the MRB_TT_MODULE branch of OP_SUPER; pc_classeval and
# pc_moduleeval take the MRB_FL_CLASS_IS_PREPENDED branch (the class has a
# prepended module). The inputs are the second reader's files byte for byte;
# the sha256 prefix of each is printed.
#
# Expected class per build:
#   base:      c6 ASAN, c7 ASAN, pc_classeval ASAN, pc_moduleeval ASAN
#   developer: c6 OK,   c7 OK,   pc_classeval ASAN, pc_moduleeval ASAN
#   root:      all four OK (the merged NULL + ICLASS check guards both branches)
# The base and developer values were observed by the second reading before this
# script was written; the root values are the prediction under test and were
# written down before the root build was run.
#
# Result class per input: ASAN (sanitizer report) or OK (no sanitizer report, a
# controlled Ruby exception; CRuby raises a different error for these inputs).
# A crash is judged by the sanitizer report, never by exit status.
#
# Usage (inside the instance container): supernull_second_reading_cases.sh <mruby binary>
set -u
MRUBY=$1
D=/tmp/supernull_sr; mkdir -p "$D"
echo "HEAD $(git -C /src/mruby rev-parse HEAD)"
echo "--- git diff --stat"; git -C /src/mruby diff --stat
echo "--- cases"
ok=0; asan=0; total=0

case_run() { # name, program
  local f=$D/$1.rb out msg; printf '%s\n' "$2" > "$f"
  out=$("$MRUBY" "$f" 2>&1); total=$((total+1))
  if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then
    asan=$((asan+1)); printf '%-14s ASAN %s %s\n' "$1" "$(grep -m1 -o 'SEGV' <<<"$out")" "$(sha256sum "$f" | cut -c1-12)"
  else
    ok=$((ok+1)); msg=$(tail -n 1 <<<"$out" | sed 's#^[^ ]*:[0-9]*:in [^:]*: ##')
    printf '%-14s OK   %s | %s\n' "$1" "$(sha256sum "$f" | cut -c1-12)" "$msg"
  fi
}

case_run c6_modeval 'module M; end
def go; M.module_eval { 0x7f.instance_eval { super } }; end
go'
case_run c7_clseval 'def go; Comparable.module_eval { 0x7f.instance_eval { super } }; end
go'
case_run pc_classeval 'module Pm2; end
class PC
  prepend Pm2
end
def go
  PC.class_eval { 0x7f.instance_eval { super } }
end
go'
case_run pc_moduleeval 'module Pm3; end
class PC2
  prepend Pm3
end
def go
  PC2.module_eval { 0x7f.instance_exec { super } }
end
go'

# the dataset PoC, as a check of the build under test
if [ -f /testcase/PoC.js ]; then
  out=$("$MRUBY" /testcase/PoC.js 2>&1); total=$((total+1))
  if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then
    asan=$((asan+1)); printf '%-14s ASAN %s\n' poc "$(grep -m1 -o 'SEGV' <<<"$out")"
  else
    ok=$((ok+1)); printf '%-14s OK\n' poc
  fi
fi
echo "summary: $ok OK, $asan ASAN of $total"
