#!/bin/bash
# `super` with a NULL target class (mruby.cve-2022-1427). Copy of
# scripts/supernull_cases.sh (mruby.cve-2022-1201) with the dataset PoC row
# reading /testcase/poc.rb instead of /testcase/PoC.js; the case programs are
# unchanged. In the OP_SUPER handler (src/vm.c, base bdc244e9) the proc target
# class, when it is a module or a prepended class, is replaced by
# mrb_vm_ci_target_class(ci), which can return NULL (its backing
# ci->u.env->c / ci->u.target_class is unset). The reassigned class is then
# used without a NULL check. At this base the MRB_TT_MODULE branch already has
# the NULL check (mruby.cve-2022-1201 developer patch 00acae117, an ancestor of
# this base), so only the MRB_FL_CLASS_IS_PREPENDED branch reaches
# mrb_obj_is_kind_of(recv, NULL), which does `switch (c->tt)` (src/object.c)
# with no NULL check: a SEGV on the zero page. This instance's developer patch
# (a4d97934d) merges the two branches under one NULL + ICLASS check, so the
# prepended branch no longer crashes.
#
# Usage (inside the instance container): superprep_cases.sh <mruby binary>
# Passing `ruby` runs only the valid-super controls on the image's CRuby,
# which validates their expected values (the crasher cases raise different
# errors on CRuby and are skipped there).
#
# Result class per case: ASAN (sanitizer report), INV (a SUPER-INVARIANT
# marker from the assertion variant), OK, or WRONG. A crash is judged by the
# sanitizer report, never by exit status. For a crasher case OK means the
# fix turned the crash into a controlled Ruby exception (no sanitizer report);
# for a control case OK means the printed value equals the CRuby reference.
set -u
MRUBY=$1
D=$(mktemp -d)
ok=0; wrong=0; asan=0; inv=0; total=0
is_ruby=0; [ "$MRUBY" = ruby ] && is_ruby=1

# A crasher: expected to SEGV on the base build; the fix must turn it into a
# controlled exception (no sanitizer report). Skipped under the CRuby oracle.
crash_case() { # name, program
  [ $is_ruby = 1 ] && return
  local f=$D/$1.rb out; printf '%s\n' "$2" > "$f"
  out=$("$MRUBY" "$f" 2>&1); total=$((total+1))
  if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then
    asan=$((asan+1)); printf '%-18s ASAN %s\n' "$1" "$(grep -m1 -o 'SEGV' <<<"$out")"
  elif grep -q 'SUPER-INVARIANT' <<<"$out"; then
    inv=$((inv+1)); printf '%-18s %s\n' "$1" "$(grep -m1 -o 'SUPER-INVARIANT[^"]*' <<<"$out")"
  else
    ok=$((ok+1)); printf '%-18s OK\n' "$1"
  fi
}

# A valid-super control: must print the expected value (equal to CRuby) on
# every build; a crash or a changed value is a regression of the fix.
ctrl_case() { # name, program, expected
  local f=$D/$1.rb out val; printf '%s\n' "$2" > "$f"
  out=$("$MRUBY" "$f" 2>&1); total=$((total+1))
  if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then
    asan=$((asan+1)); printf '%-18s ASAN %s\n' "$1" "$(grep -m1 -o 'SEGV' <<<"$out")"
  elif grep -q 'SUPER-INVARIANT' <<<"$out"; then
    inv=$((inv+1)); printf '%-18s %s\n' "$1" "$(grep -m1 -o 'SUPER-INVARIANT[^"]*' <<<"$out")"
  else
    val=$(sed -n 's/.*<<\(.*\)>>.*/\1/p' <<<"$out" | tail -1)
    if [ "$val" = "$3" ]; then ok=$((ok+1)); printf '%-18s OK\n' "$1"
    else wrong=$((wrong+1)); printf '%-18s WRONG got=%s\n' "$1" "${val:-<none>}"; fi
  fi
}

# --- MRB_TT_MODULE branch: super whose target class is a module, reached via
#     Module#initialize's block and instance_eval (ci target class NULL) ---
crash_case mod_init   'module Mi; end
Mi.initialize { 1.instance_eval { super } }'
crash_case mod_init2  'Comparable.initialize { :s.instance_eval { super } }'

# --- boundary: a NON-immediate receiver (String) gets a real singleton, so
#     mrb_vm_ci_target_class(ci) is non-NULL and no branch dereferences NULL;
#     no crash on any build ---
crash_case recv_string 'module Ms; end
Ms.initialize { "x".instance_eval { super } }'

# --- MRB_FL_CLASS_IS_PREPENDED branch: same, but the module has something
#     prepended, so target_class carries the prepended flag; NOT fixed by the
#     developer patch ---
crash_case prep_init  'module Qp; end
module Pp; end
Pp.prepend(Qp)
Pp.initialize { 1.instance_eval { super } }'
crash_case prep_init2 'module Qp2; end
module Pp2; end
Pp2.prepend(Qp2)
Pp2.initialize { :sym.instance_eval { super } }'

# --- controls caught earlier (proc target class NULL -> "super called outside
#     of method"); they never reach the reassignment branches ---
crash_case outside    'module Mo; end
Mo.module_eval { 1.instance_eval { super } }'

# --- valid super (must keep working; wrong value or crash is a regression) ---
ctrl_case ctrl_class    'class Ac; def f; 10; end; end
class Bc < Ac; def f; super + 1; end; end
print "<<" + Bc.new.f.to_s + ">>"'                               "11"
ctrl_case ctrl_module   'module Mm; def f; 100; end; end
class Am; def f; 100; end; end
class Bm < Am; include Mm; def f; super + 1; end; end
print "<<" + Bm.new.f.to_s + ">>"'                               "101"
ctrl_case ctrl_prepend  'module Pr; def f; super + 1; end; end
class Cr; prepend Pr; def f; 10; end; end
print "<<" + Cr.new.f.to_s + ">>"'                               "11"
ctrl_case ctrl_prepend2 'class Ap; def f; 5; end; end
module Pp3; def f; super * 2; end; end
class Cp < Ap; prepend Pp3; def f; 10; end; end
print "<<" + Cp.new.f.to_s + ">>"'                               "20"

# --- the dataset PoC (MRB_FL_CLASS_IS_PREPENDED branch: `prepend dup` inside
#     Math.initialize's block, 4.instance_exec { super() }) ---
if [ $is_ruby = 0 ] && [ -f /testcase/poc.rb ]; then
  out=$("$MRUBY" /testcase/poc.rb 2>&1); total=$((total+1))
  if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then
    asan=$((asan+1)); printf '%-18s ASAN %s\n' poc "$(grep -m1 -o 'SEGV' <<<"$out")"
  elif grep -q 'SUPER-INVARIANT' <<<"$out"; then
    inv=$((inv+1)); printf '%-18s %s\n' poc "$(grep -m1 -o 'SUPER-INVARIANT[^"]*' <<<"$out")"
  else
    ok=$((ok+1)); printf '%-18s OK\n' poc
  fi
fi

echo "summary: $ok OK, $wrong WRONG, $asan ASAN, $inv INV of $total"
rm -rf "$D"
