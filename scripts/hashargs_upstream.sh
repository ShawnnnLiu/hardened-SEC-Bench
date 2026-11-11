#!/bin/bash
# Upstream and residual-site check for mruby.cve-2022-1934.
#
# The developer patch is upstream commit aa7f98dedb; this script records
# that it is upstream, the history of the fixed function since the fix, the
# form at origin/master, and a scan for any other helper that holds a raw
# VM-value-stack pointer across a call that can reallocate the stack (the
# bug class). It must be run inside a container with network from the
# instance image (git clone/fetch of mruby/mruby). Local paths are not
# printed.
#
# Usage (inside the instance container): hashargs_upstream.sh
set -u
FIX=aa7f98dedb68d735a1665d3a289036c88b0c47ce
cd /src/mruby

sec() { echo; echo "======== $1"; }

sec "fix commit (CVE_NVD developers_patch / patch_url)"
git fetch -q --depth 50 https://github.com/mruby/mruby "$FIX" 2>&1 | tail -1 || true
git log -1 --format='%H%n%an%n%ad%n%s' "$FIX" 2>&1
echo "--- is base_commit the fix's parent?"
echo "base HEAD: $(git rev-parse HEAD)"
echo "fix^:      $(git rev-parse ${FIX}^ 2>/dev/null || echo '(parent not fetched)')"

sec "origin/master form of the fixed function"
git fetch -q --depth 1 https://github.com/mruby/mruby master 2>&1 | tail -1 || true
MASTER=$(git rev-parse FETCH_HEAD)
echo "origin/master: $MASTER"
echo "--- grep for hash_new_from_values / hash_new_from_regs on master:"
for f in src/vm.c; do
  git grep -n -E 'hash_new_from_(values|regs)|mrb_value \*regs|mrb_int idx' "$MASTER" -- "$f" 2>/dev/null
done
echo "--- function body on master (if present):"
git show "$MASTER:src/vm.c" 2>/dev/null | awk '/hash_new_from_/{p=1} p{print} p&&/^}/{exit}' | head -25

sec "history of src/vm.c keyword-pack code since the fix"
git log --oneline "$FIX..$MASTER" -- src/vm.c 2>/dev/null | head -40
echo "--- commits since the fix whose vm.c diff touches hash_new_from_regs or ARGUMENT_NORMALIZE:"
git log --oneline -S hash_new_from_regs "$FIX..$MASTER" -- src/vm.c 2>/dev/null
git log --oneline -S ARGUMENT_NORMALIZE "$FIX..$MASTER" -- src/vm.c 2>/dev/null

sec "residual-site scan: helpers taking a raw mrb_value* stack pointer"
echo "--- functions in src/vm.c with an (mrb_value *regs / *argv / *) parameter:"
grep -nE '^[A-Za-z_].*\(mrb_state \*mrb,.*mrb_value \*[A-Za-z_]+\)' src/vm.c
echo "--- note: mrb_funcall_argv/mrb_yield_argv/mrb_yield_cont copy argv into"
echo "    the stack via mrb_stack_extend_adjust(&argv), which updates the"
echo "    pointer after a reallocation; hash_new_from_values did not."
