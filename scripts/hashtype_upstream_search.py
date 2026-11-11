#!/usr/bin/env python3
"""Search upstream mruby around the mruby.cve-2022-0614 / mruby.cve-2022-0623 fix.

Usage: hashtype_upstream_search.py <mruby clone>

<mruby clone> is a full clone of https://github.com/mruby/mruby with every
branch and tag fetched. Local paths are not printed.

Both instances share one CVE_NVD developer patch, upstream commit
  ff3a5ebed6ffbe3e70481531cfb969b497aa73ad ("vm.c: should check type before
  hash access.", 2022-02-15), whose parent is ecb28f4b. It replaces, in the
  OP_HASHADD handler of mrb_vm_exec, `mrb_assert(mrb_hash_p(hash));` with
  `mrb_ensure_hash_type(mrb, hash);`, so a non-hash in regs[a] raises TypeError
  instead of being passed to mrb_hash_set.

The two instances differ in their SEC-bench base commit:
  0614 base ecb28f4b (= ff3a5ebed~1, the CVE_NVD base and the image HEAD);
  0623 image HEAD 9037e447, which is an ancestor of ecb28f4b.

The search records: the fix metadata, that it is on master, the release tags of
the fix and of each base, and later commits that touch the OP_HASHADD type
check, to check for a follow-up fix of the same invariant.
"""
import datetime, subprocess, sys

repo = sys.argv[1]
FIX = 'ff3a5ebed6ffbe3e70481531cfb969b497aa73ad'
BASE_0614 = 'ecb28f4bf463483cf914c799d086b0cfff997aee'
BASE_0623 = '9037e447a536133559cf5ba2bab9952ac594b723'


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def git(*a):
    return subprocess.run(['git', '-C', repo, *a], capture_output=True, text=True,
                          errors='replace').stdout.rstrip('\n')


def head(t):
    print('\n== ' + t)


print(f'# hashtype_upstream_search CVE-2022-0614 / CVE-2022-0623  {now()}')
print(f'# fix {FIX}  (CVE_NVD developers_patch of both; == each SEC-bench gold)')
print(f'# 0614 base {BASE_0614}  (= fix parent)')
print(f'# 0623 base {BASE_0623}  (image HEAD; ancestor of 0614 base)')

head('fix metadata')
print(git('show', '-s', '--format=%H%n%an%n%cI%n%s', FIX))

head('fix parent')
print('parent: ' + git('rev-parse', f'{FIX}^'))

head('base relationships')
for name, b in (('0614 base', BASE_0614), ('0623 base', BASE_0623)):
    anc = subprocess.run(['git', '-C', repo, 'merge-base', '--is-ancestor', b, FIX]).returncode == 0
    print(f'{name} {b}: ancestor of fix = {anc}; commits {b}..{FIX} = ' + git('rev-list', '--count', f'{b}..{FIX}'))
print('0623 base ancestor of 0614 base = ' +
      str(subprocess.run(['git', '-C', repo, 'merge-base', '--is-ancestor', BASE_0623, BASE_0614]).returncode == 0) +
      f'; commits {BASE_0623}..{BASE_0614} = ' + git('rev-list', '--count', f'{BASE_0623}..{BASE_0614}'))

head('fix is on origin/master')
print('on master' if subprocess.run(['git', '-C', repo, 'merge-base', '--is-ancestor', FIX, 'origin/master']).returncode == 0
      else 'NOT on master')

head('first release tags (sorted by creation)')
for name, c in (('fix', FIX), ('0614 base', BASE_0614), ('0623 base', BASE_0623)):
    print(f'{name}:')
    print(git('tag', '--contains', c, '--sort=creatordate'))

head('later commits that change the OP_HASHADD type check (pickaxe on mrb_ensure_hash_type)')
print(git('log', '--oneline', '--format=%H %cI %s', f'{FIX}..origin/master',
          '-S', 'mrb_ensure_hash_type(mrb, hash)', '--', 'src/vm.c') or '(none: the check is unchanged from the fix to master)')

head('OP_HASHADD handler on origin/master')
src = git('show', 'origin/master:src/vm.c')
lines = src.splitlines()
for i, l in enumerate(lines):
    if 'OP_HASHADD' in l:
        for l2 in lines[i:i + 12]:
            print(l2)
        break
