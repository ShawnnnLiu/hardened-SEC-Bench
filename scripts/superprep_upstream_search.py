#!/usr/bin/env python3
"""Search upstream mruby around the mruby.cve-2022-1427 fix.

Usage: superprep_upstream_search.py <mruby clone>

<mruby clone> is a full clone of https://github.com/mruby/mruby with every
branch and tag fetched. Local paths are not printed.

For this instance the CVE_NVD developer patch IS the upstream fix:
  a4d97934d51cb88954cc49161dc1d151f64afb6b ("vm.c: check if target_class is
  NULL (when prepended).", 2022-04-21), whose parent is the base commit
  bdc244e9. It merges the MRB_FL_CLASS_IS_PREPENDED and MRB_TT_MODULE branches
  of OP_SUPER under one `!target_class || target_class->tt != MRB_TT_ICLASS`
  check, so a NULL class from mrb_vm_ci_target_class(ci) no longer reaches
  mrb_obj_is_kind_of. The base already carries the mruby.cve-2022-1201
  developer patch 00acae117 (an ancestor), which guarded the MRB_TT_MODULE
  branch alone.

The search records: that the fix is on master, the release tags of the base
and the fix, and every later commit that touches the OP_SUPER reassignment
region, to check for a follow-up fix of the same NULL invariant.
"""
import datetime, subprocess, sys

repo = sys.argv[1]
BASE = 'bdc244e9b035c608e3aeb1cb3440c47c2a5d61e6'
DEV = '00acae117da1b45b318dc36531a7b0021b8097ae'    # mruby.cve-2022-1201 fix, ancestor of BASE
FIX = 'a4d97934d51cb88954cc49161dc1d151f64afb6b'    # this instance's developer patch
CVE = 'CVE-2022-1427'
HUNTR = '23b6f0a9-64f5-421e-a55f-b5b7a671f301'


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def git(*a):
    return subprocess.run(['git', '-C', repo, *a], capture_output=True, text=True,
                          errors='replace').stdout.rstrip('\n')


def head(t):
    print('\n== ' + t)


print(f'# superprep_upstream_search {CVE} (huntr {HUNTR})  {now()}')
print(f'# base {BASE}')
print(f'# dev/fix {FIX}  (parent of base; CVE_NVD developers_patch == SEC-bench gold == upstream fix)')
print(f'# 1201 fix {DEV}  (ancestor of base; guards the MRB_TT_MODULE branch only)')

head('fix metadata')
print(git('show', '-s', '--format=%H%n%an%n%cI%n%s', FIX))

head('00acae117 is an ancestor of the base')
print('ancestor' if subprocess.run(['git', '-C', repo, 'merge-base', '--is-ancestor', DEV, BASE]).returncode == 0
      else 'NOT an ancestor')
print('commits DEV..BASE: ' + git('rev-list', '--count', f'{DEV}..{BASE}'))

head('fix is on origin/master')
print('on master' if subprocess.run(['git', '-C', repo, 'merge-base', '--is-ancestor', FIX, 'origin/master']).returncode == 0
      else 'NOT on master')

head('first release tags (sorted by creation)')
print('base:')
print(git('tag', '--contains', BASE, '--sort=creatordate'))
print('fix:')
print(git('tag', '--contains', FIX, '--sort=creatordate'))

head('later commits that change the merged OP_SUPER guard (pickaxe on the guard string)')
print(git('log', '--format=%H %cI %s', f'{FIX}..origin/master',
          '-S', 'target_class->tt != MRB_TT_ICLASS', '--', 'src/vm.c'))

head('later commits touching the prepended branch of OP_SUPER (pickaxe on the flag test)')
print(git('log', '--format=%H %cI %s', f'{FIX}..origin/master',
          '-S', 'target_class->flags & MRB_FL_CLASS_IS_PREPENDED', '--', 'src/vm.c'))

head('OP_SUPER NULL handling on origin/master')
src = git('show', 'origin/master:src/vm.c')
lines = src.splitlines()
for i, l in enumerate(lines):
    if 'CASE(OP_SUPER' in l:
        for l2 in lines[i:i + 14]:
            print(l2)
        break
