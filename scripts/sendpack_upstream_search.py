#!/usr/bin/env python3
"""Search upstream mruby around the mruby.cve-2022-0631 fix.

Usage: sendpack_upstream_search.py <mruby clone>

<mruby clone> is a full clone of https://github.com/mruby/mruby with every
branch and tag fetched. Local paths are not printed.

For this instance the CVE_NVD developer patch IS the upstream fix:
  47068ae07a5fa3aa9a1879cdfe98a9ce0f339299 ("vm.c: packed arguments length may
  be zero for `send` method.", 2022-02-18), whose parent is the base commit
  1e314242. It adds, in the n == 15 (CALL_MAXARGS) branch of mrb_f_send, a
  check `if (RARRAY_LEN(regs[0]) == 0) goto argnum_error;` before the method
  name is read from RARRAY_PTR(regs[0])[0], and labels the existing n == 0
  error path argnum_error, so an empty packed argument array raises
  ArgumentError instead of reading past the array buffer.

The search records: that the fix is on master, the release tags of the base
and the fix, and every later commit that touches mrb_f_send, to check for a
follow-up fix of the same empty-packed-array invariant.
"""
import datetime, subprocess, sys

repo = sys.argv[1]
BASE = '1e314242e42932ec7146eaef87605e9ae5e91ba3'
FIX = '47068ae07a5fa3aa9a1879cdfe98a9ce0f339299'    # this instance's developer patch
CVE = 'CVE-2022-0631'
HUNTR = '9bdc49ca-6697-4adc-a785-081e1961bf40'


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def git(*a):
    return subprocess.run(['git', '-C', repo, *a], capture_output=True, text=True,
                          errors='replace').stdout.rstrip('\n')


def head(t):
    print('\n== ' + t)


print(f'# sendpack_upstream_search {CVE} (huntr {HUNTR})  {now()}')
print(f'# base {BASE}')
print(f'# dev/fix {FIX}  (parent of base; CVE_NVD developers_patch == SEC-bench gold == upstream fix)')

head('fix metadata')
print(git('show', '-s', '--format=%H%n%an%n%cI%n%s', FIX))

head('fix parent is the base commit')
print('parent: ' + git('rev-parse', f'{FIX}^'))

head('fix is on origin/master')
print('on master' if subprocess.run(['git', '-C', repo, 'merge-base', '--is-ancestor', FIX, 'origin/master']).returncode == 0
      else 'NOT on master')

head('first release tags (sorted by creation)')
print('base:')
print(git('tag', '--contains', BASE, '--sort=creatordate'))
print('fix:')
print(git('tag', '--contains', FIX, '--sort=creatordate'))

head('later commits that change the empty-array check (pickaxe on the check string)')
print(git('log', '--oneline', '--format=%H %cI %s', f'{FIX}..origin/master',
          '-S', 'RARRAY_LEN(regs[0]) == 0', '--', 'src/vm.c') or '(none: the check is unchanged from the fix to master)')

head('later commits on src/vm.c whose subject names send or public_send')
print(git('log', '--oneline', '--format=%H %cI %s', f'{FIX}..origin/master',
          '--grep', r'send', '-i', '--', 'src/vm.c') or '(none)')

head('empty-packed-array check on origin/master (now in the shared send_method)')
src = git('show', 'origin/master:src/vm.c')
lines = src.splitlines()
for i, l in enumerate(lines):
    if l.startswith('send_method(mrb_state'):
        # print from the function signature to a few lines past the n == 15 check
        end = i + 40
        for j, l2 in enumerate(lines[i:end]):
            print(l2)
            if 'RARRAY_LEN(regs[0]) == 0' in l2:
                print(lines[i + j + 1])
                break
        break
