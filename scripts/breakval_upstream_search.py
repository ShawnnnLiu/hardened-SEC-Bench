#!/usr/bin/env python3
"""Search upstream mruby around the mruby.cve-2022-1212 fix.

Usage: breakval_upstream_search.py <mruby clone>

<mruby clone> is a full clone of https://github.com/mruby/mruby with every
branch, tag and refs/pull/*/head fetched. Local paths are not printed.

For this instance the CVE_NVD developer patch IS the upstream fix:
  3cf291f72224715942beaf8553e42ba8891ab3c6 ("vm.c: create break object before
  clearing GC arena.", 2022-04-04), whose parent is the base commit
  8aec568fc50c23f4062153fbc75b423ba22219e9. In the OP_R_BREAK
  (ci->cci > CINFO_NONE) branch of mrb_vm_exec it moves the
  `mrb->exc = break_new(..., RBREAK_TAG_BREAK, proc, v)` assignment to directly
  after cipop, before mrb_gc_arena_restore, so the break object (which holds v)
  is created while the arena still protects v across break_new's allocation.

The search records: that the fix is on master, the release tags of the base
and the fix, and every later commit that touches the break path
(break_new, the cci break branch, mark_context_stack) to check for a follow-up
fix of the same break-value-lifetime invariant (the lane file names
748af76ed2, 2024-07-21, which reworks error checking at OP_RETURN/OP_BREAK).
"""
import datetime, subprocess, sys

repo = sys.argv[1]
BASE = '8aec568fc50c23f4062153fbc75b423ba22219e9'
FIX = '3cf291f72224715942beaf8553e42ba8891ab3c6'   # this instance's developer patch
CVE = 'CVE-2022-1212'
HUNTR = '9fcc06d0-08e4-49c8-afda-2cae40946abe'
FOLLOWUP = '748af76ed2'   # named in the lane file; reworks OP_RETURN/OP_BREAK


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def git(*a):
    return subprocess.run(['git', '-C', repo, *a], capture_output=True, text=True,
                          errors='replace').stdout.rstrip('\n')


def head(t):
    print('\n== ' + t)


print(f'# breakval_upstream_search {CVE} (huntr {HUNTR})  {now()}')
print(f'# base {BASE}')
print(f'# dev/fix {FIX}  (base is its parent; CVE_NVD developers_patch == SEC-bench gold == upstream fix)')

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

head('later commits on src/vm.c that touch break_new or the break tag (pickaxe)')
for s in ('break_new', 'RBREAK_TAG_BREAK'):
    print(f'-- pickaxe {s}:')
    print(git('log', '--oneline', '--format=%H %cI %s', f'{FIX}..origin/master',
              '-S', s, '--', 'src/vm.c') or '(none)')

head('later commits on src/vm.c whose subject names break')
print(git('log', '--oneline', '--format=%H %cI %s', f'{FIX}..origin/master',
          '--grep', r'break', '-i', '--', 'src/vm.c') or '(none)')

head('later commits that touch mark_context_stack (src/gc.c, break-value reachability)')
print(git('log', '--oneline', '--format=%H %cI %s', f'{FIX}..origin/master',
          '-S', 'mark_context_stack', '--', 'src/gc.c') or '(none)')

head(f'named follow-up {FOLLOWUP} (OP_RETURN/OP_BREAK rework)')
meta = git('show', '-s', '--format=%H%n%an%n%cI%n%s', FOLLOWUP)
print(meta or '(commit not present in clone)')
if meta:
    print('on master' if subprocess.run(['git', '-C', repo, 'merge-base', '--is-ancestor', FOLLOWUP, 'origin/master']).returncode == 0
          else 'NOT on master')

head('the cci break branch on origin/master (how v is handled now)')
src = git('show', 'origin/master:src/vm.c')
lines = src.splitlines()
for i, l in enumerate(lines):
    if 'cci > CINFO_NONE' in l and 'break' not in l.lower():
        # print a window around the branch that contains break_new / arena_restore
        window = lines[i:i + 14]
        if any('break_new' in w for w in window):
            for w in window:
                print(w)
            break
