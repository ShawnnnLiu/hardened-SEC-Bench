#!/usr/bin/env python3
"""Search upstream mruby around the mruby.cve-2022-1286 fix and its follow-ups.

Usage: mcache_upstream_search.py <mruby clone>

<mruby clone> is a full clone of https://github.com/mruby/mruby with every
branch, tag and refs/pull/*/head fetched. Local paths are not printed.

The CVE_NVD developer patch is b1d0296a937fe278239bdfac840a3fd0e93b3ee9
("class.c: clear method cache after `remove_method`.", 2022-04-09), whose parent
is the base commit c30e6ebe. It adds mrb_mc_clear_by_class(mrb, c) after a
successful mt_del in mrb_remove_method (src/class.c). mrb_mc_clear_by_class
clears the whole cache only if c has MRB_FL_CLASS_IS_INHERITED, otherwise only
entries with mc->c == c, so a cache entry whose method was found in c through a
subclass search (mc->c == subclass, mc->c0 == c) survives when c lacks the flag
(BasicObject). The developer patch does not fix that root cause.

Upstream later fixed it:
  a99e4a926d22188aea72ed030b8d4c31535b4eeb ("class.c (mrb_mc_clear_by_class):
    simplify method cache clear condition.", 2022-07-05): always clears entries
    with mc->c == c || mc->c0 == c (drops the flag special case).
  638356af03a00a7edce4e108084d10dab0a42028 ("class.c (mc_clear_by_id): clear
    method cache with method id specified.", 2022-07-05): mrb_remove_method and
    mrb_define_method_raw clear by method id.

The search records the distance from the developer fix to each follow-up, the
pull requests, release tags, and whether the messages name the CVE.
"""
import datetime, subprocess, sys

repo = sys.argv[1]
BASE = 'c30e6ebe1200962d37751255ca489defd96819d6'
FIX = 'b1d0296a937fe278239bdfac840a3fd0e93b3ee9'   # developer patch (not the root fix)
ROOTS = ['a99e4a926d22188aea72ed030b8d4c31535b4eeb',
         '638356af03a00a7edce4e108084d10dab0a42028']
CVE = 'CVE-2022-1286'
HUNTR = 'f918376e-b488-4113-963d-ffe8716e4189'


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def git(*a):
    return subprocess.run(['git', '-C', repo, *a], capture_output=True, text=True,
                          errors='replace').stdout.rstrip('\n')


def head(t):
    print('\n== ' + t)


def on_master(h):
    return subprocess.run(['git', '-C', repo, 'merge-base', '--is-ancestor', h, 'origin/master']).returncode == 0


print(f'# mcache_upstream_search {CVE} (huntr {HUNTR})  {now()}')
print(f'# base {BASE}')
print(f'# dev/fix {FIX}  (developer patch; parent is the base; does NOT fix the root cause)')

head('developer fix metadata')
print(git('show', '-s', '--format=%H%n%an%n%cI%n%s', FIX))
print('parent: ' + git('rev-parse', f'{FIX}^'))
print('on master' if on_master(FIX) else 'NOT on master')
print('first release tags:'); print(git('tag', '--contains', FIX, '--sort=creatordate'))

for R in ROOTS:
    head(f'root follow-up {R[:12]}')
    print(git('show', '-s', '--format=%H%n%an%n%cI%n%s', R))
    print('on master' if on_master(R) else 'NOT on master')
    print('commits dev..root: ' + git('rev-list', '--count', f'{FIX}..{R}'))
    print('first release tags:'); print(git('tag', '--contains', R, '--sort=creatordate'))
    print('message names the CVE/huntr/issue: ' +
          str(any(s in git('show', '-s', '--format=%B', R) for s in (CVE, '1286', HUNTR, 'huntr'))))

head('later commits on src/class.c touching mrb_mc_clear_by_class or the clear condition (dev..master)')
for s in ('mrb_mc_clear_by_class', 'mc->c0', 'mc_clear_by_id'):
    print(f'-- pickaxe {s}:')
    print(git('log', '--oneline', '--format=%H %cI %s', f'{FIX}..origin/master',
              '-S', s, '--', 'src/class.c') or '(none)')

head('mrb_mc_clear_by_class on origin/master')
src = git('show', 'origin/master:src/class.c')
lines = src.splitlines()
for i, l in enumerate(lines):
    if 'mrb_mc_clear_by_class' in l and l.rstrip().endswith('c)'):
        for l2 in lines[i-1:i+14]:
            print(l2)
        break
