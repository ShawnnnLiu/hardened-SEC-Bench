#!/usr/bin/env python3
"""Search upstream mruby around the mruby.cve-2022-0890 fix.

Usage: fiberpack_upstream_search.py <mruby clone>

<mruby clone> is a full clone of https://github.com/mruby/mruby with every
branch and tag fetched. Local paths are not printed. Only commit subjects (%s)
are printed, never message bodies.

For this instance the CVE_NVD developer patch IS the upstream fix:
  da48e7dbb20024c198493b8724adae1b842083aa ("fiber.c: should pack 15+ arguments
  in an array.", Matz, 2022-03-09), whose parent is the CVE_NVD base commit
  6e964bd1c6b1fcaab0d9fdcb3b87c7567b29d932. It rewrites the created-fiber start
  branch of fiber_switch (mrbgems/mruby-fiber/src/fiber.c): for len >= 15 it
  packs all arguments into one Array at c->stbase[1] (mrb_ary_new_from_values)
  and sets len = 15, so c->cibase->n = len stores the packed marker 15 with a
  real Array behind it, instead of copying the arguments individually and
  leaving OP_ENTER (src/vm.c) to read regs[1] as an Array.

The SEC-bench container is at c2f7ed514dfa0fcae2e7e72d51f25be3d3d6d72c, 6
commits before the CVE_NVD base; those commits touch only pack.c, sleep.c,
socket.c, src/array.c and src/string.c, so fiber.c and src/vm.c are identical
at both and the fix applies at the container base.

The search records: the fix metadata, that it is on master, the release tags of
the base and the fix, and later commits that touch the created branch of
fiber_switch or the argc == 15 branch of OP_ENTER, to check for a follow-up fix
of the same 4-bit-count invariant.
"""
import datetime, subprocess, sys

repo = sys.argv[1]
BASE = '6e964bd1c6b1fcaab0d9fdcb3b87c7567b29d932'    # CVE_NVD base (= da48e7db~1)
CBASE = 'c2f7ed514dfa0fcae2e7e72d51f25be3d3d6d72c'   # SEC-bench container base
FIX = 'da48e7dbb20024c198493b8724adae1b842083aa'     # developer patch == upstream fix
CVE = 'CVE-2022-0890'
HUNTR = '68e09ec1-6cc7-48b8-981d-30f478c70276'
FIBER = 'mrbgems/mruby-fiber/src/fiber.c'


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def git(*a):
    return subprocess.run(['git', '-C', repo, *a], capture_output=True, text=True,
                          errors='replace').stdout.rstrip('\n')


def is_anc(a, b):
    return subprocess.run(['git', '-C', repo, 'merge-base', '--is-ancestor', a, b]).returncode == 0


def head(t):
    print('\n== ' + t)


print(f'# fiberpack_upstream_search {CVE} (huntr {HUNTR})  {now()}')
print(f'# CVE_NVD base {BASE}  (= da48e7db~1)')
print(f'# container base {CBASE}  (SEC-bench base, 6 commits before; fiber.c and src/vm.c identical at both)')
print(f'# dev/fix {FIX}  (CVE_NVD developers_patch == SEC-bench gold == upstream fix)')

head('fix metadata')
print(git('show', '-s', '--format=%H%n%an%n%cI%n%s', FIX))
print('parent: ' + git('rev-parse', f'{FIX}^'))
print(f'parent == CVE_NVD base: {git("rev-parse", f"{FIX}^") == BASE}')

head('container base vs CVE_NVD base')
print(f'container base ancestor of CVE_NVD base: {is_anc(CBASE, BASE)}; '
      f'commits {CBASE}..{BASE} = ' + git('rev-list', '--count', f'{CBASE}..{BASE}'))
print('files changed container-base..CVE_NVD-base:')
print(git('diff', '--name-only', CBASE, BASE))
print('fiber.c identical at both: ' + ('yes' if not git('diff', CBASE, BASE, '--', FIBER) else 'NO'))
print('src/vm.c identical at both: ' + ('yes' if not git('diff', CBASE, BASE, '--', 'src/vm.c') else 'NO'))

head('fix is on origin/master')
print('on master' if is_anc(FIX, 'origin/master') else 'NOT on master')

head('first release tags (sorted by creation)')
for name, c in (('container base', CBASE), ('CVE_NVD base', BASE), ('fix', FIX)):
    print(f'{name}: ' + (git('tag', '--contains', c, '--sort=creatordate').split('\n')[0] or '(none)'))

head('later commits that change the created branch of fiber_switch (pickaxe on fiber.c)')
for s in ('mrb_ary_new_from_values', 'cibase->n', 'MRB_FIBER_CREATED'):
    out = git('log', '--format=%H %cI %s', f'{FIX}..origin/master', '-S', s, '--', FIBER)
    print(f'-- pickaxe "{s}":')
    print(out or '(none)')

head('later commits on src/vm.c near the argc == 15 OP_ENTER branch (pickaxe)')
print(git('log', '--format=%H %cI %s', f'{FIX}..origin/master', '-S', 'argc == 15', '--', 'src/vm.c')
      or '(none for this pickaxe)')

head('created-fiber start branch of fiber_switch on origin/master')
src = git('show', 'origin/master:' + FIBER)
lines = src.splitlines()
for i, l in enumerate(lines):
    if 'MRB_FIBER_CREATED' in l:
        for l2 in lines[i:i + 22]:
            print(l2)
        break
