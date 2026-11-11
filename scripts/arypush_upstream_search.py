#!/usr/bin/env python3
"""Search upstream mruby around the mruby.cve-2022-0717 fix.

Usage: arypush_upstream_search.py <mruby clone>

<mruby clone> is a full clone of https://github.com/mruby/mruby with every
branch and tag, and the pull request heads fetched as
refs/remotes/origin/pr/<n> (git fetch origin '+refs/pull/*/head:refs/remotes/origin/pr/*').
Local paths are not printed. The GitHub search uses the gh CLI.

The CVE_NVD developer patch is upstream commit
  f72315575f78a9a773adbce0ee7d3ec33434cb76 ("codegen.c: fix a argument
  generation bug in array assignment.", 2022-02-22), whose parent is the
  SEC-bench base 349307ba. In the call branch of gen_assignment() it replaces
  `if (n < 14) { n++; }` after the right-hand side by `if (n < 15) { n++;
  if (n == 15) { pop_n(14); genop_2(s, OP_ARRAY, cursp(), 15); } }`, so 14
  register arguments plus the right-hand side are packed into one array
  instead of the right-hand side being appended to the 14th argument with
  OP_ARYPUSH.

The search records: the fix metadata, that it is on master, the release tags
of the fix and the base, later commits on any ref that change the
post-right-hand-side branch or the keyword branch before it, the relation to
c8c083cb75 (the CVE_NVD developers_patch of mruby.cve-2022-1276, which packs
13 positional arguments before a keyword hash), commit messages that name
the CVE or the huntr report, GitHub issues and pull requests that name them,
and the form of the branch at origin/master.
"""
import datetime, json, subprocess, sys

repo = sys.argv[1]
FIX = 'f72315575f78a9a773adbce0ee7d3ec33434cb76'
BASE = '349307ba884740b132dcf08dfb615c0f329d2579'
FIX1276 = 'c8c083cb750606b2da81582cd8e43b442bb143e6'
CVE = 'CVE-2022-0717'
HUNTR = '27a851a5-7ebf-409b-854f-b2614771e8f9'
LEGACY = ['mrbgems/mruby-compiler/core/codegen.c',
          'mrbgems/mruby-compiler-lrama/core/codegen.c',
          'src/codegen.c']
PRISM = ['mrbgems/mruby-compiler/src/codegen.c',
         'mrbgems/mruby-compiler-prism/src/codegen.c']


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def run(*a):
    return subprocess.run(list(a), capture_output=True, text=True, errors='replace').stdout.rstrip('\n')


def git(*a):
    return run('git', '-C', repo, *a)


def ok(*a):
    return subprocess.run(['git', '-C', repo, *a], capture_output=True).returncode == 0


def head(t):
    print('\n== ' + t)


print(f'# arypush_upstream_search {CVE}  {now()}')
print(f'# fix {FIX}  (CVE_NVD developers_patch; changed lines == SEC-bench gold)')
print(f'# base {BASE}  (SEC-bench base, image HEAD)')
print(f'# origin/master {git("rev-parse", "origin/master")} {git("show", "-s", "--format=%cI", "origin/master")}')
refs = git('for-each-ref', '--format=%(refname)').splitlines()
print(f'# refs: {sum(r.startswith("refs/remotes/origin/pr/") for r in refs)} pull request heads, '
      f'{sum(r.startswith("refs/tags/") for r in refs)} tags, '
      f'{sum(r.startswith("refs/remotes/origin/") and not r.startswith("refs/remotes/origin/pr/") for r in refs)} remote branches')

head('fix metadata')
print(git('show', '-s', '--format=%H%n%an%n%aI%n%s', FIX))
print('files: ' + ' '.join(git('show', '--format=', '--name-only', FIX).split()))

head('fix parent')
print('parent: ' + git('rev-parse', f'{FIX}^') + ('  (= base)' if git('rev-parse', f'{FIX}^') == BASE else '  (!= base)'))

head('fix is on origin/master')
print('on master' if ok('merge-base', '--is-ancestor', FIX, 'origin/master') else 'NOT on master')

head('first release tags (sorted by creation)')
for name, c in (('fix', FIX), ('base', BASE)):
    tags = git('tag', '--contains', c, '--sort=creatordate').split()
    print(f'{name}: first {tags[0] if tags else "(none)"}; all: {" ".join(tags)}')

head('mruby.cve-2022-1276 developer patch c8c083cb75')
print(git('show', '-s', '--format=%H%n%an%n%aI%n%s', FIX1276))
print('fix is an ancestor of c8c083cb75: ' + str(ok('merge-base', '--is-ancestor', FIX, FIX1276)))
print(f'commits {FIX[:10]}..{FIX1276[:10]} = ' + git('rev-list', '--count', f'{FIX}..{FIX1276}'))
d0 = datetime.datetime.fromisoformat(git('show', '-s', '--format=%aI', FIX))
d1 = datetime.datetime.fromisoformat(git('show', '-s', '--format=%aI', FIX1276))
print(f'author-date days apart = {(d1 - d0).days}')
print('same author: ' + str(git('show', '-s', '--format=%an', FIX) == git('show', '-s', '--format=%an', FIX1276)))
tags = git('tag', '--contains', FIX1276, '--sort=creatordate').split()
print(f'first release tag: {tags[0] if tags else "(none)"}')
msg = git('show', '-s', '--format=%B', FIX1276)
print('message names 0717, its CVE or the huntr report: ' + str(any(k in msg for k in ('0717', HUNTR, 'huntr'))))

head('commits on any ref, after the fix, that change the post-rhs pack or the keyword branch (pickaxe)')
seen = {}
for pat in ('genop_2(s, OP_ARRAY, cursp(), 15)', 'if (n < 15) {', 'if (n == 13 || n == 14)',
            'pop_n(14);'):
    for line in git('log', '--all', '--format=%H %aI %s', '-S', pat, '--', *LEGACY, *PRISM).splitlines():
        h = line.split()[0]
        if h != FIX and not ok('merge-base', '--is-ancestor', h, BASE):
            seen.setdefault(h, (line, set()))[1].add(pat)
for h, (line, pats) in sorted(seen.items(), key=lambda kv: kv[1][0].split()[1]):
    onm = 'master' if ok('merge-base', '--is-ancestor', h, 'origin/master') else 'not on master'
    print(f'{line[:110]}  [{onm}; strings: {sorted(pats)}]')
if not seen:
    print('(none)')

head(f'commit messages on any ref that name {CVE}, the huntr report or the fix')
hits = git('log', '--all', '--format=%H %aI %s', '-i', '--grep', 'CVE-2022-0717', '--grep', HUNTR,
           '--grep', '27a851a5', '--grep', 'f72315575')
print(hits or '(none)')

head('GitHub issues and pull requests that name the CVE or the huntr report (gh search)')
for q in (CVE, HUNTR, 'f72315575'):
    out = run('gh', 'api', '-X', 'GET', 'search/issues', '-f', f'q=repo:mruby/mruby {q}',
              '--jq', '[.total_count, [.items[] | (.number|tostring) + " " + .title]]')
    print(f'{q}: {out or "(no response)"}')

head('legacy codegen.c commits after the fix (origin/master)')
for p in LEGACY:
    n = git('rev-list', '--count', f'{FIX}..origin/master', '--', p)
    print(f'{p}: {n} commits')

head('index assignment argument packing at origin/master')
for p in LEGACY + PRISM:
    src = git('show', f'origin/master:{p}')
    if not src:
        print(f'{p}: not present at origin/master')
        continue
    lines = src.splitlines()
    start = next((i for i, l in enumerate(lines) if l.startswith('gen_call_assign(')), None)
    if start is None:
        print(f'{p}: present; no gen_call_assign()')
        continue
    end = next(i for i in range(start, len(lines)) if lines[i] == '}')
    print(f'{p}: gen_call_assign() at lines {start + 1}-{end + 1}; the lines that gather or count the arguments:')
    for i in range(start, end + 1):
        if any(k in lines[i] for k in ('gen_values_upto', 'gathered = 1', 'OP_ARYPUSH',
                                       'n = CALL_MAXARGS', 'if (!gathered) n++')):
            print(f'   {i + 1}: {lines[i].strip()}')
