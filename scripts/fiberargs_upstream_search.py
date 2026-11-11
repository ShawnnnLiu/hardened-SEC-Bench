#!/usr/bin/env python3
"""Search upstream mruby around the mruby.cve-2018-12248 fix.

Usage: fiberargs_upstream_search.py <mruby clone>

<mruby clone> is a full clone of https://github.com/mruby/mruby with every branch
and tag, and the pull request heads fetched as refs/remotes/origin/pr/<n>. Local
paths are not printed. The GitHub search uses the gh CLI.

The CVE_NVD developer patch is upstream commit
  778500563a9f7ceba996937dc886bd8cde29b42b ("Extend stack when pushing arguments
  that does not fit in; fix #4038", 2018-06-07), whose parent is the SEC-bench base
  ff0a4f78674308b7643db1da9b9dc591f25c21d0. In fiber_switch() (mrbgems/mruby-fiber/
  src/fiber.c) it replaces the FiberError check `len >= c->stend - c->stack` with
  mrb_stack_extend(mrb, len+2) for a new fiber, so the fiber's stack is sized for
  the receiver, the arguments and the block slot that OP_ENTER reads.

The known later change to the same stack handling is
  da48e7dbb... ("fiber.c: should pack 15+ arguments in an array.", 2022-03-09),
  the developer patch of mruby.cve-2022-0890, a different issue (the callinfo
  argument count became four bits). At ff0a4f78 the argument count is an int, so
  that packing defect does not exist on this base; da48e7dbb is recorded here only
  as the next change to fiber_switch's argument handling, not as a fix of a 12248
  residual.

The search records: the fix metadata, that it is on master, the release tags of
the fix and the base, later commits on any ref that change fiber_switch, commit
messages that name the CVE or issues #4038/#3641, GitHub issues and pull requests
that name them, and the form of fiber_switch at origin/master.
"""
import datetime
import subprocess
import sys

repo = sys.argv[1]
FIX = '778500563a9f7ceba996937dc886bd8cde29b42b'
BASE = 'ff0a4f78674308b7643db1da9b9dc591f25c21d0'
SIBLING = 'da48e7dbb'
CVE = 'CVE-2018-12248'
ISSUE = '4038'
ISSUE2 = '3641'
FILE = 'mrbgems/mruby-fiber/src/fiber.c'
FUNC = 'fiber_switch'


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


print(f'# fiberargs_upstream_search {CVE}  {now()}')
print(f'# fix {FIX}  (CVE_NVD developers_patch; changed lines != SEC-bench gold, gold is only hunk 2)')
print(f'# base {BASE}  (SEC-bench base, image HEAD, CVE_NVD base_commit = fix~1)')
print(f'# origin/master {git("rev-parse", "origin/master")} {git("show", "-s", "--format=%cI", "origin/master")}')
refs = git('for-each-ref', '--format=%(refname)').splitlines()
print(f'# refs: {sum(r.startswith("refs/remotes/origin/pr/") for r in refs)} pull request heads, '
      f'{sum(r.startswith("refs/tags/") for r in refs)} tags, '
      f'{sum(r.startswith("refs/remotes/origin/") and not r.startswith("refs/remotes/origin/pr/") for r in refs)} remote branches')

head('fix metadata')
print(git('show', '-s', '--format=%H%n%an%n%aI%n%s%n%b', FIX))
print('files: ' + ' '.join(git('show', '--format=', '--name-only', FIX).split()))

head('fix parent')
par = git('rev-parse', f'{FIX}^')
print('parent: ' + par + ('  (= base)' if par == BASE else '  (!= base)'))

head('fix is on origin/master')
print('on master' if ok('merge-base', '--is-ancestor', FIX, 'origin/master') else 'NOT on master')

head('first release tags (sorted by creation)')
for name, c in (('fix', FIX), ('base', BASE)):
    tags = git('tag', '--contains', c, '--sort=creatordate').split()
    print(f'{name}: first {tags[0] if tags else "(none)"}; all: {" ".join(tags[:12])}')

head('later change to the same stack handling (sibling da48e7dbb, mruby.cve-2022-0890)')
sib = git('rev-parse', SIBLING) if ok('rev-parse', SIBLING) else ''
if sib and ok('cat-file', '-e', sib):
    print(git('show', '-s', '--format=%H%n%aI%n%s', sib))
    print('on master: ' + str(ok('merge-base', '--is-ancestor', sib, 'origin/master')))
    print('commits fix..sibling: ' + git('rev-list', '--count', f'{FIX}..{sib}'))
else:
    print('sibling not resolved in this clone')

head('commits on any ref, after the base, that change fiber_switch (pickaxe)')
seen = {}
for pat in ('mrb_stack_extend', 'too many arguments to fiber', 'fiber_switch', 'c->stend - c->stack'):
    for line in git('log', '--all', '--format=%H %aI %s', '-S', pat, '--', FILE).splitlines():
        if not line:
            continue
        h = line.split()[0]
        if h != FIX and not ok('merge-base', '--is-ancestor', h, BASE):
            seen.setdefault(h, (line, set()))[1].add(pat)
for h, (line, pats) in sorted(seen.items(), key=lambda kv: kv[1][0].split()[1]):
    onm = 'master' if ok('merge-base', '--is-ancestor', h, 'origin/master') else 'not on master'
    print(f'{line[:110]}  [{onm}; strings: {sorted(pats)}]')
if not seen:
    print('(none)')

head(f'commit messages on any ref that name {CVE}, issue #{ISSUE}/#{ISSUE2} or the fix')
hits = git('log', '--all', '--format=%H %aI %s', '-i', '--grep', CVE, '--grep', '12248',
           '--grep', f'#{ISSUE}', '--grep', f'#{ISSUE2}', '--grep', FIX[:12])
print(hits or '(none)')

head('GitHub issues and pull requests that name the CVE or the fix (gh search)')
for q in (CVE, '12248', FIX[:12]):
    out = run('gh', 'api', '-X', 'GET', 'search/issues', '-f', f'q=repo:mruby/mruby {q}',
              '--jq', '[.total_count, [.items[] | (.number|tostring) + " " + .title]]')
    print(f'{q}: {out or "(no response)"}')

head('pull requests containing the fix (GitHub API)')
print(run('gh', 'api', f'repos/mruby/mruby/commits/{FIX}/pulls', '--jq',
          '[.[] | {number, title, merged_at}]') or '(no response)')

head('mrbgems/mruby-fiber/src/fiber.c commits after the fix (origin/master)')
print(f'{FILE}: ' + git('rev-list', '--count', f'{FIX}..origin/master', '--', FILE) + ' commits')

head('fiber_switch at origin/master')
loc = git('grep', '-l', f'{FUNC}(mrb_state', 'origin/master', '--', FILE)
path = None
for line in loc.splitlines():
    if ':' in line:
        path = line.split(':', 1)[1]
        break
if path is None:
    print(f'{FUNC}: not found at origin/master by signature search')
else:
    src = git('show', f'origin/master:{path}')
    lines = src.splitlines()
    start = next((i for i, l in enumerate(lines) if l.startswith(f'{FUNC}(')), None)
    if start is None:
        print(f'{path}: present; no {FUNC}() at column 0')
    else:
        end = next((i for i in range(start, len(lines)) if lines[i] == '}'), start)
        print(f'{path}: {FUNC}() at lines {start + 1}-{end + 1}:')
        for i in range(max(0, start - 1), min(end + 1, start + 60)):
            print(f'   {i + 1}: {lines[i]}')
