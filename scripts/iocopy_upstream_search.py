#!/usr/bin/env python3
"""Search upstream mruby around the mruby.cve-2018-10199 fix.

Usage: iocopy_upstream_search.py <mruby clone>

<mruby clone> is a full clone of https://github.com/mruby/mruby with every
branch and tag, and the pull request heads fetched as refs/remotes/origin/pr/<n>
(git clone https://github.com/mruby/mruby; cd mruby;
 git fetch origin '+refs/pull/*/head:refs/remotes/origin/pr/*'). Local paths are
not printed. The GitHub search uses the gh CLI.

The CVE_NVD developer patch is upstream commit
  b51b21fc63c9805862322551387d9036f2b63433 ("Fix `use after free in
  File#initilialize_copy`; fix #4001", 2018-04-17), whose parent is the SEC-bench
  base fabc460880fbabd18369a7ef8715538c83ebffc9. In mrb_io_initialize_copy()
  (mrbgems/mruby-io/src/io.c) it moves `fptr_orig = io_get_open_fptr(mrb, orig);`
  to right after mrb_get_args, so the argument validation (and its possible raise)
  happens before the receiver's old struct is freed.

The known follow-up is c9275bbbed36478283f3b0d1737b4ba5583d3023
  ("`mrb_io_initialize_copy` should not free existing `fptr`; fix #4005",
  2018-04-18), which adds `if (fptr_orig == fptr_copy) return copy;` to fix the
  self copy (orig and copy the same object), a use-after-free that the developer
  patch does not fix.

The search records: the fix metadata, that it is on master, the release tags of
the fix and the base, the follow-up c9275bbb metadata and its first release,
later commits on any ref that change mrb_io_initialize_copy in io.c (pickaxe),
commit messages that name the CVE or issues #4001/#4005, GitHub issues and pull
requests that name them, and the form of the initialize_copy routine at
origin/master (renamed io_init_copy there).
"""
import datetime
import subprocess
import sys

repo = sys.argv[1]
FIX = 'b51b21fc63c9805862322551387d9036f2b63433'
BASE = 'fabc460880fbabd18369a7ef8715538c83ebffc9'
FOLLOWUP = 'c9275bbbed36478283f3b0d1737b4ba5583d3023'
CVE = 'CVE-2018-10199'
ISSUE = '4001'
ISSUE2 = '4005'
FILE = 'mrbgems/mruby-io/src/io.c'
FUNCS = ('mrb_io_initialize_copy', 'io_init_copy')


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


print(f'# iocopy_upstream_search {CVE}  {now()}')
print(f'# fix {FIX}  (CVE_NVD developers_patch; changed lines != SEC-bench gold)')
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
for name, c in (('fix', FIX), ('base', BASE), ('follow-up c9275bbb', FOLLOWUP)):
    tags = git('tag', '--contains', c, '--sort=creatordate').split()
    print(f'{name}: first {tags[0] if tags else "(none)"}; all: {" ".join(tags[:12])}')

head('follow-up c9275bbb (#4005 self copy) metadata')
print(git('show', '-s', '--format=%H%n%an%n%aI%n%s%n%b', FOLLOWUP))
print('files: ' + ' '.join(git('show', '--format=', '--name-only', FOLLOWUP).split()))
print('on master: ' + str(ok('merge-base', '--is-ancestor', FOLLOWUP, 'origin/master')))
print('commits fix..follow-up: ' + git('rev-list', '--count', f'{FIX}..{FOLLOWUP}'))
print('fix is ancestor of follow-up: ' + str(ok('merge-base', '--is-ancestor', FIX, FOLLOWUP)))

head('commits on any ref, after the base, that change mrb_io_initialize_copy (pickaxe)')
seen = {}
for pat in ('io_get_open_fptr', 'fptr_orig == fptr_copy', 'mrb_io_initialize_copy', 'io_init_copy'):
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
hits = git('log', '--all', '--format=%H %aI %s', '-i', '--grep', CVE, '--grep', '10199',
           '--grep', f'#{ISSUE}', '--grep', f'#{ISSUE2}', '--grep', FIX[:12])
print(hits or '(none)')

head('GitHub issues and pull requests that name the CVE or the fix (gh search)')
for q in (CVE, '10199', FIX[:12]):
    out = run('gh', 'api', '-X', 'GET', 'search/issues', '-f', f'q=repo:mruby/mruby {q}',
              '--jq', '[.total_count, [.items[] | (.number|tostring) + " " + .title]]')
    print(f'{q}: {out or "(no response)"}')

head(f'commits that closed the fix and the follow-up (GitHub API pulls)')
for name, c in (('fix', FIX), ('follow-up', FOLLOWUP)):
    print(f'{name} {c[:12]}: ' + (run('gh', 'api', f'repos/mruby/mruby/commits/{c}/pulls', '--jq',
          '[.[] | {number, title, merged_at}]') or '(no response)'))

head('mrbgems/mruby-io/src/io.c commits after the fix (origin/master)')
print(f'{FILE}: ' + git('rev-list', '--count', f'{FIX}..origin/master', '--', FILE) + ' commits')

head('initialize_copy routine at origin/master')
path = None
for fn in FUNCS:
    loc = git('grep', '-l', f'{fn}(mrb_state', 'origin/master', '--', FILE)
    for line in loc.splitlines():
        if ':' in line:
            path = line.split(':', 1)[1]
            func = fn
            break
    if path:
        break
if path is None:
    print('initialize_copy routine: not found at origin/master by signature search')
else:
    src = git('show', f'origin/master:{path}')
    lines = src.splitlines()
    start = next((i for i, l in enumerate(lines) if l.startswith(f'{func}(')), None)
    if start is None:
        print(f'{path}: present; no {func}() at column 0')
    else:
        end = next((i for i in range(start, len(lines)) if lines[i] == '}'), start)
        print(f'{path}: {func}() at lines {start + 1}-{end + 1}:')
        for i in range(max(0, start - 1), end + 1):
            print(f'   {i + 1}: {lines[i]}')
