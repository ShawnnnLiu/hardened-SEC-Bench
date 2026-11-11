#!/usr/bin/env python3
"""Search upstream mruby around the mruby.cve-2018-11743 fix.

Usage: iclass_upstream_search.py <mruby clone>

<mruby clone> is a full clone of https://github.com/mruby/mruby with every
branch and tag, and the pull request heads fetched as refs/remotes/origin/pr/<n>
(git clone https://github.com/mruby/mruby; cd mruby;
 git fetch origin '+refs/pull/*/head:refs/remotes/origin/pr/*'). Local paths are
not printed. The GitHub search uses the gh CLI.

The CVE_NVD developer patch is upstream commit
  b64ce17852b180dfeea81cf458660be41a78974d ("Should not call initialize_copy for
  TT_ICLASS; fix #4027", 2018-05-30), whose parent is the SEC-bench base
  1dddc2f712f774b22a8f65432299cebb3b26361b. In init_copy() (src/kernel.c) it
  adds `case MRB_TT_ICLASS: copy_class(mrb, dest, obj); return;` before the
  MRB_TT_CLASS/MRB_TT_MODULE case, so init_copy never dispatches initialize_copy
  on a TT_ICLASS object.

The search records: the fix metadata, that it is on master, the release tags of
the fix and the base, later commits on any ref that change init_copy or
copy_class in src/kernel.c (pickaxe MRB_TT_ICLASS, initialize_copy, copy_class),
the relation to the sibling kernel.c/class.c NULL-deref CVE fixes
mruby.cve-2018-12247 (55edae02) and mruby.cve-2018-12249 (faa4eaf6), commit
messages that name the CVE or issue #4027, GitHub issues and pull requests that
name them, and the form of init_copy at origin/master.
"""
import datetime
import subprocess
import sys

repo = sys.argv[1]
FIX = 'b64ce17852b180dfeea81cf458660be41a78974d'
BASE = '1dddc2f712f774b22a8f65432299cebb3b26361b'
FIX12247 = '55edae0226409de25e59922807cb09acb45731a2'
FIX12249 = 'faa4eaf6803bd11669bc324b4c34e7162286bfa3'
CVE = 'CVE-2018-11743'
ISSUE = '4027'
FILE = 'src/kernel.c'


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


print(f'# iclass_upstream_search {CVE}  {now()}')
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
par = git('rev-parse', f'{FIX}^')
print('parent: ' + par + ('  (= base)' if par == BASE else '  (!= base)'))

head('fix is on origin/master')
print('on master' if ok('merge-base', '--is-ancestor', FIX, 'origin/master') else 'NOT on master')

head('first release tags (sorted by creation)')
for name, c in (('fix', FIX), ('base', BASE)):
    tags = git('tag', '--contains', c, '--sort=creatordate').split()
    print(f'{name}: first {tags[0] if tags else "(none)"}; all: {" ".join(tags[:12])}')

head('sibling kernel.c/class.c NULL-deref CVE fixes')
for name, c in (('mruby.cve-2018-12247 55edae02', FIX12247), ('mruby.cve-2018-12249 faa4eaf6', FIX12249)):
    if not ok('cat-file', '-e', c):
        print(f'{name}: not in this clone'); continue
    print(f'{name}: ' + git('show', '-s', '--format=%aI %s', c))
    print('  files: ' + ' '.join(git('show', '--format=', '--name-only', c).split()))
    print('  ancestor of the fix: ' + str(ok('merge-base', '--is-ancestor', c, FIX))
          + '; fix ancestor of it: ' + str(ok('merge-base', '--is-ancestor', FIX, c)))

head('commits on any ref, after the base, that change init_copy or copy_class (pickaxe)')
seen = {}
for pat in ('MRB_TT_ICLASS', 'copy_class(mrb, dest, obj)', 'init_copy',
            '"initialize_copy"'):
    for line in git('log', '--all', '--format=%H %aI %s', '-S', pat, '--', FILE).splitlines():
        h = line.split()[0]
        if h != FIX and not ok('merge-base', '--is-ancestor', h, BASE):
            seen.setdefault(h, (line, set()))[1].add(pat)
for h, (line, pats) in sorted(seen.items(), key=lambda kv: kv[1][0].split()[1]):
    onm = 'master' if ok('merge-base', '--is-ancestor', h, 'origin/master') else 'not on master'
    print(f'{line[:110]}  [{onm}; strings: {sorted(pats)}]')
if not seen:
    print('(none)')

head(f'commit messages on any ref that name {CVE}, issue #{ISSUE} or the fix')
hits = git('log', '--all', '--format=%H %aI %s', '-i', '--grep', CVE, '--grep', '11743',
           '--grep', f'#{ISSUE}', '--grep', FIX[:12])
print(hits or '(none)')

head('GitHub issues and pull requests that name the CVE or the fix (gh search)')
for q in (CVE, '11743', FIX[:12]):
    out = run('gh', 'api', '-X', 'GET', 'search/issues', '-f', f'q=repo:mruby/mruby {q}',
              '--jq', '[.total_count, [.items[] | (.number|tostring) + " " + .title]]')
    print(f'{q}: {out or "(no response)"}')

head('issue #4027 pulls (GitHub API) and the commit that closed it')
print(run('gh', 'api', f'repos/mruby/mruby/commits/{FIX}/pulls', '--jq',
          '[.[] | {number, title, merged_at}]') or '(no response)')

head('src/kernel.c commits after the fix (origin/master)')
print(f'{FILE}: ' + git('rev-list', '--count', f'{FIX}..origin/master', '--', FILE) + ' commits')

head('init_copy at origin/master')
src = git('show', f'origin/master:{FILE}')
if not src:
    print(f'{FILE}: not present at origin/master (search for init_copy elsewhere)')
else:
    lines = src.splitlines()
    start = next((i for i, l in enumerate(lines) if l.startswith('init_copy(')), None)
    if start is None:
        print(f'{FILE}: present; no init_copy() (it may have moved or been renamed)')
    else:
        end = next((i for i in range(start, len(lines)) if lines[i] == '}'), start)
        print(f'{FILE}: init_copy() at lines {start + 1}-{end + 1}; TT_ICLASS and initialize_copy lines:')
        for i in range(start, end + 1):
            if any(k in lines[i] for k in ('MRB_TT_ICLASS', 'initialize_copy', 'copy_class', 'return')):
                print(f'   {i + 1}: {lines[i].strip()}')
