#!/usr/bin/env python3
"""Search upstream mruby around the mruby.cve-2018-12249 fix.

Usage: classreal_upstream_search.py <mruby clone>

<mruby clone> is a full clone of https://github.com/mruby/mruby with every
branch and tag, and the pull request heads fetched as refs/remotes/origin/pr/<n>
(git clone https://github.com/mruby/mruby; cd mruby;
 git fetch origin '+refs/pull/*/head:refs/remotes/origin/pr/*'). Local paths are
not printed. The GitHub search uses the gh CLI.

The CVE_NVD developer patch is upstream commit
  faa4eaf6803bd11669bc324b4c34e7162286bfa3 ("mrb_class_real() did not work for
  BasicObject; fix #4037", 2018-06-08), whose parent is the SEC-bench base
  55edae0226409de25e59922807cb09acb45731a2 (the mruby.cve-2018-12247 fix). In
  mrb_class_real() (src/class.c) it adds `if (cl == 0) return NULL;` inside the
  SCLASS/ICLASS super-walk loop, so the walk stops at a NULL super instead of
  reading cl->tt of a NULL class.

The search records: the fix metadata, that it is on master, the release tags of
the fix and the base, later commits on any ref that change mrb_class_real in
src/class.c (pickaxe mrb_class_real, cl->super, the NULL check), the relation to
the sibling kernel.c/class.c NULL-deref CVE fixes mruby.cve-2018-11743
(b64ce178) and mruby.cve-2018-12247 (55edae02), commit messages that name the
CVE or issue #4037, GitHub issues and pull requests that name them, and the form
of mrb_class_real at origin/master.
"""
import datetime
import subprocess
import sys

repo = sys.argv[1]
FIX = 'faa4eaf6803bd11669bc324b4c34e7162286bfa3'
BASE = '55edae0226409de25e59922807cb09acb45731a2'
FIX11743 = 'b64ce17852b180dfeea81cf458660be41a78974d'
FIX12247 = '55edae0226409de25e59922807cb09acb45731a2'
CVE = 'CVE-2018-12249'
ISSUE = '4037'
FILE = 'src/class.c'
FUNC = 'mrb_class_real'


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


print(f'# classreal_upstream_search {CVE}  {now()}')
print(f'# fix {FIX}  (CVE_NVD developers_patch; changed lines == SEC-bench gold)')
print(f'# base {BASE}  (SEC-bench base, image HEAD; = mruby.cve-2018-12247 fix)')
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
for name, c in (('mruby.cve-2018-11743 b64ce178', FIX11743), ('mruby.cve-2018-12247 55edae02', FIX12247)):
    if not ok('cat-file', '-e', c):
        print(f'{name}: not in this clone'); continue
    print(f'{name}: ' + git('show', '-s', '--format=%aI %s', c))
    print('  files: ' + ' '.join(git('show', '--format=', '--name-only', c).split()))
    print('  ancestor of the fix: ' + str(ok('merge-base', '--is-ancestor', c, FIX))
          + '; fix ancestor of it: ' + str(ok('merge-base', '--is-ancestor', FIX, c)))

head('commits on any ref, after the base, that change mrb_class_real (pickaxe)')
seen = {}
for pat in ('mrb_class_real', 'cl->super', 'cl == 0', 'MRB_TT_SCLASS'):
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

head(f'commit messages on any ref that name {CVE}, issue #{ISSUE} or the fix')
hits = git('log', '--all', '--format=%H %aI %s', '-i', '--grep', CVE, '--grep', '12249',
           '--grep', f'#{ISSUE}', '--grep', FIX[:12])
print(hits or '(none)')

head('GitHub issues and pull requests that name the CVE or the fix (gh search)')
for q in (CVE, '12249', FIX[:12]):
    out = run('gh', 'api', '-X', 'GET', 'search/issues', '-f', f'q=repo:mruby/mruby {q}',
              '--jq', '[.total_count, [.items[] | (.number|tostring) + " " + .title]]')
    print(f'{q}: {out or "(no response)"}')

head(f'issue #{ISSUE} pulls (GitHub API) and the commit that closed it')
print(run('gh', 'api', f'repos/mruby/mruby/commits/{FIX}/pulls', '--jq',
          '[.[] | {number, title, merged_at}]') or '(no response)')

head('src/class.c commits after the fix (origin/master)')
print(f'{FILE}: ' + git('rev-list', '--count', f'{FIX}..origin/master', '--', FILE) + ' commits')

head('mrb_class_real at origin/master')
# mrb_class_real may have moved files on master; locate it first.
loc = git('grep', '-l', f'{FUNC}(struct RClass', 'origin/master')
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
        for i in range(max(0, start - 1), end + 1):
            print(f'   {i + 1}: {lines[i]}')
