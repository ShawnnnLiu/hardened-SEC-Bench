#!/usr/bin/env python3
"""Search upstream mruby for the fix of the mruby.cve-2022-0326 root cause
(gen_hash() emitting stack operations for a discarded value, i.e. a `**` splat
in a hash/keyword-hash literal in value-less (NOVAL) position, which corrupts
the compiler stack pointer; the dataset PoC reaches a NULL dereference in
iv_free at exit-time garbage collection).

Usage: novalgc_upstream_search.py <mruby clone> <github data dir>

<mruby clone> is a full clone of https://github.com/mruby/mruby with every
branch, tag and refs/pull/*/head fetched. <github data dir> holds the raw
JSONL of issues, pulls and comments of mruby/mruby (issues.jsonl,
pulls.jsonl, issue_comments.jsonl, review_comments.jsonl,
commit_comments.jsonl). Local paths are not printed.

Hypothesis: the reported failure is the final-OP_HASHADD branch (F) of
gen_hash() moving the stack pointer for a discarded `**`-splat literal. The
developer patch b611c43a5 (2022-01-21, "no OP_HASHADD required when val is
false") is itself the upstream fix of that branch; its parent is the base
adb16fc6. The K and C branches (a pair before a `**`, the OP_HASHCAT after a
`**`) stay unguarded after it and are fixed upstream by the separate commit
ae3c99767 (2022-02-03, "fixed a bug in hash code generation with !val"), 13
days later. Both add `val &&` guards. The base adb16fc6 (2022-01-21) contains
neither; at origin/master the legacy compiler is replaced by the prism front
end (mrbgems/mruby-compiler/src/codegen.c), whose gen_hash carries the guards.
"""
import datetime, json, os, subprocess, sys

repo, ghdir = sys.argv[1], sys.argv[2]
BASE = 'adb16fc6dfc27a39b783782e3a12d877e71c78ac'
DEV = 'b611c43a5de061ec21b343967e1b64c45c373d7e'
FIXES = ['b611c43a5de061ec21b343967e1b64c45c373d7e',   # !val final block (F) = developer patch
         'ae3c99767a27f5c6c584162e2adc6a5d0eb2c54e']   # !val KW_REST blocks (K, C)
LEGACY = 'mrbgems/mruby-compiler/core/codegen.c'
PRISM = 'mrbgems/mruby-compiler/src/codegen.c'
CVE = 'CVE-2022-0326'
HUNTR = '795dcbd9-1695-44bb-8c59-ad327c97c976'


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def git(*a):
    return subprocess.run(['git', '-C', repo, *a], capture_output=True,
                          text=True, errors='replace').stdout


def section(t):
    print('\n' + '=' * 8 + ' ' + t)


def is_ancestor(a, b):
    return subprocess.run(['git', '-C', repo, 'merge-base', '--is-ancestor', a, b]).returncode == 0


print(f'novalgc_upstream_search for {CVE} run at {now()}')

section('clone')
master = git('rev-parse', 'origin/master').strip()
print('origin/master:', master, git('log', '-1', '--format=%ci %s', master).strip())
refs = git('for-each-ref', '--format=%(refname)').splitlines()
kinds = {}
for r in refs:
    k = '/'.join(r.split('/')[1:3])
    kinds[k.split('/')[0]] = kinds.get(k.split('/')[0], 0) + 1
print('ref kinds:', {k: sum(1 for r in refs if r.split('/')[1] == k) for k in ('heads', 'remotes', 'tags')})
print('pull heads:', sum(1 for r in refs if '/pr/' in r))
print('total commits (--all):', git('rev-list', '--count', '--all').strip())

section('base, developer patch and the fix commits')
for name, h in [('base', BASE), ('developer patch', DEV)] + [(f'fix {i+1}', f) for i, f in enumerate(FIXES)]:
    print(f'-- {name}: {git("log", "-1", "--format=%H %ci %s", h).strip()}')
print('developer patch parent:', git('rev-parse', DEV + '^').strip())
print('developer patch parent (== base?):', git('rev-parse', DEV + '^').strip(), '==', BASE,
      git('rev-parse', DEV + '^').strip() == BASE)
for f in FIXES:
    print(f'fix {f[:9]} is already in base?', is_ancestor(f, BASE),
          '| base is ancestor of fix?', is_ancestor(BASE, f))

section('gen_hash() !val guards: base vs after the fixes')
print('-- base gen_hash branch conditions (no `val &&`):')
base_src = git('show', f'{BASE}:{LEGACY}')
for i, line in enumerate(base_src.splitlines(), 1):
    s = line.strip()
    if s in ('if (len > 0) {', 'if (len > 0 || update) {') and 1590 < i < 1660:
        print(f'   {i}: {s}')
print('-- after both fixes (at fix 2 ae3c99767):')
fix_src = git('show', f'{FIXES[1]}:{LEGACY}')
for line in fix_src.splitlines():
    s = line.strip()
    if s.startswith('if (val && len > 0)') or s.startswith('if (val && (len > 0'):
        print(f'   {s}')

section('history of the gen_hash keyword/!val region after the base')
hist = git('log', '--oneline', '--reverse', f'{BASE}..origin/master', '--', LEGACY).splitlines()
print(f'{len(hist)} commits touch {LEGACY} between base and master; the ones that change the')
print('gen_hash() !val / keyword-rest handling:')
for h in hist:
    sha = h.split()[0]
    msg = h.split(' ', 1)[1] if ' ' in h else ''
    if any(w in msg.lower() for w in ('!val', 'val is false', 'hash code generation', 'hashadd', 'kw_rest', 'keyword')):
        print('  ', h)

section('form at origin/master')
has_legacy = bool(git('ls-tree', 'origin/master', LEGACY).strip())
has_prism = bool(git('ls-tree', 'origin/master', PRISM).strip())
print(f'legacy {LEGACY} present at master: {has_legacy}')
print(f'prism  {PRISM} present at master: {has_prism}')
src = git('show', f'origin/master:{PRISM}') if has_prism else (git('show', f'origin/master:{LEGACY}') if has_legacy else '')
if 'gen_hash' in src:
    lines = src.splitlines()
    gi = next((i for i, l in enumerate(lines) if l.startswith('gen_hash')), None)
    if gi is not None:
        seg = '\n'.join(lines[gi:gi + 90])
        print('master gen_hash guards `val &&` on the stack-op branches:',
              seg.count('if (val &&'), 'occurrence(s)')

section('CVE / huntr references')
cites = []
for fn in ('issues.jsonl', 'pulls.jsonl', 'issue_comments.jsonl', 'review_comments.jsonl', 'commit_comments.jsonl'):
    p = os.path.join(ghdir, fn)
    if not os.path.exists(p):
        print(f'  {fn}: absent'); continue
    n = hit = 0
    for line in open(p):
        n += 1
        if CVE in line or HUNTR in line or '2022-0326' in line:
            hit += 1
    print(f'  {fn}: {n} records, {hit} mention {CVE}/huntr')
print('commit messages on any ref mentioning the CVE or huntr id:')
print(' ', git('log', '--all', '--oneline', f'--grep={CVE}', f'--grep={HUNTR}').strip() or '  (none)')
print('the compiler-fix commit messages do not mention the CVE (they describe the !val bug):')
for f in FIXES:
    print('  ', git('log', '-1', '--format=%h %s', f).strip())

section('release tags: first release containing both fixes')
tags = [t for t in git('tag').splitlines() if t]
for t in sorted(tags):
    if is_ancestor(FIXES[0], t) and is_ancestor(FIXES[1], t):
        print('  first tag with both fixes:', t, git('log', '-1', '--format=%ci', t).strip())
        break
else:
    print('  no release tag contains both fixes')
print('first tag with the developer patch (F fix) only:')
for t in sorted(tags):
    if is_ancestor(FIXES[0], t):
        print('  ', t, git('log', '-1', '--format=%ci', t).strip())
        break
print('base release line (base', git('log', '-1', '--format=%ci', BASE).strip(), ')')
print('\ndone', now())
