#!/usr/bin/env python3
"""Search upstream mruby for the fix of the mruby.cve-2022-1201 root cause
(a NULL target class used in the OP_SUPER handler when the proc target class
is a module or a prepended class).

Usage: supernull_upstream_search.py <mruby clone> <github data dir>

<mruby clone> is a full clone of https://github.com/mruby/mruby with every
branch, tag and refs/pull/*/head fetched. <github data dir> holds the raw
JSONL of issues, pulls and comments. Local paths are not printed.

The root cause (mrb_vm_ci_target_class(ci) may be NULL and is used without a
check in two OP_SUPER branches) was fixed upstream across two commits, both
after the base commit:
  00acae117 (2022-04-01, the CVE fix / developer patch) guards the
    MRB_TT_MODULE branch;
  a4d97934d (2022-04-22, "vm.c: check if target_class is NULL (when
    prepended).") merges the MRB_FL_CLASS_IS_PREPENDED branch into it, so the
    NULL + ICLASS check covers the prepended branch too.
The developer patch alone leaves the prepended branch crashing.
"""
import datetime, os, subprocess, sys

repo, ghdir = sys.argv[1], sys.argv[2]
BASE = 'd1f1b4ea38cd5a2a9d0b2aa3547d4f2828180299'
DEV = '00acae117da1b45b318dc36531a7b0021b8097ae'
PREP = 'a4d97934d51cb88954cc49161dc1d151f64afb6b'
LATER = ['92be161b1', '3bd2c56da']   # check_target_class hardening
CVE = 'CVE-2022-1201'
HUNTR = '6f930add-c9d8-4870-ae56-d4bd8354703b'


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def git(*a):
    return subprocess.run(['git', '-C', repo, *a], capture_output=True, text=True, errors='replace').stdout


def anc(a, b):
    return subprocess.run(['git', '-C', repo, 'merge-base', '--is-ancestor', a, b]).returncode == 0


def section(t):
    print('\n' + '=' * 8 + ' ' + t)


print(f'supernull_upstream_search for {CVE} run at {now()}')

section('clone')
master = git('rev-parse', 'origin/master').strip()
print('origin/master:', master, git('log', '-1', '--format=%ci %s', master).strip())
refs = git('for-each-ref', '--format=%(refname)').splitlines()
print('pull heads:', sum(1 for r in refs if '/pr/' in r), '| tags:', sum(1 for r in refs if r.startswith('refs/tags/')))
print('total commits (--all):', git('rev-list', '--count', '--all').strip())

section('base, developer patch and the prepended-branch fix')
for name, h in [('base', BASE), ('developer patch (CVE fix)', DEV), ('prepended-branch fix', PREP)]:
    print(f'-- {name}: {git("log", "-1", "--format=%H %ci %s", h).strip()}')
print('developer patch parent (== base?):', git('rev-parse', DEV + '^').strip(), '==', BASE,
      git('rev-parse', DEV + '^').strip() == BASE)
print('prepended fix a4d97934d: in base?', anc(PREP, BASE), '| after the CVE fix?', anc(DEV, PREP))

section('what each commit changes in the OP_SUPER branches')
print('-- developer patch 00acae117 (MRB_TT_MODULE branch gets `!target_class ||`):')
print(git('show', '--format=', DEV).strip())
print('-- prepended-branch fix a4d97934d (merges the two branches under one NULL + ICLASS check):')
print(git('show', '--format=', PREP).strip())

section('later NULL-target-class hardening (context, not needed for this CVE)')
for h in LATER:
    print('  ', git('log', '-1', '--format=%h %ci %s', h).strip())

section('form at origin/master')
src = git('show', f'origin/master:src/vm.c')
print('master OP_SUPER keeps a NULL target-class check:',
      'CI_TARGET_CLASS' in src or 'check_target_class' in src,
      '| !target_class occurrences in vm.c:', src.count('!target_class'))

section('release tags')
for t in sorted(git('tag').splitlines()):
    if t and anc(PREP, t):
        print('  first release tag containing a4d97934d:', t, git('log', '-1', '--format=%ci', t).strip())
        break
print('  developer CVE fix 00acae117 first tag:', end=' ')
for t in sorted(git('tag').splitlines()):
    if t and anc(DEV, t):
        print(t, git('log', '-1', '--format=%ci', t).strip()); break

section('CVE / huntr references')
for fn in ('issues.jsonl', 'pulls.jsonl', 'issue_comments.jsonl', 'review_comments.jsonl', 'commit_comments.jsonl'):
    p = os.path.join(ghdir, fn)
    if not os.path.exists(p):
        print(f'  {fn}: absent'); continue
    n = hit = 0
    for line in open(p):
        n += 1
        if CVE in line or HUNTR in line or '2022-1201' in line:
            hit += 1
    print(f'  {fn}: {n} records, {hit} mention {CVE}/huntr')
print('commit messages mentioning the CVE or huntr id on any ref:')
print(' ', git('log', '--all', '--oneline', f'--grep={CVE}', f'--grep={HUNTR}').strip() or '  (none)')
print('\ndone', now())
