#!/usr/bin/env python3
"""Search upstream mruby around the mruby.cve-2022-0570 fix.

Usage: sendempty_upstream_search.py <mruby clone>

<mruby clone> is a full clone of https://github.com/mruby/mruby with every
branch and tag fetched. Local paths are not printed.

For this instance the CVE_NVD developer patch IS the upstream fix, and is
byte-identical to the mruby.cve-2022-0631 developer patch:
  47068ae07a5fa3aa9a1879cdfe98a9ce0f339299 ("vm.c: packed arguments length may
  be zero for `send` method.", 2022-02-18). It adds, in the n == 15
  (CALL_MAXARGS) branch of mrb_f_send, a check `if (RARRAY_LEN(regs[0]) == 0)
  goto argnum_error;` before the method name is read from RARRAY_PTR(regs[0])[0],
  and labels the existing n == 0 error path argnum_error, so an empty packed
  argument array raises ArgumentError instead of reading past the array buffer.

Dataset disagreement: the SEC-bench base and the CVE_NVD base are both 0ed3fcf,
which is NOT the parent of the fix. The fix's parent is 1e314242 (the
mruby.cve-2022-0631 base), 11 commits after 0ed3fcf, and the fix is 12 commits
after 0ed3fcf. mrb_f_send is identical at 0ed3fcf and 1e314242 (both at line
672, the read at vm.c:695), so the developer patch applies at 0ed3fcf. The
search lists the 11 commits 0ed3fcf..1e314242 and those among them that touch
src/vm.c, the release tags, and every later commit touching the check, to
confirm no follow-up fix of the same empty-packed-array invariant.
"""
import datetime, subprocess, sys

repo = sys.argv[1]
BASE = '0ed3fcfa26de93c20c8cb4789d16fceab6e38b40'      # SEC-bench / CVE_NVD base
FIXPARENT = '1e314242e42932ec7146eaef87605e9ae5e91ba3'  # fix parent (= 0631 base)
FIX = '47068ae07a5fa3aa9a1879cdfe98a9ce0f339299'        # this instance's developer patch
CVE = 'CVE-2022-0570'
HUNTR = '65a7632e-f95b-4836-b1a7-9cb95e5124f1'


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def git(*a):
    return subprocess.run(['git', '-C', repo, *a], capture_output=True, text=True,
                          errors='replace').stdout.rstrip('\n')


def head(t):
    print('\n== ' + t)


print(f'# sendempty_upstream_search {CVE} (huntr {HUNTR})  {now()}')
print(f'# base {BASE}  (SEC-bench and CVE_NVD base; NOT the fix parent)')
print(f'# dev/fix {FIX}  (CVE_NVD developers_patch == upstream fix; byte-identical to the 0631 patch)')

head('fix metadata')
print(git('show', '-s', '--format=%H%n%an%n%cI%n%s', FIX))

head('base vs fix parent (dataset disagreement)')
print('fix parent:            ' + git('rev-parse', f'{FIX}^'))
print('fix parent == 0631 base 1e314242:', git('rev-parse', f'{FIX}^') == FIXPARENT)
print('commits base..fixparent:', git('rev-list', '--count', f'{BASE}..{FIXPARENT}'))
print('commits base..fix:      ', git('rev-list', '--count', f'{BASE}..{FIX}'))
print('base is ancestor of fix:',
      subprocess.run(['git', '-C', repo, 'merge-base', '--is-ancestor', BASE, FIX]).returncode == 0)

head('the 11 commits base..fixparent (0ed3fcf..1e314242)')
print(git('log', '--oneline', '--format=%H %cI %s', f'{BASE}..{FIXPARENT}'))
head('of those, the ones that touch src/vm.c')
print(git('log', '--oneline', '--format=%H %cI %s', f'{BASE}..{FIXPARENT}', '--', 'src/vm.c') or '(none)')
head('mrb_f_send identical at base and fix parent')
a = git('show', f'{BASE}:src/vm.c')
b = git('show', f'{FIXPARENT}:src/vm.c')
def fn(src):
    L = src.splitlines()
    i = next((k for k, l in enumerate(L) if l.startswith('mrb_f_send(mrb_state')), None)
    if i is None:
        return None
    j = next((k for k in range(i, len(L)) if L[k] == '}'), i + 70)
    return '\n'.join(L[i:j + 1])
print('mrb_f_send byte-identical at 0ed3fcf and 1e314242:', fn(a) == fn(b))

head('fix is on origin/master')
print('on master' if subprocess.run(['git', '-C', repo, 'merge-base', '--is-ancestor', FIX, 'origin/master']).returncode == 0
      else 'NOT on master')

head('first release tags (sorted by creation)')
print('base:')
print(git('tag', '--contains', BASE, '--sort=creatordate'))
print('fix:')
print(git('tag', '--contains', FIX, '--sort=creatordate'))

head('later commits that change the empty-array check (pickaxe on the check string)')
print(git('log', '--oneline', '--format=%H %cI %s', f'{FIX}..origin/master',
          '-S', 'RARRAY_LEN(regs[0]) == 0', '--', 'src/vm.c') or '(none: the check is unchanged from the fix to master)')

head('later commits on src/vm.c whose subject names send or public_send')
print(git('log', '--oneline', '--format=%H %cI %s', f'{FIX}..origin/master',
          '--grep', r'send', '-i', '--', 'src/vm.c') or '(none)')

head('empty-packed-array check on origin/master (now in the shared send_method)')
src = git('show', 'origin/master:src/vm.c')
lines = src.splitlines()
for i, l in enumerate(lines):
    if l.startswith('send_method(mrb_state'):
        end = i + 40
        for j, l2 in enumerate(lines[i:end]):
            print(l2)
            if 'RARRAY_LEN(regs[0]) == 0' in l2:
                print(lines[i + j + 1])
                break
        break
