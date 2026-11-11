#!/usr/bin/env python3
"""Search upstream mruby around the mruby.cve-2022-0630 fix.

Usage: hashcat_upstream_search.py <mruby clone>

<mruby clone> is a full clone of https://github.com/mruby/mruby with every
branch, tag and pull-request head fetched. Local paths are not printed. Only
commit subjects (%s) are printed, never message bodies.

The CVE_NVD developers_patch of mruby.cve-2022-0630 is the OP_HASHCAT hunk of
  ee06bbb4177a0c65aab9b3006f0f15fe9f3503fd ("vm.c: replace type assertions with
  runtime checks", Matz, 2026-01-04), rebased to the base ecb28f4b. It replaces,
  in the OP_HASHCAT handler of mrb_vm_exec, `mrb_assert(mrb_hash_p(hash));` with
  `mrb_ensure_hash_type(mrb, hash);`, so a non-hash accumulator regs[a] raises
  TypeError instead of reaching mrb_hash_merge (the reported crash).

The reported crash is the OP_HASHCAT sibling of mruby.cve-2022-0614/0623
  (OP_HASHADD), whose fix is
  ff3a5ebed6ffbe3e70481531cfb969b497aa73ad ("vm.c: should check type before hash
  access.", 2022-02-15, parent ecb28f4b).

Both crashes and the aliasing wrong result share one gen_hash code-generation
defect (a leading double-splat reuses the splat operand register as the
accumulator). Upstream fixes the root cause in
  12d51807a397545d5cf423d2f9bd9b52b7e4a786 ("Insert an empty hash before the
  first `NODE_KW_REST_ARGS`", dearblue, 2022-02-18, parent 47068ae07, PR #5650),
  which emits an empty OP_HASH accumulator before the first splat in gen_hash.

The search records: each commit's metadata, distance from the base, whether it
is on master, its first release tag, the pull requests that contain it, and
later commits that touch the OP_HASHCAT type check or the gen_hash splat path.
"""
import datetime, subprocess, sys, json

repo = sys.argv[1]
BASE = 'ecb28f4bf463483cf914c799d086b0cfff997aee'
DEV = 'ee06bbb4177a0c65aab9b3006f0f15fe9f3503fd'       # CVE_NVD developers_patch source (OP_HASHCAT hunk)
ROOT = '12d51807a397545d5cf423d2f9bd9b52b7e4a786'      # gen_hash root fix
SIB = 'ff3a5ebed6ffbe3e70481531cfb969b497aa73ad'       # 0614/0623 OP_HASHADD fix
CODEGEN = 'mrbgems/mruby-compiler/core/codegen.c'


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def git(*a):
    return subprocess.run(['git', '-C', repo, *a], capture_output=True, text=True,
                          errors='replace').stdout.rstrip('\n')


def is_anc(a, b):
    return subprocess.run(['git', '-C', repo, 'merge-base', '--is-ancestor', a, b]).returncode == 0


def pulls(sha):
    try:
        out = subprocess.run(['gh', 'api', f'repos/mruby/mruby/commits/{sha}/pulls'],
                             capture_output=True, text=True, timeout=60).stdout
        arr = json.loads(out)
        if not arr:
            return 'none'
        return '; '.join(f"#{p['number']} {p['title']} [{p['state']}]" for p in arr)
    except Exception as e:
        return f'(gh api unavailable: {e})'


def head(t):
    print('\n== ' + t)


print(f'# hashcat_upstream_search CVE-2022-0630  {now()}')
print(f'# base {BASE}')
print(f'# dev-patch source {DEV} (OP_HASHCAT hunk rebased to base)')
print(f'# gen_hash root fix {ROOT}')
print(f'# OP_HASHADD sibling fix {SIB} (mruby.cve-2022-0614/0623)')
print('# huntr f7cdd680-1a7f-4992-b4b8-44b5e4ba3e32')

for label, sha in (('dev-patch source (ee06bbb4)', DEV),
                   ('gen_hash root fix (12d51807a)', ROOT),
                   ('OP_HASHADD sibling fix (ff3a5ebed)', SIB)):
    head(f'{label} metadata')
    print(git('show', '-s', '--format=%H%n%an%n%cI%n%s', sha))
    print('parent: ' + git('rev-parse', f'{sha}^'))
    print(f'on origin/master: {is_anc(sha, "origin/master")}')
    print(f'commits base..commit: ' + git('rev-list', '--count', f'{BASE}..{sha}'))
    print('first release tags (by creation): ' +
          (git('tag', '--contains', sha, '--sort=creatordate').split('\n')[0] or '(none)'))
    print('pull requests: ' + pulls(sha))

head('codegen.c unchanged between base and the root-fix parent (empty = unchanged)')
d = git('diff', BASE, f'{ROOT}^', '--', CODEGEN)
print('UNCHANGED' if not d else d[:400])

head('base relationship to each fix')
for name, s in (('dev source', DEV), ('root fix', ROOT), ('sibling fix', SIB)):
    print(f'{name} {s}: ancestor-of-master={is_anc(s, "origin/master")}, base-is-ancestor={is_anc(BASE, s)}')

head('later commits that change the OP_HASHCAT type check (pickaxe mrb_ensure_hash_type on src/vm.c, base..master)')
print(git('log', '--format=%H %cI %s', f'{BASE}..origin/master',
          '-S', 'mrb_ensure_hash_type(mrb, hash)', '--', 'src/vm.c')
      or '(none on src/vm.c between base and master for this pickaxe)')

head('commits that touch the gen_hash splat path (pickaxe NODE_KW_REST_ARGS on codegen.c, base..master)')
print(git('log', '--format=%H %cI %s', f'{BASE}..origin/master',
          '-S', 'NODE_KW_REST_ARGS', '--', CODEGEN)
      or '(none)')

head('OP_HASHCAT handler on origin/master')
src = git('show', 'origin/master:src/vm.c')
for i, l in enumerate(src.splitlines()):
    if 'OP_HASHCAT' in l:
        for l2 in src.splitlines()[i:i + 8]:
            print(l2)
        break
