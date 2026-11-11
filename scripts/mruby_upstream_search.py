#!/usr/bin/env python3
"""Search upstream mruby for a fix of the mruby.cve-2022-1276 root cause
(the extra push after gen_hash(s, ..., VAL, 0) in the keyword branch of an
index assignment) and of the residual gen_hash() final-branch defect.

Usage: mruby_upstream_search.py <mruby clone> <github data dir> [--scrape]

<mruby clone> is a full clone of https://github.com/mruby/mruby with every
branch, tag and refs/pull/*/head fetched, e.g.
  git -c gc.auto=0 clone --no-checkout https://github.com/mruby/mruby.git
  git config --add remote.origin.fetch '+refs/pull/*/head:refs/remotes/pr/*'
  git config --add remote.origin.fetch '+refs/tags/*:refs/tags/*'
  git fetch origin
<github data dir> holds the raw JSON of every issue, PR and comment of
mruby/mruby; --scrape (re)fetches it with the gh CLI first.

Sections: clone, keyword-block forms, gen_hash() final-branch forms,
commits that change either block, pickaxe, commit messages, release tags,
GitHub issues/PRs/comments, external sources. Local paths are not printed.
"""
import collections, datetime, html, json, os, re, subprocess, sys, urllib.request

repo, ghdir = sys.argv[1], sys.argv[2]
scrape = '--scrape' in sys.argv[3:]
LEGACY = ['mrbgems/mruby-compiler/core/codegen.c',
          'mrbgems/mruby-compiler-lrama/core/codegen.c',
          'src/codegen.c']
PRISM = ['mrbgems/mruby-compiler/src/codegen.c',
         'mrbgems/mruby-compiler-prism/src/codegen.c']
WINDOW = '2022-01-20'   # b53cd3ce25 adds the keyword branch
CVE = 'CVE-2022-1276'
HUNTR = 'huntr.dev/bounties/6ea041d1-e2aa-472c-bf3e-da5fa8726c25'


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def sh(*a, cwd=None):
    return subprocess.run(list(a), cwd=cwd, capture_output=True, text=True, errors='replace').stdout


def git(*a):
    return sh('git', '-C', repo, *a)


def section(title):
    print('\n' + '=' * 8 + ' ' + title)


cat = subprocess.Popen(['git', '-C', repo, 'cat-file', '--batch'],
                       stdin=subprocess.PIPE, stdout=subprocess.PIPE)
_blobs = {}


def blob(rev, path):
    key = rev + ':' + path
    if key not in _blobs:
        cat.stdin.write((key + '\n').encode()); cat.stdin.flush()
        hdr = cat.stdout.readline().decode()
        if hdr.endswith('missing\n'):
            _blobs[key] = None
        else:
            data = cat.stdout.read(int(hdr.split()[2])); cat.stdout.read(1)
            _blobs[key] = data.decode('utf-8', 'replace')
    return _blobs[key]


def legacy_src(rev):
    for p in LEGACY:
        b = blob(rev, p)
        if b is not None:
            return b
    return None


def func(src, name):
    m = re.search(r'^' + name + r'\(.*?^\}', src, re.S | re.M)
    return m.group(0) if m else None


def kwblock(src):
    """Every call gen_hash(s, ..., VAL, 0) with 8 lines of context either side."""
    lines = src.split('\n'); out = []
    for i, l in enumerate(lines):
        if re.search(r'gen_hash\(s, [^;]*, VAL, 0\);', l):
            out.append('\n'.join(lines[max(0, i - 8):i + 9]))
    return '\n@@\n'.join(out) if out else None


def hashtail(src):
    f = func(src, 'gen_hash')
    if not f:
        return None
    i = f.find('if (val && len > limit)')
    return f[i:] if i >= 0 else None


def norm(x):
    return None if x is None else re.sub(r'\s+', ' ', x).strip()


def blocks(rev):
    src = legacy_src(rev)
    if src is None:
        return {}
    return {'kw': kwblock(src), 'hashtail': hashtail(src),
            'gen_hash': func(src, 'gen_hash'), 'gen_values': func(src, 'gen_values')}


def info(c):
    return git('log', '-1', '--format=%h %aI %an | %s', c).strip()


print('run started', now())

# ---------------------------------------------------------------- clone
section('clone')
print('origin/master', git('rev-parse', 'origin/master').strip(), git('log', '-1', '--format=%cI', 'origin/master').strip())
refs = git('for-each-ref', '--format=%(refname)').split()
kinds = collections.Counter(re.sub(r'^(refs/remotes/pr|refs/remotes/origin|refs/tags|refs/heads)/.*', r'\1', r) for r in refs)
for k, v in sorted(kinds.items()):
    print(f'refs {k}: {v}')
print('commits on all refs:', git('rev-list', '--all', '--count').strip())
revs = git('rev-list', '--all', '--full-history', '--', *LEGACY).split()
print('commits touching a legacy codegen.c on all refs (--full-history):', len(revs))

# ---------------------------------------------------------------- forms
forms = {'kw': collections.OrderedDict(), 'hashtail': collections.OrderedDict()}
bl = {}
for c in revs:
    bl[c] = b = blocks(c)
    for key in forms:
        if b.get(key):
            forms[key].setdefault(norm(b[key]), {'text': b[key], 'commits': []})['commits'].append(c)
for key, title in (('kw', 'keyword-block forms (8 lines around each gen_hash(s, ..., VAL, 0))'),
                   ('hashtail', 'gen_hash() final-branch forms (from "if (val && len > limit)")')):
    section(f'{title}: {len(forms[key])} distinct')
    for i, f in enumerate(forms[key].values()):
        dated = sorted(info(c) for c in f['commits'])
        dated.sort(key=lambda s: s.split()[1])
        has_pop = bool(re.search(r'n\+\+;\s*pop\(\);', f['text'])) if key == 'kw' else None
        merges = bool(re.search(r'!update', f['text'])) if key == 'hashtail' else None
        print(f'--- form {i}: {len(f["commits"])} commits; earliest {dated[0]}; latest {dated[-1]}')
        if key == 'kw':
            print('pop() after n++ in the n < 14 branch:', has_pop)
        else:
            print('final branch checks !update:', merges)
        print(f['text'])

# ---------------------------------------------------------------- changes
section('commits on any ref that change a block (merges only if different from every parent)')
for c in revs:
    parents = git('rev-list', '--parents', '-n1', c).split()[1:]
    diffs = []
    for par in parents:
        pb = bl[par] if par in bl else blocks(par)
        diffs.append({k for k in ('kw', 'hashtail', 'gen_hash', 'gen_values')
                      if norm(bl[c].get(k)) != norm(pb.get(k))})
    changed = set.intersection(*diffs) if diffs else set()
    if changed:
        print(','.join(sorted(changed)), '|', info(c))

# ---------------------------------------------------------------- pickaxe
section('pickaxe over all refs (mrbgems/mruby-compiler*/**, src/codegen.c)')
paths = [':(glob)mrbgems/mruby-compiler*/**', 'src/codegen.c']
for q in ['-Sgen_hash(s, tree->cdr->car->cdr, VAL, 0)', '-Sgen_hash(s, kwargs->cdr, VAL, 0)',
          '-Gn == 1[34]', r'-Gif \(val && len > limit', r'-Glen > limit && !update|!update && len > limit']:
    out = git('log', '--all', '--format=%h %aI %an | %s', q, '--', *paths).strip()
    print(f'--- {q}: {len(out.splitlines()) if out else 0} commits')
    if out:
        print(out)

# ---------------------------------------------------------------- messages
section(f'commit messages on all refs since {WINDOW} (case-insensitive)')
terms = ['keyword', 'kwarg', 'aset', r'\[\]=', 'index assign', 'gen_hash', 'gen_assignment',
         'gen_call_assign', 'push', 'stack', '1276', 'huntr', 'OP_HASHADD', r'OP_HASH\b', r'n=\*', 'wrong argument']
for t in terms:
    n = len(set(git('log', '--all', '-i', '-E', f'--grep={t}', f'--since={WINDOW}', '--format=%H').split()))
    print(f'{t!r}: {n} commits')
print('--- of these, commits touching a codegen.c:')
print(git('log', '--all', '-i', '-E', f'--since={WINDOW}', '--format=%h %aI %an | %s',
          r'--grep=keyword|kwarg|\baset\b|\[\]=|index.assign|gen_hash|gen_assignment|1276|huntr|OP_HASH',
          '--', '*codegen.c').strip())

# ---------------------------------------------------------------- tags
section('release tags: keyword branch and added pop()')
for t in git('tag', '--sort=creatordate').split():
    src = legacy_src(t)
    calls = len(re.findall(r'gen_hash\(s, [^;]*, VAL, 0\);', src)) if src else 0
    pop = bool(src and re.search(r'VAL, 0\);\s*if \(n < 14\) \{\s*n\+\+;\s*pop\(\);', src))
    prism = any(blob(t, p) is not None for p in PRISM)
    print(f'{t} {git("log", "-1", "--format=%cs", t).strip()} legacy={src is not None} '
          f'keyword_calls={calls} pop_after_n++={pop} prism_compiler={prism}')

# ---------------------------------------------------------------- github
section('GitHub mruby/mruby issues, PRs and comments')
os.makedirs(ghdir, exist_ok=True)
EPS = {'issues': 'repos/mruby/mruby/issues?state=all&per_page=100&direction=asc',
       'issue_comments': 'repos/mruby/mruby/issues/comments?per_page=100&direction=asc',
       'review_comments': 'repos/mruby/mruby/pulls/comments?per_page=50&sort=created&direction=asc',
       'commit_comments': 'repos/mruby/mruby/comments?per_page=100'}
if scrape:
    for name, ep in EPS.items():
        for attempt in range(3):
            r = subprocess.run(['gh', 'api', '--paginate', ep, '--jq', '.[]'], capture_output=True, text=True)
            if r.returncode == 0:
                open(f'{ghdir}/{name}.jsonl', 'w').write(r.stdout)
                print(f'scraped {name} at {now()} (attempt {attempt + 1})')
                break
            print(f'scrape {name} attempt {attempt + 1} failed: {r.stderr.strip()[:200]}')
        else:
            sys.exit(f'scrape of {name} failed')
    open(f'{ghdir}/scraped_at.txt', 'w').write(now() + '\n')
print('data scraped at', open(f'{ghdir}/scraped_at.txt').read().strip())


def load(n):
    return [json.loads(l) for l in open(f'{ghdir}/{n}.jsonl')]


iss = load('issues')
items = [('PR' if i.get('pull_request') else 'issue', i['number'], i['created_at'], i['state'], i['title'] or '',
          (i['title'] or '') + '\n' + (i['body'] or '')) for i in iss]
items += [('issue_comment', int(c['issue_url'].rsplit('/', 1)[1]), c['created_at'], '', '', c['body'] or '')
          for c in load('issue_comments')]
items += [('review_comment', int(c['pull_request_url'].rsplit('/', 1)[1]), c['created_at'], '', '',
           (c.get('path') or '') + '\n' + (c.get('diff_hunk') or '') + '\n' + (c['body'] or ''))
          for c in load('review_comments')]
items += [('commit_comment', c['commit_id'][:10], c['created_at'], '', '', (c.get('path') or '') + '\n' + (c['body'] or ''))
          for c in load('commit_comments')]
cnt = collections.Counter(i[0] for i in items)
print('scanned:', ', '.join(f'{k} {v}' for k, v in sorted(cnt.items())),
      f'(highest issue/PR number {max(i["number"] for i in iss)}; issue comment counts sum to {sum(i["comments"] for i in iss)})')
T = collections.OrderedDict([
    ('keyword', r'keyword'), ('kwarg', r'kwarg'), ('aset', r'\baset\b'), ('[]=', r'\[\]='),
    ('index assign', r'index[ _-]?assign'), ('gen_hash', r'gen_hash'), ('gen_assignment', r'gen_assignment'),
    ('gen_call_assign', r'gen_call_assign|codegen_call_assign'), ('push', r'\bpush\b'), ('stack', r'stack'),
    ('1276', r'1276'), ('huntr', r'huntr'), ('keyword argument + index', None), ('**{}', r'\*\*\{\}'),
    ('n=*', r'n=\*'), ('OP_SEND', r'OP_SEND'), ('OP_HASH', r'OP_HASH\b'), ('OP_HASHADD', r'OP_HASHADD'),
    ('wrong argument', r'wrong argument'), ('SEGV + mrb_get_args', None), ('codegen', r'codegen')])


def match(k, t):
    if k == 'keyword argument + index':
        return re.search(r'keyword arg', t, re.I) and re.search(r'index|\[\]=|aset', t, re.I)
    if k == 'SEGV + mrb_get_args':
        return re.search(r'SEGV', t) and re.search(r'mrb_get_args', t)
    return re.search(T[k], t, re.I)


SPEC = {'aset', '[]=', 'index assign', 'gen_hash', 'gen_assignment', 'gen_call_assign', '1276', 'huntr',
        'keyword argument + index', '**{}', 'n=*', 'OP_HASH', 'OP_HASHADD', 'SEGV + mrb_get_args'}
counts = {k: [0, 0] for k in T}; threads = collections.defaultdict(set)
for it in items:
    for k in T:
        if match(k, it[5]):
            counts[k][0] += 1
            if it[2] >= WINDOW:
                counts[k][1] += 1; threads[it[1]].add(k)
for k, (a, w) in counts.items():
    print(f'{k!r}: {a} items, {w} since {WINDOW}')
meta = {i['number']: i for i in iss}
print(f'--- threads since {WINDOW} with a specific term')
for n, ks in sorted(threads.items(), key=lambda x: str(x[0])):
    if ks & SPEC:
        m = meta.get(n)
        head = (f'{"PR" if m.get("pull_request") else "issue"} #{n} {m["created_at"][:10]} {m["state"]} {m["title"][:80]!r}'
                if m else f'commit {n}')
        print(head, '::', ', '.join(sorted(ks)))


# ---------------------------------------------------------------- external
section('external sources')


def fetch(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode('utf-8', 'replace')


adv = json.loads(sh('gh', 'api', f'advisories?cve_id={CVE}'))
for a in adv:
    print('GitHub advisory', a['ghsa_id'], a['published_at'], '| references:', ' '.join(a['references']))
try:
    nvd = json.loads(fetch(f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={CVE}'))['vulnerabilities'][0]['cve']
    print('NVD published', nvd['published'], 'lastModified', nvd['lastModified'])
    for r in sorted({(r['url'], ','.join(r.get('tags', []))) for r in nvd['references']}):
        print('NVD reference', r[0], f'[{r[1]}]')
    for n in nvd.get('configurations', []):
        for node in n['nodes']:
            for m in node['cpeMatch']:
                print('NVD configuration', m['criteria'], 'versionEndExcluding', m.get('versionEndExcluding'))
except Exception as e:  # report and continue
    print('NVD not reachable:', e)
try:
    live = fetch('https://' + HUNTR)
    t = re.search(r'<title>([^<]*)', live)
    print('huntr live page title:', html.unescape(t.group(1)) if t else None,
          '| mentions mrb_get_args:', 'mrb_get_args' in live)
except Exception as e:
    print('huntr live page not reachable:', e)
cdx = json.loads(fetch(f'https://web.archive.org/cdx/search/cdx?url={HUNTR}*&output=json'))
snaps = [r[1] for r in cdx[1:] if r[4] == '200' and r[3] == 'text/html']
print('huntr Wayback snapshots with status 200:', ' '.join(snaps))
if snaps:
    page = fetch(f'https://web.archive.org/web/{snaps[-1]}id_/https://{HUNTR}/')
    page = re.sub(r'<script.*?</script>|<style.*?</style>', ' ', page, flags=re.S)
    words = ' '.join(html.unescape(re.sub(r'<[^>]+>', '\n', page)).split())
    print(f'huntr snapshot {snaps[-1]} text:')
    for pat in [r'Out-of-bounds Read in mrb_get_args in mruby/mruby.{0,40}', r'Reported on \S+ \S+ \S+',
                r'Affected commit \S+', r'Proof of Concept .{0,120}?Below', r'marked this as fixed in \S+ with commit \S+',
                r'root cause.{0,200}', r'keyword.{0,200}']:
        m = re.search(pat, words, re.I)
        print(f'  /{pat}/:', m.group(0) if m else 'no match')
print('OSS-Fuzz tracker: not queried by this script (issues.oss-fuzz.com requires sign-in)')
print('run finished', now())
