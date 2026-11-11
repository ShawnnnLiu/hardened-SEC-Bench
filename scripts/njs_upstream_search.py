#!/usr/bin/env python3
"""Search upstream njs for follow-up fixes of an njs instance's root cause
and residual defects (njs instances).

Usage: njs_upstream_search.py <njs clone> <github data dir> <config.json> [--scrape]

<njs clone> is a clone of https://github.com/nginx/njs with every branch,
tag and refs/pull/*/head fetched, e.g.
  git -c gc.auto=0 clone --no-checkout https://github.com/nginx/njs.git
  git config --add remote.origin.fetch '+refs/pull/*/head:refs/remotes/pr/*'
  git config --add remote.origin.fetch '+refs/tags/*:refs/tags/*'
  git fetch origin
<github data dir> holds the raw JSON of every issue, PR and comment of
nginx/njs; --scrape (re)fetches it with the gh CLI first.
<config.json> names the instance (scripts/<topic>_upstream.json):
  cve, fix (the developers_patch commit), base (the image tree commit),
  since (start of the commit-message window), files, functions (a list of
  {"name", "file", "checks": {label: regex}}: every distinct form of the
  function over all refs is printed with the checks evaluated on it),
  pickaxe (git log -S/-G arguments), messages (commit-message regexes),
  terms (issue/PR/comment regexes) and commits (upstream commits to show
  with their message and files).

Sections: clone, named commits, function forms, commits that change a
function, pickaxe, commit messages, release tags, GitHub issues/PRs/
comments, external sources (GitHub advisory, NVD). Local paths are not
printed.
"""
import collections, datetime, json, os, re, subprocess, sys, urllib.request

repo, ghdir, cfgpath = sys.argv[1], sys.argv[2], sys.argv[3]
scrape = '--scrape' in sys.argv[4:]
cfg = json.load(open(cfgpath))


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def sh(*a):
    return subprocess.run(list(a), capture_output=True, text=True, errors='replace').stdout


def git(*a):
    return sh('git', '-C', repo, *a)


def section(title):
    print('\n' + '=' * 8 + ' ' + title)


cat = subprocess.Popen(['git', '-C', repo, 'cat-file', '--batch'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
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


def func(src, name):
    if src is None:
        return None
    m = re.search(r'^' + re.escape(name) + r'\(.*?^\}', src, re.S | re.M)
    return m.group(0) if m else None


def norm(x):
    return None if x is None else re.sub(r'\s+', ' ', x).strip()


def info(c):
    return git('log', '-1', '--format=%h %aI %an | %s', c).strip()


print('run started', now())
print('config', os.path.basename(cfgpath), 'cve', cfg['cve'], 'fix', cfg['fix'], 'base', cfg['base'])

section('clone')
print('origin/master', git('rev-parse', 'origin/master').strip(), git('log', '-1', '--format=%cI', 'origin/master').strip())
refs = git('for-each-ref', '--format=%(refname)').split()
kinds = collections.Counter(re.sub(r'^(refs/remotes/pr|refs/remotes/origin|refs/tags|refs/heads)/.*', r'\1', r) for r in refs)
for k, v in sorted(kinds.items()):
    print(f'refs {k}: {v}')
print('commits on all refs:', git('rev-list', '--all', '--count').strip())
print('fix', info(cfg['fix']), '| parent', git('rev-parse', cfg['fix'] + '~1').strip())
print('base', info(cfg['base']))
print('fix is a descendant of base:',
      subprocess.run(['git', '-C', repo, 'merge-base', '--is-ancestor', cfg['base'], cfg['fix']]).returncode == 0)
print('commits between base and fix parent:', git('rev-list', '--count', f'{cfg["base"]}..{cfg["fix"]}~1').strip())
print('branches containing the fix:', ' '.join(sorted(set(
    r.strip() for r in git('branch', '-r', '--contains', cfg['fix']).splitlines() if not r.strip().startswith('pr/')))) or '-')
tags = git('tag', '--contains', cfg['fix'], '--sort=creatordate').split()
print('first tag containing the fix:', tags[0] if tags else '-', f'({len(tags)} tags)')

section('named commits')
for c in cfg.get('commits', []):
    print('---', info(c))
    print(git('log', '-1', '--format=%B', c).strip())
    print(git('show', '--stat', '--format=', c).strip())
    contains = git('tag', '--contains', c, '--sort=creatordate').split()
    print('first tag containing it:', contains[0] if contains else '-')

for fn in cfg['functions']:
    revs = git('rev-list', '--all', '--full-history', '--', fn['file']).split()
    forms = collections.OrderedDict()
    per = {}
    for c in revs:
        f = func(blob(c, fn['file']), fn['name'])
        per[c] = norm(f)
        if f:
            forms.setdefault(norm(f), {'text': f, 'commits': []})['commits'].append(c)
    section(f'{fn["name"]} ({fn["file"]}): {len(forms)} distinct forms over {len(revs)} commits touching the file')
    for i, f in enumerate(forms.values()):
        dated = sorted((info(c) for c in f['commits']), key=lambda s: s.split()[1])
        checks = ', '.join(f'{k}={bool(re.search(v, f["text"]))}' for k, v in fn['checks'].items())
        print(f'--- form {i}: {len(f["commits"])} commits; earliest {dated[0]}; latest {dated[-1]}; {checks}')
    for ref in ('base', 'fix'):
        f = func(blob(cfg[ref], fn['file']), fn['name'])
        print(f'at {ref}:', ', '.join(f'{k}={bool(f and re.search(v, f))}' for k, v in fn['checks'].items()))
    f = func(blob('origin/master', fn['file']), fn['name'])
    print('at origin/master:', 'absent' if f is None else
          ', '.join(f'{k}={bool(re.search(v, f))}' for k, v in fn['checks'].items()))
    if f is not None:
        print(f)
    print('--- commits that change the function (merges only if different from every parent)')
    for c in revs:
        parents = git('rev-list', '--parents', '-n1', c).split()[1:]
        if parents and all(per[c] != (per[p] if p in per else norm(func(blob(p, fn['file']), fn['name'])))
                           for p in parents):
            print(info(c))

section('pickaxe over all refs')
for q in cfg.get('pickaxe', []):
    out = git('log', '--all', '--format=%h %aI %an | %s', q, '--', *cfg['files']).strip()
    print(f'--- {q}: {len(out.splitlines()) if out else 0} commits')
    if out:
        print(out)

section(f'commit messages on all refs since {cfg["since"]} (case-insensitive)')
for t in cfg.get('messages', []):
    out = git('log', '--all', '-i', '-E', f'--grep={t}', f'--since={cfg["since"]}', '--format=%h %aI %an | %s').strip()
    print(f'--- {t!r}: {len(out.splitlines()) if out else 0} commits')
    if out:
        print(out)

section('release tags: function checks')
for t in git('tag', '--sort=creatordate').split():
    parts = []
    for fn in cfg['functions']:
        f = func(blob(t, fn['file']), fn['name'])
        parts.append(f'{fn["name"]}:' + ('absent' if f is None else
                     ','.join(f'{k}={int(bool(re.search(v, f)))}' for k, v in fn['checks'].items())))
    print(t, git('log', '-1', '--format=%cs', t).strip(), ' '.join(parts))

section('GitHub nginx/njs issues, PRs and comments')
os.makedirs(ghdir, exist_ok=True)
EPS = {'issues': 'repos/nginx/njs/issues?state=all&per_page=100&direction=asc',
       'issue_comments': 'repos/nginx/njs/issues/comments?per_page=100&direction=asc',
       'review_comments': 'repos/nginx/njs/pulls/comments?per_page=50&sort=created&direction=asc',
       'commit_comments': 'repos/nginx/njs/comments?per_page=100'}
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
items = [('PR' if i.get('pull_request') else 'issue', i['number'], i['created_at'],
          (i['title'] or '') + '\n' + (i['body'] or '')) for i in iss]
items += [('issue_comment', int(c['issue_url'].rsplit('/', 1)[1]), c['created_at'], c['body'] or '')
          for c in load('issue_comments')]
items += [('review_comment', int(c['pull_request_url'].rsplit('/', 1)[1]), c['created_at'],
           (c.get('path') or '') + '\n' + (c.get('diff_hunk') or '') + '\n' + (c['body'] or ''))
          for c in load('review_comments')]
items += [('commit_comment', c['commit_id'][:10], c['created_at'], (c.get('path') or '') + '\n' + (c['body'] or ''))
          for c in load('commit_comments')]
cnt = collections.Counter(i[0] for i in items)
print('scanned:', ', '.join(f'{k} {v}' for k, v in sorted(cnt.items())),
      f'(highest issue/PR number {max(i["number"] for i in iss)})')
meta = {i['number']: i for i in iss}
threads = collections.defaultdict(set)
for k, rx in cfg['terms'].items():
    n = 0
    for it in items:
        if re.search(rx, it[3], re.I):
            n += 1
            threads[it[1]].add(k)
    print(f'{k!r}: {n} items')
print('--- threads with a term')
for n, ks in sorted(threads.items(), key=lambda x: str(x[0])):
    m = meta.get(n)
    head = (f'{"PR" if m.get("pull_request") else "issue"} #{n} {m["created_at"][:10]} {m["state"]} {m["title"][:90]!r}'
            if m else f'commit {n}')
    print(head, '::', ', '.join(sorted(ks)))
for n in cfg.get('issues', []):
    m = meta.get(n)
    if m:
        print(f'--- issue #{n} {m["state"]} closed {m.get("closed_at")} {m["title"]!r}')
        for c in load('issue_comments'):
            if int(c['issue_url'].rsplit('/', 1)[1]) == n:
                print(f'  comment {c["created_at"]} {c["user"]["login"]}: {(c["body"] or "")[:600]!r}')

section('external sources')


def fetch(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode('utf-8', 'replace')


try:
    adv = json.loads(sh('gh', 'api', f'advisories?cve_id={cfg["cve"]}'))
    print('GitHub advisories:', len(adv))
    for a in adv:
        print('GitHub advisory', a['ghsa_id'], a['published_at'], '| references:', ' '.join(a['references']))
except Exception as e:
    print('GitHub advisory query failed:', e)
try:
    nvd = json.loads(fetch(f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cfg["cve"]}'))['vulnerabilities'][0]['cve']
    print('NVD published', nvd['published'], 'lastModified', nvd['lastModified'])
    for r in sorted({(r['url'], ','.join(r.get('tags', []))) for r in nvd['references']}):
        print('NVD reference', r[0], f'[{r[1]}]')
    for n in nvd.get('configurations', []):
        for node in n['nodes']:
            for m in node['cpeMatch']:
                print('NVD configuration', m['criteria'], 'versionEndExcluding', m.get('versionEndExcluding'))
except Exception as e:
    print('NVD not reachable:', e)
print('run finished', now())
