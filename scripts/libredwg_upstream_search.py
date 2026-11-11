#!/usr/bin/env python3
"""Search upstream LibreDWG for a fix of the root cause of a CVE_NVD instance
and for later changes to the patched code.

Usage: libredwg_upstream_search.py <clone> <github data dir> --cve CVE-YYYY-N
         --paths P[,P...] --funcs F[,F...] --since YYYY-MM-DD
         [--fix HASH[,HASH...]] [--terms T[,T...]] [--pickaxe PAT]...
         [--flag NAME=REGEX]... [--issue N[,N...]] [--scrape]

<clone> is a full clone of https://github.com/LibreDWG/libredwg with every
branch, tag and refs/pull/*/head fetched, e.g.
  git -c gc.auto=0 clone --no-checkout https://github.com/LibreDWG/libredwg.git
  git config --add remote.origin.fetch '+refs/pull/*/head:refs/remotes/pr/*'
  git config --add remote.origin.fetch '+refs/tags/*:refs/tags/*'
  git fetch origin
<github data dir> holds the raw JSON of every issue, PR and comment of
LibreDWG/libredwg; --scrape (re)fetches it with the gh CLI first.

--paths are the files of the patched code and --funcs the C functions in
them whose text is followed through history (a function runs from the line
that starts with its name to the next line that starts with "}"); each
--flag NAME=REGEX is evaluated on every form of every function. --fix names
the fix commits (their forms are printed in full), --terms the words
searched in commit messages, issues, pull requests and comments (case
insensitive), --pickaxe a pattern searched with git log -S over the whole
tree, --issue the issue numbers read in full.

Sections: clone, forms, changes, pickaxe, commit messages, release tags,
GitHub issues/PRs/comments, external sources. Local paths are not printed.
"""
import argparse
import collections
import datetime
import json
import os
import re
import subprocess
import sys
import urllib.request

ap = argparse.ArgumentParser()
ap.add_argument('repo')
ap.add_argument('ghdir')
ap.add_argument('--cve', required=True)
ap.add_argument('--paths', required=True)
ap.add_argument('--funcs', required=True)
ap.add_argument('--since', required=True)
ap.add_argument('--fix', default='')
ap.add_argument('--terms', default='')
ap.add_argument('--pickaxe', action='append', default=[])
ap.add_argument('--flag', action='append', default=[])
ap.add_argument('--issue', default='')
ap.add_argument('--scrape', action='store_true')
A = ap.parse_args()
repo, ghdir = A.repo, A.ghdir
PATHS = A.paths.split(',')
FUNCS = A.funcs.split(',')
FLAGS = [tuple(f.split('=', 1)) for f in A.flag]
FIX = [f for f in A.fix.split(',') if f]
TERMS = [t for t in A.terms.split(',') if t]
ISSUES = [int(i) for i in A.issue.split(',') if i]


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


def func(src, name):
    m = re.search(r'^' + re.escape(name) + r'\s*\(.*?^\}', src, re.S | re.M)
    return m.group(0) if m else None


def norm(x):
    return None if x is None else re.sub(r'\s+', ' ', x).strip()


def forms_at(rev):
    out = {}
    for p in PATHS:
        src = blob(rev, p)
        if src is None:
            continue
        for f in FUNCS:
            t = func(src, f)
            if t:
                out[f] = t
    return out


def info(c):
    return git('log', '-1', '--format=%h %aI %an | %s', c).strip()


def flags_of(text):
    return ','.join(n for n, rx in FLAGS if re.search(rx, text)) or '-'


print('run started', now())
print('options:', ' '.join(a for a in sys.argv[1:] if a not in (repo, ghdir)))

# ---------------------------------------------------------------- clone
section('clone')
print('origin/master', git('rev-parse', 'origin/master').strip(), git('log', '-1', '--format=%cI', 'origin/master').strip())
refs = git('for-each-ref', '--format=%(refname)').split()
kinds = collections.Counter(re.sub(r'^(refs/remotes/pr|refs/remotes/origin|refs/tags|refs/heads)/.*', r'\1', r) for r in refs)
for k, v in sorted(kinds.items()):
    print(f'refs {k}: {v}')
print('commits on all refs:', git('rev-list', '--all', '--count').strip())
revs = git('rev-list', '--all', '--full-history', '--', *PATHS).split()
print(f'commits touching {" ".join(PATHS)} on all refs (--full-history):', len(revs))
for f in FIX:
    print('fix commit', info(f))

# ---------------------------------------------------------------- forms
bl = {c: forms_at(c) for c in revs}
bl['origin/master'] = forms_at('origin/master')
for f in FUNCS:
    forms = collections.OrderedDict()
    for c in revs:
        t = bl[c].get(f)
        if t:
            forms.setdefault(norm(t), {'text': t, 'commits': []})['commits'].append(c)
    section(f'forms of {f}(): {len(forms)} distinct')
    master = norm(bl['origin/master'].get(f))
    fixforms = {norm(forms_at(h).get(f)) for h in FIX}
    for i, fm in enumerate(forms.values()):
        dated = sorted(((info(c).split()[1], info(c)) for c in fm['commits']))
        tags = []
        if norm(fm['text']) in fixforms:
            tags.append('form at a fix commit')
        if norm(fm['text']) == master:
            tags.append('form at origin/master')
        print(f'--- form {i}: {len(fm["commits"])} commits; earliest {dated[0][1]}; latest {dated[-1][1]}; '
              f'flags {flags_of(fm["text"])}' + (f'; {", ".join(tags)}' if tags else ''))
        if tags:
            print(fm['text'])

# ---------------------------------------------------------------- changes
section('commits on any ref that change a followed function (merges only if different from every parent)')
for c in sorted(revs, key=lambda c: git('log', '-1', '--format=%aI', c)):
    parents = git('rev-list', '--parents', '-n1', c).split()[1:]
    diffs = []
    for par in parents:
        pb = bl[par] if par in bl else forms_at(par)
        diffs.append({f for f in FUNCS if norm(bl[c].get(f)) != norm(pb.get(f))})
    changed = set.intersection(*diffs) if diffs else set(FUNCS)
    if changed:
        print(','.join(sorted(changed)), '|', info(c))

# ---------------------------------------------------------------- pickaxe
section('pickaxe over all refs (whole tree)')
for q in A.pickaxe:
    out = git('log', '--all', '--format=%h %aI %an | %s', '-S' + q).strip()
    print(f'--- -S{q}: {len(out.splitlines()) if out else 0} commits')
    if out:
        print(out)

# ---------------------------------------------------------------- messages
section(f'commit messages on all refs since {A.since} (case-insensitive)')
for t in TERMS:
    n = len(set(git('log', '--all', '-i', '-E', f'--grep={t}', f'--since={A.since}', '--format=%H').split()))
    print(f'{t!r}: {n} commits')
print('--- of these, commits touching the followed files:')
if TERMS:
    print(git('log', '--all', '-i', '-E', f'--since={A.since}', '--format=%h %aI %an | %s',
              '--grep=' + '|'.join(TERMS), '--', *PATHS).strip())

# ---------------------------------------------------------------- tags
section('release tags: followed functions')
for t in git('tag', '--sort=creatordate').split():
    fm = forms_at(t)
    if not fm:
        continue
    print(f'{t} {git("log", "-1", "--format=%cs", t).strip()} ' +
          ' '.join(f'{f}:[{flags_of(fm[f])}]' if f in fm else f'{f}:absent' for f in FUNCS))
for h in FIX:
    first = git('tag', '--contains', h, '--sort=creatordate').split()
    print(f'tags containing {h}: {len(first)}; first {first[:3]}')

# ---------------------------------------------------------------- github
section('GitHub LibreDWG/libredwg issues, PRs and comments')
os.makedirs(ghdir, exist_ok=True)
EPS = {'issues': 'repos/LibreDWG/libredwg/issues?state=all&per_page=100&direction=asc',
       'issue_comments': 'repos/LibreDWG/libredwg/issues/comments?per_page=100&direction=asc',
       'review_comments': 'repos/LibreDWG/libredwg/pulls/comments?per_page=50&sort=created&direction=asc',
       'commit_comments': 'repos/LibreDWG/libredwg/comments?per_page=100'}
if A.scrape:
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
counts = {t: [0, 0] for t in TERMS}; threads = collections.defaultdict(set)
for it in items:
    for t in TERMS:
        if re.search(t, it[5], re.I):
            counts[t][0] += 1
            if it[2] >= A.since:
                counts[t][1] += 1; threads[it[1]].add(t)
for t, (a, w) in counts.items():
    print(f'{t!r}: {a} items, {w} since {A.since}')
meta = {i['number']: i for i in iss}
print(f'--- threads since {A.since} that mention a term')
for n, ks in sorted(threads.items(), key=lambda x: str(x[0])):
    m = meta.get(n)
    head = (f'{"PR" if m.get("pull_request") else "issue"} #{n} {m["created_at"][:10]} {m["state"]} {m["title"][:80]!r}'
            if m else f'commit {n}')
    print(head, '::', ', '.join(sorted(ks)))
for n in ISSUES:
    m = meta.get(n)
    print(f'--- issue #{n}:', (f'{m["created_at"]} {m["state"]} closed {m.get("closed_at")} {m["title"]!r}, '
                               f'{m["comments"]} comments') if m else 'not found')
    for it in items:
        if it[1] == n and it[0] == 'issue_comment':
            print('   comment', it[2], '|', ' '.join(it[5].split())[:140])


# ---------------------------------------------------------------- external
section('external sources')


def fetch(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode('utf-8', 'replace')


try:
    adv = json.loads(sh('gh', 'api', f'advisories?cve_id={A.cve}'))
    for a in adv:
        print('GitHub advisory', a['ghsa_id'], a['published_at'], '| references:', ' '.join(a['references']))
    print('GitHub advisories listed for', A.cve + ':', len(adv))
except Exception as e:  # report and continue
    print('GitHub advisory query failed:', e)
try:
    nvd = json.loads(fetch(f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={A.cve}'))['vulnerabilities'][0]['cve']
    print('NVD published', nvd['published'], 'lastModified', nvd['lastModified'])
    print('NVD description:', ' '.join(d['value'] for d in nvd['descriptions'] if d['lang'] == 'en')[:400])
    for r in sorted({(r['url'], ','.join(r.get('tags', []))) for r in nvd['references']}):
        print('NVD reference', r[0], f'[{r[1]}]')
except Exception as e:
    print('NVD not reachable:', e)
print('OSS-Fuzz tracker: not queried by this script (issues.oss-fuzz.com requires sign-in)')
print('run finished', now())
