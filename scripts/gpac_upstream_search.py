#!/usr/bin/env python3
"""Search upstream gpac for fixes of the gpac.cve-2023-5586 root cause (the
WAVE branch of pcmreframe_process() accepts a header without the format,
sample-rate and channel-count conditions under which
pcmreframe_configure_pid() creates the output pid) and of the residual
defects recorded for the instance (header offset applied to the current
block, leak on the incomplete-header return).

Usage: gpac_upstream_search.py <gpac clone> <github data dir> [--scrape]

<gpac clone> is a full clone of https://github.com/gpac/gpac with every
branch, tag and refs/pull/*/head fetched, e.g.
  git -c gc.auto=0 clone --no-checkout https://github.com/gpac/gpac.git
  git config --add remote.origin.fetch '+refs/pull/*/head:refs/remotes/pr/*'
  git config --add remote.origin.fetch '+refs/tags/*:refs/tags/*'
  git fetch origin
<github data dir> holds the raw JSON of every issue, PR and comment of
gpac/gpac; --scrape (re)fetches it with the gh CLI first.

Sections: clone, block forms, commits that change a block, pickaxe,
commit messages, release tags, GitHub issues/PRs/comments, external
sources. Local paths are not printed.
"""
import collections, datetime, html, json, os, re, subprocess, sys, urllib.request

repo, ghdir = sys.argv[1], sys.argv[2]
scrape = '--scrape' in sys.argv[3:]
PATH = 'src/filters/reframe_rawpcm.c'
BASE = '5692dc729491805e0e5f55c21d50ba1e6b19e88e'
FIX = 'ca1b48f0abe71bf81a58995d7d75dc27f5a17ddc'
WINDOW = '2023-03-01'   # e7f96c2d37 (#2425) changes the header-overflow handling on 2023-03-27
CVE = 'CVE-2023-5586'


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


def blob(rev, path=PATH):
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


def between(src, start, end):
    i = src.find(start)
    if i < 0:
        return None
    j = src.find(end, i + len(start))
    return src[i:j + len(end)] if j >= 0 else None


def blocks(rev):
    src = blob(rev)
    if src is None:
        return {}
    proc = between(src, 'GF_Err pcmreframe_process(', '\n}\n') or ''
    return {
        # the checks after the chunk loop, up to the header size
        'checks': between(proc, 'if (gf_bs_is_overflow(bs)) {', 'ctx->wav_hdr_size ='),
        # what follows the configure call in the WAVE branch
        'after_configure': between(proc, 'pcmreframe_configure_pid(filter, ctx->ipid, GF_FALSE);', 'ctx->init_skip = GF_TRUE;'),
        # the header skip on the packet after the header was accepted
        'init_skip': between(proc, 'if (ctx->init_skip) {', '}'),
    }


def norm(x):
    return None if x is None else re.sub(r'\s+', ' ', x).strip()


def props(key, text):
    if text is None:
        return 'absent'
    if key == 'checks':
        leak_fixed = bool(re.search(r'drop_packet\(ctx->ipid\);\s*gf_bs_del\(bs\);\s*return GF_OK;', text))
        return (f"ch_check={'!ctx->ch' in text} sr_check={'!ctx->sr' in text} safmt_check={'!ctx->safmt' in text} "
                f"bs_del_before_wait_return={leak_fixed}")
    if key == 'after_configure':
        checked = bool(re.search(r'GF_Err\s+\w+\s*=\s*pcmreframe_configure_pid|if\s*\(\s*!?\s*ctx->opid|if\s*\(\s*e\b', text))
        return f"checks_return_or_opid={checked}"
    if key == 'init_skip':
        return f"uses_probe_data={'probe_data' in text}"


def info(c):
    return git('log', '-1', '--format=%h %aI %an | %s', c).strip()


def when(line):
    """Author time in seconds of the commit whose short hash starts the line."""
    return int(git('log', '-1', '--format=%at', line.split()[0]).strip())


print('run started', now())

# ---------------------------------------------------------------- clone
section('clone')
print('origin/master', git('rev-parse', 'origin/master').strip(), git('log', '-1', '--format=%cI', 'origin/master').strip())
refs = git('for-each-ref', '--format=%(refname)').split()
kinds = collections.Counter(re.sub(r'^(refs/remotes/pr|refs/remotes/origin|refs/tags|refs/heads)/.*', r'\1', r) for r in refs)
for k, v in sorted(kinds.items()):
    print(f'refs {k}: {v}')
print('commits on all refs:', git('rev-list', '--all', '--count').strip())
revs = git('rev-list', '--all', '--full-history', '--', PATH).split()
print(f'commits touching {PATH} on all refs (--full-history):', len(revs))
print('base commit', info(BASE))
print('developer fix', info(FIX))

# ---------------------------------------------------------------- forms
KEYS = [('checks', 'header checks after the chunk loop (from the overflow test to wav_hdr_size)'),
        ('after_configure', 'code after the configure call in the WAVE branch'),
        ('init_skip', 'header skip on the packet (init_skip block)')]
forms = {k: collections.OrderedDict() for k, _ in KEYS}
bl = {}
for c in revs:
    bl[c] = b = blocks(c)
    for k, _ in KEYS:
        if b.get(k):
            forms[k].setdefault(norm(b[k]), {'text': b[k], 'commits': []})['commits'].append(c)
master = blocks('origin/master')
for k, title in KEYS:
    section(f'{title}: {len(forms[k])} distinct')
    for i, f in enumerate(forms[k].values()):
        dated = sorted((info(c) for c in f['commits']), key=when)
        tag = ' [base]' if norm(blocks(BASE).get(k)) == norm(f['text']) else ''
        tag += ' [origin/master]' if norm(master.get(k)) == norm(f['text']) else ''
        print(f'--- form {i}{tag}: {len(f["commits"])} commits; earliest {dated[0]}; latest {dated[-1]}')
        print(props(k, f['text']))
        print(f['text'])

# ---------------------------------------------------------------- changes
section('commits on any ref that change a block (merges only if different from every parent)')
for c in revs:
    parents = git('rev-list', '--parents', '-n1', c).split()[1:]
    diffs = []
    for par in parents:
        pb = bl[par] if par in bl else blocks(par)
        diffs.append({k for k, _ in KEYS if norm(bl[c].get(k)) != norm(pb.get(k))})
    changed = set.intersection(*diffs) if diffs else set()
    if changed:
        print(','.join(sorted(changed)), '|', info(c))

# ---------------------------------------------------------------- history after the fix
section(f'origin/master history of {PATH} after the developer fix')
print(git('log', '--format=%h %aI %an | %s', f'{FIX}..origin/master', '--', PATH).strip())

# ---------------------------------------------------------------- pickaxe
section(f'pickaxe over all refs ({PATH})')
for q in ['-SAudio format unrecognized in wave', '-SChannel count %d invalid in wave', '-SSamplerate %d invalid in wave',
          '-Ginit_skip', '-Gwav_hdr_size', r'-G=\s*pcmreframe_configure_pid\(', r'-Gif \(!ctx->opid\)']:
    out = git('log', '--all', '--format=%h %aI %an | %s', q, '--', PATH).strip()
    print(f'--- {q}: {len(set(out.splitlines())) if out else 0} commits')
    if out:
        print('\n'.join(sorted(set(out.splitlines()), key=when)))

# ---------------------------------------------------------------- messages
section(f'commit messages on all refs since {WINDOW} (case-insensitive)')
terms = ['wav', 'wave', 'pcm', 'rfpcm', 'pcmreframe', 'reframe_rawpcm', '2632', '2649', '2425', '2470',
         'sample ?rate', 'channel count', 'hang', 'probe_data', 'init_skip']
for t in terms:
    n = len(set(git('log', '--all', '-i', '-E', f'--grep={t}', f'--since={WINDOW}', '--format=%H').split()))
    print(f'{t!r}: {n} commits')
print(f'--- of these, commits touching {PATH}:')
print(git('log', '--all', '-i', '-E', f'--since={WINDOW}', '--format=%h %aI %an | %s',
          r'--grep=\bwav|wave|pcm|2632|2649|2425|hang', '--', PATH).strip())

# ---------------------------------------------------------------- tags
section('release tags: header checks and init_skip block')
for t in git('tag', '--sort=creatordate').split():
    b = blocks(t)
    if not b:
        print(f'{t} {git("log", "-1", "--format=%cs", t).strip()} file absent')
        continue
    print(f'{t} {git("log", "-1", "--format=%cs", t).strip()} {props("checks", b.get("checks"))} '
          f'{props("after_configure", b.get("after_configure"))} {props("init_skip", b.get("init_skip"))}')

# ---------------------------------------------------------------- github
section('GitHub gpac/gpac issues, PRs and comments')
os.makedirs(ghdir, exist_ok=True)
EPS = {'issues': 'repos/gpac/gpac/issues?state=all&per_page=100&direction=asc',
       'issue_comments': 'repos/gpac/gpac/issues/comments?per_page=100&direction=asc',
       'review_comments': 'repos/gpac/gpac/pulls/comments?per_page=50&sort=created&direction=asc',
       'commit_comments': 'repos/gpac/gpac/comments?per_page=100'}
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
    ('pcmreframe', r'pcmreframe'), ('PCMReframe log', r'\[PCMReframe\]'), ('rfpcm', r'\brfpcm\b'),
    ('reframe_rawpcm', r'reframe_rawpcm'), ('wav', r'\.wav\b|\bwave?\b'), ('2632', r'#?2632\b'),
    ('gf_filter_pck_new_alloc_internal', r'gf_filter_pck_new_alloc_internal'),
    ('Missing audio sample rate', r'Missing audio sample rate'), ('Missing audio ch', r'Missing audio ch\b'),
    ('Invalid or unsupported WAVE header', r'Invalid or unsupported WAVE header'),
    ('Audio format unrecognized', r'Audio format unrecognized'), ('wav_hdr_size', r'wav_hdr_size'),
    ('init_skip', r'init_skip'), ('probe_data', r'probe_data'), ('rfpcm/wav + hang', None),
    ('pcmreframe_process + heap', None)])


def match(k, t):
    if k == 'rfpcm/wav + hang':
        return re.search(r'rfpcm|pcmreframe|\.wav\b|\bwav\b', t, re.I) and re.search(r'\bhang|infinite|not responding', t, re.I)
    if k == 'pcmreframe_process + heap':
        return re.search(r'pcmreframe_process', t) and re.search(r'heap-buffer-overflow|use-after-free', t)
    return re.search(T[k], t, re.I)


SPEC = set(T) - {'wav'}
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


adv = json.loads(sh('gh', 'api', f'advisories?cve_id={CVE}') or '[]')
print('GitHub advisories:', len(adv))
for a in adv:
    print('GitHub advisory', a['ghsa_id'], a['published_at'], '| references:', ' '.join(a['references']))
huntr = None
try:
    nvd = json.loads(fetch(f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={CVE}'))['vulnerabilities'][0]['cve']
    print('NVD published', nvd['published'], 'lastModified', nvd['lastModified'])
    print('NVD description:', nvd['descriptions'][0]['value'])
    for r in sorted({(r['url'], ','.join(r.get('tags', []))) for r in nvd['references']}):
        print('NVD reference', r[0], f'[{r[1]}]')
        if 'huntr' in r[0]:
            huntr = re.sub(r'^https?://', '', r[0]).rstrip('/')
    for n in nvd.get('configurations', []):
        for node in n['nodes']:
            for m in node['cpeMatch']:
                print('NVD configuration', m['criteria'], 'versionEndExcluding', m.get('versionEndExcluding'))
except Exception as e:  # report and continue
    print('NVD not reachable:', e)
if huntr:
    try:
        cdx = json.loads(fetch(f'https://web.archive.org/cdx/search/cdx?url={huntr}*&output=json'))
        snaps = [r[1] for r in cdx[1:] if r[4] == '200' and r[3] == 'text/html']
        print('huntr Wayback snapshots with status 200:', ' '.join(snaps) or 'none')
        if snaps:
            page = fetch(f'https://web.archive.org/web/{snaps[-1]}id_/https://{huntr}')
            page = re.sub(r'<script.*?</script>|<style.*?</style>', ' ', page, flags=re.S)
            words = ' '.join(html.unescape(re.sub(r'<[^>]+>', '\n', page)).split())
            print(f'huntr snapshot {snaps[-1]} text:')
            for pat in [r'NULL Pointer Dereference.{0,80}', r'Reported on \S+ \S+ \S+', r'Affected commit \S+',
                        r'marked this as fixed in \S+ with commit \S+', r'root cause.{0,200}', r'sample ?rate.{0,200}']:
                m = re.search(pat, words, re.I)
                print(f'  /{pat}/:', m.group(0) if m else 'no match')
    except Exception as e:
        print('huntr Wayback not reachable:', e)
print('run finished', now())
