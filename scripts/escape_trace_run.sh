#!/bin/bash
# Runs the test suite of a libredwg tree built with the developer patch and
# scripts/escape_trace.diff (instrumentation that appends one line per call
# of htmlescape and htmlwescape to /tmp/escape_trace.log) and prints, for
# each function, how many calls the suite makes and how many characters of
# each class and buffer growths they contain. Shows which branches of the
# patched code the suite reaches.
#
# Usage: escape_trace_run.sh <image> <developer-patch> <trace-diff> [<make-output-copy>] > log
#
# <image> is a local image committed from a built container
# (scripts/libredwg_make_built_image.sh). The container is
# secb-libredwg-<cve number>-trace; extra `docker run` options are taken
# from SECB_DOCKER_OPTS (default empty).
set -eu
image=$1 patch=$2 trace=$3 copy=${4:-}
here=$(cd "$(dirname "$0")" && pwd)
opts=${SECB_DOCKER_OPTS:-}
inst=${image##*.x86_64.}; inst=${inst%%:*}; cve=${inst##*-}
c=secb-libredwg-$cve-trace
# shellcheck disable=SC2086
docker run -d --name "$c" --platform linux/amd64 $opts "$image" sleep infinity >/dev/null
trap 'docker rm -f "$c" >/dev/null' EXIT
docker cp "$patch" "$c:/tmp/dev.diff"
docker cp "$trace" "$c:/tmp/trace.diff"
docker cp "$here/libredwg_run_tests.sh" "$c:/tmp/libredwg_run_tests.sh"
echo "--- container $c image $image docker-opts: ${opts:-<none>}"
docker exec "$c" bash -c 'cd /src/libredwg && git apply /tmp/dev.diff && git apply /tmp/trace.diff && git diff --stat'
docker exec "$c" secb build 2>&1 | tail -n 3
docker exec "$c" rm -f /tmp/escape_trace.log
docker exec "$c" bash /tmp/libredwg_run_tests.sh /src/libredwg 2>&1 | grep -E '^(---|SUMMARY tests=)'
if [ -n "$copy" ]; then docker cp "$c:/tmp/libredwg_make_check.out" "$copy"; fi
echo "--- trace of the suite (/tmp/escape_trace.log)"
docker exec -i "$c" python3 - <<'EOF'
import collections
agg = collections.defaultdict(collections.Counter)
n = 0
try:
    lines = open('/tmp/escape_trace.log').read().splitlines()
except OSError:
    lines = []
for line in lines:
    f = line.split()
    if len(f) < 8 or f[0] != 'ESCAPE-TRACE':
        continue
    n += 1
    v = {k: int(x) for k, x in (p.split('=') for p in f[2:])}
    a = agg[f[1]]
    a['calls'] += 1
    for k, x in v.items():
        a[k] += x
    for k in ('special', 'high', 'grow'):
        a['calls_with_' + k] += v[k] > 0
print('trace lines:', n)
for fn in ('htmlescape', 'htmlwescape'):
    a = agg[fn]
    print(fn + ':', ' '.join('%s=%d' % (k, a[k]) for k in ('calls', 'in', 'special', 'high', 'plain', 'ctl', 'grow',
                                                          'calls_with_special', 'calls_with_high', 'calls_with_grow')))
EOF
