#!/bin/bash
# Compiles src/njs_iterator.c of a patch variant with the compiler flags that
# njs's own configure uses (-W -Wall -Wextra ... -Werror, from the generated
# Makefile) and without the -w that the SEC-bench build adds, with gcc and
# clang, in a scratch copy of the tree inside a container
# (njs.cve-2022-31307). It answers whether a reduction of the developer patch
# builds under the project's normal warning flags; the oracles of the variant
# runner (scripts/njs_run_variant.sh) build with -w and cannot.
#
# Usage: negfrom_warnings.sh <running container with a built base tree> <name> [<diff>]
#   <diff> is applied with plain `git apply` to the scratch copy of /src/njs
#   (e.g. logs/<instance>/ablation/L4.diff, the applied diff a variant run records);
#   without it the unpatched tree is compiled. /src/njs is not modified.
# Prints, per compiler, the exit status and the diagnostics of the compile.
set -u
c=$1 name=$2 diff=${3:-}
flags='-pipe -fPIC -fvisibility=hidden -O -W -Wall -Wextra -Wno-unused-parameter -Wwrite-strings -fstrict-aliasing -Wstrict-overflow=5 -Wmissing-prototypes -Werror -g'
echo "--- variant $name, container $c, HEAD $(docker exec "$c" git -C /src/njs rev-parse HEAD)"
echo "--- flags: $flags (no -w, no sanitizer)"
docker exec "$c" bash -c 'rm -rf /tmp/wtree && cp -a /src/njs /tmp/wtree && cd /tmp/wtree && git checkout -q -- . && git status --porcelain | wc -l | tr -d " " | sed "s/^/scratch tree modified files: /"'
if [ -n "$diff" ]; then
  docker cp "$diff" "$c:/tmp/w.diff"
  docker exec "$c" bash -c 'cd /tmp/wtree && git apply /tmp/w.diff && git diff --stat | tail -1'
fi
for cc in gcc clang; do
  docker exec "$c" bash -c "cd /tmp/wtree && $cc --version | head -1 && $cc -c $flags -Isrc -Ibuild -Injs -o /tmp/w.o src/njs_iterator.c; echo \"$cc exit=\$?\"" 2>&1 \
    | grep -E 'version|exit=|warning|error' | cut -c1-200 | head -12
done
