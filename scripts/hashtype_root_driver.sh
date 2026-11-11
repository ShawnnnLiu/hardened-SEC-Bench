#!/bin/bash
# Root-cause stages and variants of mruby.cve-2022-0614 and mruby.cve-2022-0623
# (one shared developer patch ff3a5ebed). The root-cause patch
# patches/<instance>.root.diff is the developer patch plus the backport of
# upstream 12d51807a (scripts/hashcat_12d51807a.diff, gen_hash in
# mrbgems/mruby-compiler/core/codegen.c).
#
# Usage (from any directory): scripts/hashtype_root_driver.sh <instance>
#
# Writes, in this order, and refuses to start if any of them exists:
#   logs/<instance>/apply_root.log   git rev-parse HEAD, git apply --check -v,
#                                    APPLIED, git diff --stat
#   logs/<instance>/build_root.log   secb build, under time
#   logs/<instance>/poc_root.log     secb repro, under time
#   logs/<instance>/tests_root.log   scripts/mruby_run_tests_verbose.sh, under time
#   logs/<instance>/variants/root.residual.log
#                                    scripts/hashtype_alias_cases.sh on the
#                                    root build, after the tests
#   logs/<instance>/variants/root.*            scripts/hashtype_run_variant.sh
#   logs/<instance>/variants/assert_root.*     root-cause patch +
#                                              scripts/hashtype_invariant.diff
#   logs/<instance>/variants/up12d518_alone.*  the upstream change without the
#                                              developer patch, --no-tests
#   logs/<instance>/variants/up12d518_alone.residual.log
#                                    scripts/hashtype_alias_cases.sh on a
#                                    separate build of the same variant
# The variant runner appends one summary line per variant to
# logs/<instance>/variants.log.
#
# Containers: secb-mruby-<cve>-rootstage (stopped at the end, kept),
# secb-mruby-<cve>-root, -assert_root and -up12d518_alone (created and removed
# by the runner), secb-mruby-<cve>-alonealias (removed at the end).
# Extra `docker run` options come from SECB_DOCKER_OPTS (default empty).
# A crash is judged by the presence of an AddressSanitizer report, not by exit
# status.
set -eu
inst=${1:-}
case "$inst" in
  mruby.cve-2022-0614|mruby.cve-2022-0623) ;;
  *) echo "usage: hashtype_root_driver.sh mruby.cve-2022-0614|mruby.cve-2022-0623" >&2; exit 2 ;;
esac
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
cd "$repo"
image=hwiwonlee/secb.eval.x86_64.$inst
cve=${inst##*-}
logs=logs/$inst
var=$logs/variants
root=patches/$inst.root.diff
up=scripts/hashcat_12d51807a.diff
inv=scripts/hashtype_invariant.diff
opts=${SECB_DOCKER_OPTS:-}
bin=/src/mruby/build/host/bin/mruby
echo "SECB_DOCKER_OPTS=$opts"

for f in "$root" "$up" "$inv" scripts/hashtype_run_variant.sh scripts/hashtype_alias_cases.sh \
         scripts/run_tests.sh scripts/mruby_run_tests_verbose.sh; do
  [ -f "$f" ] || { echo "missing input: $f" >&2; exit 2; }
done
for f in "$logs/apply_root.log" "$logs/build_root.log" "$logs/poc_root.log" "$logs/tests_root.log" \
         "$var/root.residual.log" "$var/up12d518_alone.residual.log" \
         "$var/root.diff" "$var/assert_root.diff" "$var/up12d518_alone.diff"; do
  [ ! -e "$f" ] || { echo "refusing to overwrite: $f" >&2; exit 2; }
done
for n in rootstage root assert_root up12d518_alone alonealias; do
  if docker ps -a --format '{{.Names}}' | grep -q -x "secb-mruby-$cve-$n"; then
    echo "container exists: secb-mruby-$cve-$n" >&2; exit 2
  fi
done

step() { echo "$(date '+%Y-%m-%d %H:%M %Z') $inst: $*"; }

# 1. Root stages in one stage container.
c=secb-mruby-$cve-rootstage
step "stage container $c"
docker run -d --name "$c" --platform linux/amd64 $opts "$image" sleep infinity >/dev/null
docker cp "$root" "$c:/tmp/root.diff"
{
  docker exec "$c" git -C /src/mruby rev-parse HEAD
  docker exec "$c" git -C /src/mruby apply --check -v /tmp/root.diff
  docker exec "$c" git -C /src/mruby apply /tmp/root.diff && echo APPLIED
  docker exec "$c" git -C /src/mruby diff --stat
} > "$logs/apply_root.log" 2>&1
grep -q -x APPLIED "$logs/apply_root.log" || { echo "apply failed, see $logs/apply_root.log" >&2; docker stop "$c" >/dev/null; exit 1; }

step "secb build"
( time docker exec "$c" secb build ) > "$logs/build_root.log" 2>&1 || true
if ! grep -q 'BUILD COMPLETED SUCCESSFULLY' "$logs/build_root.log"; then
  echo "build failed, see $logs/build_root.log" >&2; docker stop "$c" >/dev/null; exit 1
fi
step "secb repro"
( time docker exec "$c" secb repro ) > "$logs/poc_root.log" 2>&1 || true

step "regression tests"
docker exec "$c" mkdir -p /tmp/scripts
for s in run_tests.sh mruby_run_tests_verbose.sh hashtype_alias_cases.sh; do
  docker cp "scripts/$s" "$c:/tmp/scripts/$s"
done
( time docker exec "$c" bash /tmp/scripts/mruby_run_tests_verbose.sh ) > "$logs/tests_root.log" 2>&1 || true

step "aliasing cases on the root build"
docker exec "$c" bash /tmp/scripts/hashtype_alias_cases.sh "$bin" > "$var/root.residual.log" 2>&1 || true
docker stop "$c" >/dev/null

# 2. Variants on record through the repository runner.
step "variant root"
bash scripts/hashtype_run_variant.sh "$image" "$var" root \
  "developer patch + upstream 12d51807a gen_hash fresh accumulator (root-cause patch)" "$root"
step "variant assert_root"
bash scripts/hashtype_run_variant.sh "$image" "$var" assert_root \
  "root-cause patch + OP_HASHADD non-hash invariant check" "$root" "$inv"
step "variant up12d518_alone"
bash scripts/hashtype_run_variant.sh --no-tests "$image" "$var" up12d518_alone \
  "upstream 12d51807a alone, without the developer patch" "$up"

# 3. Aliasing cases on the upstream change alone.
c=secb-mruby-$cve-alonealias
step "aliasing cases on up12d518_alone ($c)"
docker run -d --name "$c" --platform linux/amd64 $opts "$image" sleep infinity >/dev/null
docker cp "$up" "$c:/tmp/up.diff"
docker exec "$c" git -C /src/mruby apply /tmp/up.diff
docker exec "$c" mkdir -p /tmp/scripts
docker cp scripts/hashtype_alias_cases.sh "$c:/tmp/scripts/hashtype_alias_cases.sh"
if docker exec "$c" secb build 2>&1 | grep -q 'BUILD COMPLETED SUCCESSFULLY'; then
  docker exec "$c" bash /tmp/scripts/hashtype_alias_cases.sh "$bin" > "$var/up12d518_alone.residual.log" 2>&1 || true
else
  echo "up12d518_alone aliasing build failed; no residual log written" >&2
fi
docker rm -f "$c" >/dev/null

step "DRIVER DONE $inst"
