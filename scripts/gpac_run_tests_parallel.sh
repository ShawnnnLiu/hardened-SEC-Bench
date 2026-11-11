#!/bin/bash
# Run the GPAC test suite one script at a time over N worker containers.
#
# Usage: scripts/gpac_run_tests_parallel.sh <container> <N> <outlog> [make_tests.sh args...]
#
# <container> is a running SEC-bench gpac container after "secb build", with
# GNU time installed, /external_media and /external_media.sha256 in place
# (scripts/gpac_mirror_media.py) and scripts/gpac_run_tests.sh at
# /tools/gpac_run_tests.sh. It is committed to an image and N workers are
# started from it, so each worker has its own file system and network
# namespace (the RTP, HTTP and ROUTE tests open local ports). The test
# scripts are independent (make_tests.sh empties its temp directory after
# each one), so each script runs as its own make_tests.sh invocation, taken
# from a shared queue by the next free worker. <outlog> receives a header,
# every per-script log in script order, the merged per-test RESULT lines
# and summed SUMMARY counts. If ARCHIVE_DIR is set, each script's results
# directory (every subtest log) is copied there as <script>.tgz. If
# SCRIPTS is set (space-separated names such as "avmix.sh rtp.sh"), only
# those scripts are run. If MARKER is set, it is passed to
# gpac_run_tests.sh and the merged section sums its per-script counts.
set -eu
src=$1 n=$2 outlog=$3
shift 3
args=("$@")
tmp=$(mktemp -d)
image=gpac-tests-$(echo "$src" | tr -c 'a-z0-9\n' '-')-$$
docker commit "$src" "$image" > /dev/null
workers=()
cleanup() {
  for w in ${workers[@]+"${workers[@]}"}; do docker rm -f "$w" > /dev/null 2>&1 || true; done
  docker rmi "$image" > /dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

if [ -n "${SCRIPTS:-}" ]; then
  printf '%s\n' $SCRIPTS > "$tmp/queue"
else
  docker exec "$src" bash -c 'ls /src/gpac/testsuite/scripts/*.sh | xargs -n1 basename' > "$tmp/queue"
fi
total=$(wc -l < "$tmp/queue" | tr -d " ")
echo 0 > "$tmp/next"

worker() { # index
  local w=$1 i s t0 t1
  while :; do
    until mkdir "$tmp/lock" 2> /dev/null; do sleep 0.2; done
    i=$(cat "$tmp/next"); echo $((i + 1)) > "$tmp/next"
    rmdir "$tmp/lock"
    [ "$i" -lt "$total" ] || return 0
    s=$(sed -n "$((i + 1))p" "$tmp/queue")
    t0=$(date +%s)
    docker exec -e RESULTS_TGZ="/tmp/results/$s.tgz" ${MARKER:+-e "MARKER=$MARKER"} "$w" bash /tools/gpac_run_tests.sh \
      /src/gpac/testsuite /external_media /external_media.sha256 ${args[@]+"${args[@]}"} \
      "scripts/$s" > "$tmp/$s.log" 2>&1 || true
    t1=$(date +%s)
    echo "$s worker=$w elapsed=$((t1 - t0))s" > "$tmp/$s.meta"
  done
}

for k in $(seq 1 "$n"); do
  w=$image-w$k
  docker run -d --platform linux/amd64 --name "$w" "$image" sleep infinity > /dev/null
  workers+=("$w")
done
t_start=$(date +%s)
for w in "${workers[@]}"; do worker "$w" & done
wait
t_end=$(date +%s)
if [ -n "${ARCHIVE_DIR:-}" ]; then
  mkdir -p "$ARCHIVE_DIR"
  for w in "${workers[@]}"; do docker cp "$w:/tmp/results/." "$ARCHIVE_DIR/"; done
fi

{
  echo "gpac test suite, $total scripts over $n workers committed from $src"
  echo "make_tests.sh args: -p=0 ${args[*]} <one script>"
  echo "wall time $((t_end - t_start))s"
  while read -r s; do
    echo
    echo "### $(cat "$tmp/$s.meta" 2> /dev/null || echo "$s not run")"
    cat "$tmp/$s.log" 2> /dev/null || true
  done < "$tmp/queue"
  echo
  echo "### merged results"
  cat "$tmp"/*.log | grep -h '^SUMMARY ' | python3 -c '
import sys, collections
tot = collections.Counter()
for line in sys.stdin:
    for kv in line.split()[1:]:
        k, v = kv.split("=")
        tot[k] += int(v)
print("SUMMARY", " ".join(f"{k}={v}" for k, v in tot.items()))
'
  echo "scripts without a SUMMARY line: $(for s in $(cat "$tmp/queue"); do grep -q '^SUMMARY ' "$tmp/$s.log" 2> /dev/null || echo "$s"; done | paste -sd' ' -)"
  if [ -n "${MARKER:-}" ]; then
    echo "MARKER $MARKER total lines=$(cat "$tmp"/*.log | sed -n 's/^MARKER .* lines=\([0-9]*\)$/\1/p' | paste -sd+ - | bc)" \
      "over $(cat "$tmp"/*.log | grep -c '^MARKER .* lines=') scripts"
  fi
  cat "$tmp"/*.log | grep -h '^RESULT ' | sort
} > "$outlog"
